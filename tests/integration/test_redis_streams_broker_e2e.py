import asyncio
import json
import os
import uuid

from agents.base_agent import AgentContext
from agents.decision_agent import DecisionAgent
from agents.mutation_agent import MutationAgent
from broker.redis_streams import RedisStreamsBroker
from broker.topics import Topic
from contracts.job import JobState, JobStatus
from unittest.mock import AsyncMock, patch


async def _consume_once_and_ack(msg, received):
    if "hello" in msg.data:
        received.append(msg.data)
    await msg.ack()


def test_redis_streams_broker_e2e_real_redis():
    async def _run():
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        broker = RedisStreamsBroker(redis_url=redis_url)

        # Fail fast if Redis is not reachable (this is a real-Redis test).
        client = await broker._get_client()  # pylint: disable=protected-access
        await client.ping()

        stream = f"stream:test:e2e:{uuid.uuid4().hex}"
        group = f"cg_test_{uuid.uuid4().hex[:8]}"
        consumer = "consumer_e2e"
        payload = {"hello": "redis", "n": 1}
        received = []

        await broker.create_consumer_group(stream, group, from_id="0")
        await broker.publish_raw(stream, payload)

        async def _handler(msg):
            await _consume_once_and_ack(msg, received)

        task = asyncio.create_task(
            broker.subscribe(stream, group, consumer, _handler, batch_size=1, block_ms=250)
        )

        deadline = asyncio.get_event_loop().time() + 5.0
        while asyncio.get_event_loop().time() < deadline and not received:
            await asyncio.sleep(0.05)

        await broker.close()
        await asyncio.sleep(0.05)
        task.cancel()

        assert received, "No expected payload consumed from Redis stream"
        assert any(item.get("hello") == "redis" for item in received)

    asyncio.run(_run())


class _FakeStateStore:
    def __init__(self) -> None:
        self._states = {}

    async def save(self, state: JobState) -> None:
        self._states[state.job_id] = state

    async def get(self, job_id: str):
        return self._states.get(job_id)


class _FakeArtifactStore:
    def __init__(self, analysis_by_id: dict[str, dict]) -> None:
        self._analysis_by_id = analysis_by_id
        self._stored = {}

    async def get_json(self, *args):
        artifact_id = args[-1]
        return self._analysis_by_id.get(artifact_id)

    async def store_json(self, job_id: str, artifact_type: str, data: dict) -> str:
        artifact_id = f"{artifact_type}_{job_id[:8]}"
        self._stored[artifact_id] = data
        return artifact_id


def _decode_redis_fields(fields: dict) -> dict:
    decoded = {}
    for key, value in fields.items():
        if isinstance(value, str):
            try:
                decoded[key] = json.loads(value)
                continue
            except json.JSONDecodeError:
                pass
        decoded[key] = value
    return decoded


async def _count_entries_for_job(client, stream: str, job_id: str, max_scan: int = 500) -> int:
    rows = await client.xrevrange(stream, "+", "-", count=max_scan)
    count = 0
    for _, fields in rows:
        payload = _decode_redis_fields(fields)
        if payload.get("job_id") == job_id:
            count += 1
    return count


async def _latest_decision_event_for_job(client, job_id: str, max_scan: int = 500) -> dict:
    rows = await client.xrevrange(Topic.EVENTS_ALL, "+", "-", count=max_scan)
    for _, fields in rows:
        payload = _decode_redis_fields(fields)
        if (
            payload.get("job_id") == job_id
            and "decision_id" in payload
            and "action" in payload
        ):
            return payload
    raise AssertionError("DecisionIssuedEvent not found for job")


def test_redis_autonomous_mutation_feedback_no_duplicate_build_dispatch():
    async def _run():
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        broker = RedisStreamsBroker(redis_url=redis_url)

        client = await broker._get_client()  # pylint: disable=protected-access
        await client.ping()

        job_id = f"job_auto_redis_{uuid.uuid4().hex[:12]}"
        sample_id = "sample_auto_redis"
        correlation_id = f"corr_{uuid.uuid4().hex[:8]}"
        analysis_result_id = f"analysis_{uuid.uuid4().hex[:8]}"

        state_store = _FakeStateStore()
        artifact_store = _FakeArtifactStore(
            analysis_by_id={
                analysis_result_id: {
                    "threat_score": 6.4,
                    "iocs": [{"type": "ip", "value": "8.8.8.8"}],
                    "behavior_categories": ["stealer"],
                    "summary": "Suspicious behavior suitable for mutation feedback.",
                }
            }
        )

        ctx = AgentContext(
            broker=broker,
            state_store=state_store,
            artifact_store=artifact_store,
            llm_provider=None,
        )

        state = JobState(
            job_id=job_id,
            sample_id=sample_id,
            correlation_id=correlation_id,
            current_status=JobStatus.DECIDING,
            source_artifact_id="source_artifact_redis",
            project_name="redis_demo_project",
            language="c",
            requested_strategies=["variant_source_generator", "alt_strategy"],
        )
        await state_store.save(state)

        build_before = await _count_entries_for_job(client, Topic.CMD_BUILD_VALIDATE, job_id)
        events_before = await _count_entries_for_job(client, Topic.EVENTS_ALL, job_id)

        decision_agent = DecisionAgent(
            ctx,
            enable_autonomous_requests=True,
            mutation_score_threshold=5.5,
            mutation_max_iocs=3,
        )
        # Use handle_event() so state is transitioned and the DecisionIssuedEvent is
        # published to the broker (handle() stores the event pending the transition).
        await decision_agent.handle_event(
            {
                "job_id": job_id,
                "sample_id": sample_id,
                "correlation_id": correlation_id,
                "analysis_result_id": analysis_result_id,
                "job_retry_count": 0,
            },
            state,
        )

        build_mid = await _count_entries_for_job(client, Topic.CMD_BUILD_VALIDATE, job_id)
        events_mid = await _count_entries_for_job(client, Topic.EVENTS_ALL, job_id)

        # New flow: DecisionAgent does NOT publish BuildValidateCommand — MutationAgent
        # self-activates on the DecisionIssuedEvent and publishes the MutateCommand.
        assert build_mid == build_before, "DecisionAgent must NOT publish BuildValidateCommand"
        assert events_mid == events_before + 1, "DecisionIssuedEvent must be published to EVENTS_ALL"

        decision_event = await _latest_decision_event_for_job(client, job_id)
        assert decision_event.get("action") == "retry_with_mutation"
        assert decision_event.get("autonomous_mutation_queued") is True

        # Production path: MutationAgent self-activates on the DecisionIssuedEvent.
        # Simulate the CAS claim (base_agent sets status=MUTATING before calling handle_event).
        pre_state = await state_store.get(job_id)
        pre_state.current_status = JobStatus.MUTATING
        await state_store.save(pre_state)

        mutation_agent = MutationAgent(ctx)
        # Patch handle() to skip LLM/artifact I/O — we only test counter increment
        # and self-activation routing, not actual mutation quality.
        with patch.object(mutation_agent, "handle", new_callable=AsyncMock):
            await mutation_agent.handle_event(decision_event, pre_state)

        build_after = await _count_entries_for_job(client, Topic.CMD_BUILD_VALIDATE, job_id)
        assert build_after == build_mid, "MutationAgent must NOT publish BuildValidateCommand directly"

        updated_state = await state_store.get(job_id)
        assert updated_state is not None
        # MutationAgent increments feedback counters on self-activation retry path.
        assert updated_state.feedback_loop_count == 1
        assert updated_state.mutation_cycle_count == 1
        assert updated_state.retry_count == 1
        # State is MUTATION_READY — handle_event transitions here after handle() completes.
        assert updated_state.current_status == JobStatus.MUTATION_READY

        await broker.close()

    asyncio.run(_run())
