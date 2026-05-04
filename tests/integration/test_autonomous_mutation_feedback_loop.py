import asyncio

from unittest.mock import AsyncMock, patch

from agents.base_agent import AgentContext
from agents.decision_agent import DecisionAgent
from agents.mutation_agent import MutationAgent
from broker.topics import Topic
from contracts.job import JobState, JobStatus
from contracts.messages import DecisionIssuedEvent


class _FakeBroker:
    def __init__(self) -> None:
        self.published = []

    async def publish(self, stream: str, message) -> str:
        self.published.append((stream, message))
        return f"msg_{len(self.published)}"

    async def publish_raw(self, stream: str, data: dict) -> str:
        self.published.append((stream, data))
        return f"raw_{len(self.published)}"


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


def test_decision_autonomous_mutation_dispatch_and_coordinator_reconcile():
    async def _run():
        job_id = "job_autonomy_001"
        sample_id = "sample_001"
        correlation_id = "corr_001"
        analysis_result_id = "analysis_001"

        broker = _FakeBroker()
        state_store = _FakeStateStore()
        artifact_store = _FakeArtifactStore(
            analysis_by_id={
                analysis_result_id: {
                    "threat_score": 6.2,
                    "iocs": [{"type": "ip", "value": "1.2.3.4"}],
                    "behavior_categories": ["stealer"],
                    "summary": "Suspicious network and credential access behavior",
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
            source_artifact_id="source_artifact_001",
            project_name="demo_project",
            language="c",
            requested_strategies=["variant_source_generator", "alt_strategy"],
        )
        await state_store.save(state)

        decision_agent = DecisionAgent(
            ctx,
            enable_autonomous_requests=True,
            mutation_score_threshold=5.5,
            mutation_max_iocs=3,
        )

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

        build_msgs = [m for (s, m) in broker.published if s == Topic.CMD_BUILD_VALIDATE]
        event_msgs = [m for (s, m) in broker.published if s == Topic.EVENTS_ALL]

        # New flow: DecisionAgent does NOT dispatch BuildValidateCommand or MutateCommand.
        # It only emits DecisionIssuedEvent with action=retry_with_mutation.
        # MutationAgent self-activates on that event and handles mutation independently.
        assert len(build_msgs) == 0, "DecisionAgent must not publish BuildValidateCommand"

        assert len(event_msgs) == 1
        assert isinstance(event_msgs[0], DecisionIssuedEvent)
        assert event_msgs[0].action == "retry_with_mutation"
        assert event_msgs[0].autonomous_mutation_queued is True
        assert event_msgs[0].next_mutation_strategy == "variant_source_generator"

        # Production path: MutationAgent self-activates on DecisionIssuedEvent.
        # Simulate the CAS claim (base_agent sets status=MUTATING before calling handle_event).
        pre_state = await state_store.get(job_id)
        pre_state.current_status = JobStatus.MUTATING
        await state_store.save(pre_state)

        mutation_agent = MutationAgent(ctx)
        event_data = event_msgs[0].model_dump()
        # Patch handle() to skip LLM/artifact I/O — tests routing and counter semantics only.
        with patch.object(mutation_agent, "handle", new_callable=AsyncMock):
            await mutation_agent.handle_event(event_data, pre_state)

        build_msgs_after = [m for (s, m) in broker.published if s == Topic.CMD_BUILD_VALIDATE]
        assert len(build_msgs_after) == 0, "MutationAgent must not publish BuildValidateCommand directly"

        updated_state = await state_store.get(job_id)
        assert updated_state is not None
        # MutationAgent increments all feedback counters on retry_with_mutation activation.
        assert updated_state.feedback_loop_count == 1
        assert updated_state.mutation_cycle_count == 1
        assert updated_state.retry_count == 1
        # handle_event transitions to MUTATION_READY after handle() completes.
        assert updated_state.current_status == JobStatus.MUTATION_READY

    asyncio.run(_run())