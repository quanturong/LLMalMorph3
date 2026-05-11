import asyncio

from agents.base_agent import AgentContext
from agents.monitor_agent import MonitorAgent
from broker.topics import Topic
from contracts.job import JobState, JobStatus
from contracts.messages import VariantGeneratedEvent


class _FakeBroker:
    def __init__(self) -> None:
        self.published = []

    async def publish(self, stream: str, message) -> str:
        self.published.append((stream, message))
        return f"msg_{len(self.published)}"


class _FakeStateStore:
    def __init__(self, state: JobState) -> None:
        self.state = state

    async def save(self, state: JobState) -> None:
        self.state = state

    async def get(self, job_id: str):
        return self.state if self.state.job_id == job_id else None


class _FakeArtifactStore:
    def __init__(self) -> None:
        self.payloads = {
            "variant_1": {
                "source_artifact_id": "source_1",
                "mutation_artifact_id": "mutation_1",
                "project_name": "demo",
                "language": "c",
                "num_files_generated": 3,
            }
        }

    async def get_json(self, *args):
        return self.payloads.get(args[-1])

    def list_for_job(self, job_id: str) -> list[dict]:
        return [
            {
                "artifact_id": "source_1",
                "type": "source_parse_result",
                "created_at": "2026-05-10T00:00:00",
            },
            {
                "artifact_id": "mutation_1",
                "type": "mutation_result",
                "created_at": "2026-05-10T00:01:00",
            },
            {
                "artifact_id": "variant_1",
                "type": "variant_source",
                "created_at": "2026-05-10T00:02:00",
            },
        ]


def test_monitor_requeues_build_failed_before_terminal_failure():
    async def _run():
        state = JobState(
            job_id="job_1",
            sample_id="sample_1",
            correlation_id="corr_1",
            current_status=JobStatus.BUILD_FAILED,
            project_name="demo",
            language="c",
        )
        broker = _FakeBroker()
        state_store = _FakeStateStore(state)
        ctx = AgentContext(
            broker=broker,
            state_store=state_store,
            artifact_store=_FakeArtifactStore(),
            llm_provider=None,
        )

        agent = MonitorAgent(ctx)
        await agent.handle(
            {
                "job_id": state.job_id,
                "sample_id": state.sample_id,
                "correlation_id": state.correlation_id,
                "auto_fix_attempts": 5,
                "error_message": "compiler failed",
            }
        )

        assert state_store.state.current_status == JobStatus.VARIANT_READY
        assert state_store.state.build_retry_count == 1
        assert state_store.state.variant_artifact_id == "variant_1"
        assert state_store.state.source_artifact_id == "source_1"
        assert state_store.state.mutation_artifact_id == "mutation_1"
        assert state_store.state.error_history[-1].error_code == "BUILD_FAILED"

        event_msgs = [m for stream, m in broker.published if stream == Topic.EVENTS_ALL]
        assert len(event_msgs) == 1
        assert isinstance(event_msgs[0], VariantGeneratedEvent)
        assert event_msgs[0].variant_artifact_id == "variant_1"

    asyncio.run(_run())
