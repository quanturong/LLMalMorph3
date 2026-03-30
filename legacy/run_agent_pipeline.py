"""Run multi-agent pipeline runtime (MVP bootstrap).

Usage:
  python run_agent_pipeline.py

This starts all agents and waits indefinitely.
"""

from __future__ import annotations

import asyncio
import signal
from typing import Optional

import redis.asyncio as aioredis

from adapters.cape_adapter import CapeAdapter
from agents import (
    AgentContext,
    BehaviorAnalysisAgent,
    BuildValidationAgent,
    CoordinatorAgent,
    DecisionAgent,
    ExecMonitorAgent,
    ReportingAgent,
    SamplePrepAgent,
    SandboxSubmitAgent,
)
from broker.memory_broker import MemoryBroker
from broker.redis_streams import RedisStreamsBroker
from configs.settings import PipelineSettings
from llm.factory import build_provider
from observability.logging_config import configure_logging, get_logger
from observability.metrics import start_metrics_server
from storage.artifact_store import ArtifactStore
from storage.report_store import ReportStore
from storage.state_store import StateStore


async def main() -> None:
    settings = PipelineSettings.from_env()
    configure_logging(level=settings.log_level)
    log = get_logger(__name__)
    start_metrics_server(settings.metrics_port)
    log.info("metrics_server_started", endpoint=f"http://127.0.0.1:{settings.metrics_port}/metrics")

    redis_client: Optional[aioredis.Redis] = None
    if settings.use_agent_broker:
        redis_client = await aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )

    # Broker selection: Redis Streams for production, memory for local smoke tests.
    if settings.use_agent_broker:
        broker = RedisStreamsBroker(redis_url=settings.redis_url)
    else:
        broker = MemoryBroker()

    state_store = StateStore(redis_client=redis_client, db_path=settings.sqlite_path)
    artifact_store = ArtifactStore(base_dir=settings.artifacts_dir, db_path=settings.sqlite_path)
    report_store = ReportStore(db_path=settings.sqlite_path, reports_dir=settings.reports_dir)

    cloud_provider = "deepseek" if settings.llm_mode == "deepseek" else "mistral"
    api_key = settings.deepseek_api_key if cloud_provider == "deepseek" else settings.mistral_api_key
    llm_provider = build_provider(
        mode=settings.llm_mode,
        redis_client=redis_client,
        cloud_provider=cloud_provider,
        api_key=api_key,
    )

    cape = CapeAdapter(api_url=settings.cape_base_url, api_token=settings.cape_api_token)

    ctx = AgentContext(
        broker=broker,
        redis_client=redis_client,
        state_store=state_store,
        artifact_store=artifact_store,
        report_store=report_store,
        llm_provider=llm_provider,
    )

    agents = [
        CoordinatorAgent(ctx),
        SamplePrepAgent(ctx),
        BuildValidationAgent(ctx),
        SandboxSubmitAgent(ctx, cape_adapter=cape),
        ExecMonitorAgent(ctx, cape_adapter=cape, timeout_s=settings.sandbox_timeout_s),
        BehaviorAnalysisAgent(ctx),
        DecisionAgent(
            ctx,
            enable_autonomous_requests=settings.decision_enable_autonomy,
            mutation_score_threshold=settings.decision_mutation_score_threshold,
            mutation_max_iocs=settings.decision_mutation_max_iocs,
        ),
        ReportingAgent(ctx),
    ]

    tasks = [asyncio.create_task(a.start()) for a in agents]

    log.info("agent_runtime_started", agent_count=len(agents), mode=settings.llm_mode)

    stop_event = asyncio.Event()

    def _stop(*_):
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            asyncio.get_event_loop().add_signal_handler(sig, _stop)
        except NotImplementedError:
            # Windows event loop may not support all signal handlers.
            pass

    await stop_event.wait()

    for a in agents:
        await a.stop()
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

    if hasattr(broker, "close"):
        maybe = broker.close()
        if asyncio.iscoroutine(maybe):
            await maybe

    if redis_client is not None:
        await redis_client.aclose()


if __name__ == "__main__":
    asyncio.run(main())
