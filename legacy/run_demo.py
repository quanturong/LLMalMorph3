import asyncio
import signal
from typing import Optional
from pathlib import Path

import redis.asyncio as aioredis

from contracts.job import JobEnvelope
from adapters.cape_adapter import CapeAdapter
from agents import (
    AgentContext, BehaviorAnalysisAgent, BuildValidationAgent,
    CoordinatorAgent, DecisionAgent, ExecMonitorAgent,
    ReportingAgent, SamplePrepAgent, SandboxSubmitAgent
)
from broker.memory_broker import MemoryBroker
from configs.settings import PipelineSettings
from llm.factory import build_provider
from observability.logging_config import configure_logging, get_logger
from storage.artifact_store import ArtifactStore
from storage.report_store import ReportStore
from storage.state_store import StateStore

async def main() -> None:
    settings = PipelineSettings.from_env()
    settings.use_agent_broker = False # force memory broker for testing
    settings.llm_mode = "mistral" # Ensure no local ollama error if missing
    settings.sandbox_timeout_s = 5 # shorten timeout for demo
    configure_logging(level="DEBUG")
    log = get_logger("demo_runner")

    redis_client = None
    broker = MemoryBroker()
    state_store = StateStore(redis_client=redis_client, db_path=settings.sqlite_path)
    artifact_store = ArtifactStore(base_dir=settings.artifacts_dir, db_path=settings.sqlite_path)
    report_store = ReportStore(db_path=settings.sqlite_path, reports_dir=settings.reports_dir)
    
    import os
    api_key = os.getenv("MISTRAL_API_KEY", "dummy_key")
    llm_provider = build_provider(mode=settings.llm_mode, redis_client=None, cloud_provider="mistral", api_key=api_key)

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
        CoordinatorAgent(ctx), SamplePrepAgent(ctx), BuildValidationAgent(ctx),
        SandboxSubmitAgent(ctx, cape_adapter=cape), ExecMonitorAgent(ctx, cape_adapter=cape, timeout_s=5),
        BehaviorAnalysisAgent(ctx), DecisionAgent(ctx), ReportingAgent(ctx)
    ]

    tasks = [asyncio.create_task(a.start()) for a in agents]
    log.info("Agent pipeline started. Submitting jobs...")
    
    coord = agents[0]
    assert isinstance(coord, CoordinatorAgent)
    
    proj1 = JobEnvelope(
        sample_id="pos_01",
        project_name="trojan_posgrabber",
        source_path=str(Path(r"E:\LLMalMorph2\samples\experiment_samples\extracted\samples\experiment_samples\trojan_posgrabber").resolve()),
        language="c"
    )
    
    proj2 = JobEnvelope(
        sample_id="prosto_01",
        project_name="Prosto_Stealer",
        source_path=str(Path(r"E:\LLMalMorph2\samples\experiment_samples\extracted\samples\experiment_samples\Prosto_Stealer").resolve()),
        language="c"
    )
    
    await coord.submit_job(proj1)
    await coord.submit_job(proj2)
    
    log.info("Jobs submitted. Waiting for terminal state...")
    import time
    start = time.time()
    while time.time() - start < 180:
        s1 = await ctx.state_store.get(proj1.job_id)
        s2 = await ctx.state_store.get(proj2.job_id)
        
        status1 = s1.current_status.value if s1 else "UNKNOWN"
        status2 = s2.current_status.value if s2 else "UNKNOWN"
        
        log.info(f"Status update -> POSGrabber: {status1}, ProstoStealer: {status2}")
        
        if s1 and s2:
            if s1.current_status.is_terminal() and s2.current_status.is_terminal():
                log.info("Both jobs reached terminal state!")
                break
                
        await asyncio.sleep(5)
        
    log.info("Test completed. Shutting down...")
    for a in agents: await a.stop()
    for t in tasks: t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

if __name__ == "__main__":
    asyncio.run(main())
