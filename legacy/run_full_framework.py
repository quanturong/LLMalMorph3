from __future__ import annotations

import asyncio
import builtins
import os
import sqlite3
import time
from pathlib import Path

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
from contracts.job import JobEnvelope
from observability.logging_config import configure_logging
from storage.artifact_store import ArtifactStore
from storage.report_store import ReportStore
from storage.state_store import StateStore

DB_PATH = "state_full_run_latest.db"
ARTIFACT_DIR = "artifacts_full_run_latest"
REPORT_DIR = "reports_full_run_latest"

_ALLOWED_PREFIXES = ("START", "STATUS", "TERMINAL", "FINAL", "ERROR", "REPORT", "DONE")
_original_print = builtins.print


def _quiet_print(*args, **kwargs):
    text = " ".join(str(a) for a in args)
    if text.startswith(_ALLOWED_PREFIXES):
        _original_print(*args, **kwargs)


builtins.print = _quiet_print


async def run_full() -> int:
    configure_logging(level="WARNING")

    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    broker = MemoryBroker()
    state_store = StateStore(redis_client=None, db_path=DB_PATH)
    artifact_store = ArtifactStore(base_dir=ARTIFACT_DIR, db_path=DB_PATH)
    report_store = ReportStore(db_path=DB_PATH, reports_dir=REPORT_DIR)

    cape_url = os.getenv("CAPE_BASE_URL", "http://192.168.1.12:8000")
    cape_token = os.getenv("CAPE_API_TOKEN", "")
    cape = CapeAdapter(api_url=cape_url, api_token=cape_token)

    ctx = AgentContext(
        broker=broker,
        redis_client=None,
        state_store=state_store,
        artifact_store=artifact_store,
        report_store=report_store,
        llm_provider=None,
    )

    agents = [
        CoordinatorAgent(ctx),
        SamplePrepAgent(ctx),
        BuildValidationAgent(ctx),
        SandboxSubmitAgent(ctx, cape_adapter=cape),
        ExecMonitorAgent(ctx, cape_adapter=cape, timeout_s=1200),
        BehaviorAnalysisAgent(ctx),
        DecisionAgent(ctx),
        ReportingAgent(ctx),
    ]

    tasks = [asyncio.create_task(a.start()) for a in agents]

    pos = JobEnvelope(
        sample_id="pos_full",
        project_name="POSGrabber",
        source_path=str(Path(r"E:\LLMalMorph2\samples\experiment_samples\extracted\samples\experiment_samples\trojan_posgrabber\Trojan-Banker.Win32.Dexter_EXPERIMENT\Dexter\POSGrabber")),
        language="cpp",
    )
    rw = JobEnvelope(
        sample_id="ransom_full",
        project_name="Win32.RansomWar",
        source_path=str(Path(r"E:\LLMalMorph2\samples\experiment_samples\extracted\samples\experiment_samples\Win32.RansomWar")),
        language="c",
    )

    coord = agents[0]
    await coord.submit_job(pos)
    await coord.submit_job(rw)

    print("START full_run", pos.job_id, rw.job_id)

    start = time.time()
    max_wait_s = int(os.getenv("FULL_RUN_MAX_WAIT_S", "2400"))
    last_status_t = 0.0

    while time.time() - start < max_wait_s:
        s1 = await state_store.get(pos.job_id)
        s2 = await state_store.get(rw.job_id)

        now = time.time()
        if now - last_status_t >= 30:
            print(
                "STATUS",
                int(now - start),
                s1.current_status.value if s1 else "NONE",
                s2.current_status.value if s2 else "NONE",
            )
            last_status_t = now

        if s1 and s2 and s1.current_status.is_terminal() and s2.current_status.is_terminal():
            print("TERMINAL", int(time.time() - start))
            break

        await asyncio.sleep(2)

    final_states = {}
    for sample, job_id in (("pos_full", pos.job_id), ("ransom_full", rw.job_id)):
        s = await state_store.get(job_id)
        if not s:
            final_states[sample] = "MISSING"
            print("FINAL", sample, "MISSING")
            continue

        final_states[sample] = s.current_status.value
        print(
            "FINAL",
            sample,
            s.current_status.value,
            "retries",
            s.retry_count,
            "sandbox_retries",
            s.sandbox_retry_count,
            "errors",
            len(s.error_history),
        )
        for e in s.error_history:
            print("ERROR", sample, e.agent, e.error_code, e.error_message)

    conn = sqlite3.connect(DB_PATH)
    try:
        for row in conn.execute(
            "SELECT report_id, job_id, sample_id, report_path, summary_path, created_at "
            "FROM reports ORDER BY created_at DESC LIMIT 20"
        ):
            print("REPORT", row)
    finally:
        conn.close()

    for a in agents:
        await a.stop()
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    await broker.close()

    print("DONE", final_states)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run_full()))
