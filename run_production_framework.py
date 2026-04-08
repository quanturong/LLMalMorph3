from __future__ import annotations

import argparse
import asyncio
import builtins
import copy
import json
import os
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from adapters.cape_adapter import CapeAdapter
from adapters.virustotal_adapter import VirusTotalAdapter
from agents import (
    AgentContext,
    BehaviorAnalysisAgent,
    BuildValidationAgent,
    DecisionAgent,
    ExecMonitorAgent,
    MonitorAgent,
    MutationAgent,
    ReportingAgent,
    SamplePrepAgent,
    SandboxSubmitAgent,
    VariantGenerationAgent,
)
from broker.memory_broker import MemoryBroker
from broker.redis_streams import RedisStreamsBroker
from contracts.job import JobEnvelope
from llm.factory import build_provider
from observability.logging_config import configure_logging
from services.agent_registry import AgentRegistry
from storage.artifact_store import ArtifactStore
from storage.report_store import ReportStore
from storage.state_store import StateStore

ROOT_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = ROOT_DIR / "configs" / "framework_production.json"
ALLOWED_PRINT_PREFIXES = (
    "CONFIG",
    "START",
    "STATUS",
    "TERMINAL",
    "FINAL",
    "ERROR",
    "REPORT",
    "DONE",
)


def _load_dotenv_file(env_path: Path) -> None:
    if not env_path.exists():
        return

    try:
        with env_path.open("r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and value and not os.environ.get(key):
                    os.environ[key] = value
    except Exception:
        # Fail open: runtime can still proceed with explicit env vars.
        pass


def _filtered_print(enabled: bool) -> None:
    if not enabled:
        return

    original_print = builtins.print

    def _quiet_print(*args, **kwargs):
        text = " ".join(str(a) for a in args)
        if text.startswith(ALLOWED_PRINT_PREFIXES):
            original_print(*args, **kwargs)

    builtins.print = _quiet_print


def _load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _interpolate_env_vars(value: Any) -> Any:
    """Recursively replace '${VAR_NAME}' strings with their env var values."""
    if isinstance(value, dict):
        return {k: _interpolate_env_vars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate_env_vars(item) for item in value]
    if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
        var_name = value[2:-1]
        return os.getenv(var_name, "")
    return value


def _resolve_with_timestamp(value: str, timestamp: str) -> str:
    return value.replace("{timestamp}", timestamp)


def _resolve_path(root: Path, value: str, timestamp: str) -> str:
    resolved = Path(_resolve_with_timestamp(value, timestamp))
    if not resolved.is_absolute():
        resolved = root / resolved
    return str(resolved.resolve())


def _resolve_config(config: dict[str, Any], root: Path) -> dict[str, Any]:
    cfg = _interpolate_env_vars(copy.deepcopy(config))
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    runtime = cfg.setdefault("runtime", {})
    storage = cfg.setdefault("storage", {})
    broker = cfg.setdefault("broker", {})
    logging_cfg = cfg.setdefault("logging", {})
    llm_cfg = cfg.setdefault("llm", {})

    runtime.setdefault("max_wait_s", 2400)
    runtime.setdefault("status_interval_s", 30)
    runtime.setdefault("sandbox_timeout_s", 1200)
    runtime.setdefault("quiet_console", True)

    broker.setdefault("mode", "memory")
    broker.setdefault("redis_url", os.getenv("REDIS_URL", "redis://localhost:6379/0"))

    storage.setdefault("db_path", "project_mutation_output/state_prod_{timestamp}.db")
    storage.setdefault("artifact_dir", "project_mutation_output/artifacts_prod_{timestamp}")
    storage.setdefault("report_dir", "project_mutation_output/reports_prod_{timestamp}")
    storage.setdefault("work_dir", "project_mutation_output/work_prod_{timestamp}")

    logging_cfg.setdefault("level", os.getenv("FRAMEWORK_LOG_LEVEL", "WARNING"))

    llm_cfg.setdefault("enabled", False)
    llm_cfg.setdefault("mode", os.getenv("FRAMEWORK_LLM_MODE", "mistral"))
    llm_cfg.setdefault("cloud_provider", os.getenv("FRAMEWORK_LLM_PROVIDER", "mistral"))
    llm_cfg.setdefault("cache_ttl_s", 3600)

    runtime["timestamp"] = timestamp
    storage["db_path"] = _resolve_path(root, storage["db_path"], timestamp)
    storage["artifact_dir"] = _resolve_path(root, storage["artifact_dir"], timestamp)
    storage["report_dir"] = _resolve_path(root, storage["report_dir"], timestamp)
    storage["work_dir"] = _resolve_path(root, storage["work_dir"], timestamp)

    for sample in cfg.get("samples", []):
        sample["source_path"] = _resolve_path(root, sample["source_path"], timestamp)

    return cfg


async def _build_broker_and_redis(cfg: dict[str, Any]):
    broker_cfg = cfg["broker"]
    mode = str(broker_cfg.get("mode", "memory")).lower()
    redis_client = None

    if mode == "redis":
        import redis.asyncio as aioredis

        redis_url = broker_cfg["redis_url"]
        redis_client = await aioredis.from_url(
            redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
        broker = RedisStreamsBroker(redis_url=redis_url)
    else:
        broker = MemoryBroker()

    return broker, redis_client


async def _build_llm_provider(cfg: dict[str, Any], redis_client):
    llm_cfg = cfg["llm"]
    if not llm_cfg.get("enabled", False):
        return None

    mode = llm_cfg.get("mode", "mistral")
    cloud_provider = llm_cfg.get("cloud_provider", "mistral")
    cloud_base_url = llm_cfg.get("cloud_base_url", "")
    api_key = llm_cfg.get("api_key", "")
    if cloud_provider == "deepseek":
        api_key = api_key or os.getenv("DEEPSEEK_API_KEY", "")
    elif cloud_provider == "salad":
        api_key = api_key or os.getenv("SALAD_API_KEY", "") or os.getenv("RUNPOD_API_KEY", "")
    elif cloud_provider in ("runpod", "openai_compatible"):
        api_key = api_key or os.getenv("RUNPOD_API_KEY", "")
    elif cloud_provider == "azure":
        api_key = api_key or os.getenv("AZURE_OPENAI_API_KEY", "")
    else:
        api_key = api_key or os.getenv("MISTRAL_API_KEY", "")

    if mode == "deepseek" and not api_key:
        raise ValueError("DEEPSEEK_API_KEY is required when llm.enabled=true and llm.mode=deepseek")
    if cloud_provider in ("runpod", "openai_compatible", "salad") and not api_key:
        # Allow "none" or "dummy" for Ollama endpoints that don't need auth
        raise ValueError(f"{cloud_provider.upper()} API key is required when llm.cloud_provider={cloud_provider}. "
                         f"Use api_key='none' for endpoints without authentication.")
    if cloud_provider in ("runpod", "openai_compatible", "salad") and not (
        cloud_base_url or os.getenv("CLOUD_URL", "") or os.getenv("SALAD_URL", "")
    ):
        raise ValueError("CLOUD_URL (or llm.cloud_base_url) is required when llm.cloud_provider={cloud_provider}")
    if mode in ("mistral", "cloud_only") and cloud_provider != "deepseek" and not api_key:
        raise ValueError("MISTRAL_API_KEY is required when llm.enabled=true and llm.mode uses mistral/cloud_only")
    if cloud_provider == "azure" and not api_key:
        raise ValueError("AZURE_OPENAI_API_KEY is required when llm.cloud_provider=azure")

    return build_provider(
        mode=mode,
        redis_client=redis_client,
        cache_ttl_s=int(llm_cfg.get("cache_ttl_s", 3600)),
        local_model=llm_cfg.get("local_model", "qwen2.5-coder:7b-instruct-q4_K_M"),
        cloud_model=llm_cfg.get("cloud_model"),
        cloud_base_url=cloud_base_url,
        api_key=api_key,
        cloud_provider=cloud_provider,
        fallback_provider=llm_cfg.get("fallback_provider", "deepseek"),
        fallback_model=llm_cfg.get("fallback_model", "deepseek-chat"),
        cloud_extra_urls=llm_cfg.get("cloud_extra_urls", []),
    )


def _print_config_summary(cfg: dict[str, Any], cape_url: str) -> None:
    print("CONFIG", json.dumps({
        "broker_mode": cfg["broker"]["mode"],
        "db_path": cfg["storage"]["db_path"],
        "artifact_dir": cfg["storage"]["artifact_dir"],
        "report_dir": cfg["storage"]["report_dir"],
        "work_dir": cfg["storage"]["work_dir"],
        "log_level": cfg["logging"]["level"],
        "sandbox_timeout_s": cfg["runtime"]["sandbox_timeout_s"],
        "max_wait_s": cfg["runtime"]["max_wait_s"],
        "cape_base_url": cape_url,
        "llm_enabled": cfg["llm"]["enabled"],
        "samples": cfg.get("samples", []),
    }, ensure_ascii=False))


def _export_llm_env_vars(cfg: dict[str, Any]) -> None:
    """Export LLM config values as env vars for the legacy src/llm_api.py system."""
    llm_cfg = cfg.get("llm", {})
    cloud_base_url = llm_cfg.get("cloud_base_url", "")
    api_key = llm_cfg.get("api_key", "")
    cloud_provider = llm_cfg.get("cloud_provider", "")

    if cloud_base_url and not os.environ.get("RUNPOD_BASE_URL"):
        os.environ["RUNPOD_BASE_URL"] = cloud_base_url

    if api_key and cloud_provider in ("runpod", "openai_compatible") and not os.environ.get("RUNPOD_API_KEY"):
        os.environ["RUNPOD_API_KEY"] = api_key

    if api_key and cloud_provider == "salad":
        if not os.environ.get("SALAD_API_KEY"):
            os.environ["SALAD_API_KEY"] = api_key
        # Also set RUNPOD env vars for legacy code paths that check them
        if not os.environ.get("RUNPOD_API_KEY"):
            os.environ["RUNPOD_API_KEY"] = api_key

    if cloud_base_url and cloud_provider in ("salad",) and not os.environ.get("CLOUD_URL"):
        os.environ["CLOUD_URL"] = cloud_base_url
    # RunPod/OpenAI-compatible: ALWAYS override CLOUD_URL (may be stale from .env)
    if cloud_base_url and cloud_provider in ("runpod", "openai_compatible"):
        os.environ["CLOUD_URL"] = cloud_base_url

    # Export the cloud model name so the auto-fixer uses the correct model on RunPod
    cloud_model = llm_cfg.get("cloud_model", "")
    if cloud_model and cloud_provider in ("runpod", "openai_compatible"):
        os.environ["FIXER_MODEL"] = cloud_model

    # Parallel race: export extra cloud URLs for RaceLLMProvider
    extra_urls = llm_cfg.get("cloud_extra_urls", [])
    if extra_urls:
        # Normalize: ensure /v1 suffix
        normalized = []
        for u in extra_urls:
            u = u.strip().rstrip("/")
            if not u.endswith("/v1"):
                u += "/v1"
            normalized.append(u)
        os.environ["CLOUD_URLS"] = ",".join(normalized)

    if api_key and cloud_provider == "deepseek" and not os.environ.get("DEEPSEEK_API_KEY"):
        os.environ["DEEPSEEK_API_KEY"] = api_key


async def run_production(config_path: Path, dry_run: bool = False) -> int:
    _load_dotenv_file(ROOT_DIR / ".env")
    cfg = _resolve_config(_load_config(config_path), ROOT_DIR)

    # Export key LLM settings as env vars so the legacy src/llm_api.py system
    # (AutoFixer / project_compiler) can route to RunPod without extra config.
    _export_llm_env_vars(cfg)

    _filtered_print(bool(cfg["runtime"].get("quiet_console", True)))
    configure_logging(level=cfg["logging"]["level"])

    cape_url = os.getenv("CAPE_BASE_URL", cfg.get("sandbox", {}).get("cape_base_url", "http://192.168.1.12:8000"))
    cape_token = os.getenv("CAPE_API_TOKEN", cfg.get("sandbox", {}).get("cape_api_token", ""))
    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY", cfg.get("sandbox", {}).get("virustotal_api_key", ""))
    vt_api_url = cfg.get("sandbox", {}).get("virustotal_api_url", "https://www.virustotal.com")

    _print_config_summary(cfg, cape_url)
    if dry_run:
        print("DONE", {"dry_run": True})
        return 0

    broker, redis_client = await _build_broker_and_redis(cfg)
    llm_provider = await _build_llm_provider(cfg, redis_client)

    state_store = StateStore(redis_client=redis_client, db_path=cfg["storage"]["db_path"])
    artifact_store = ArtifactStore(
        base_dir=cfg["storage"]["artifact_dir"],
        db_path=cfg["storage"]["db_path"],
        encrypt_pe=cfg["storage"].get("encrypt_pe", False),
        encryption_key=cfg["storage"].get("encryption_key") or os.environ.get("ARTIFACT_ENCRYPTION_KEY"),
    )
    report_store = ReportStore(db_path=cfg["storage"]["db_path"], reports_dir=cfg["storage"]["report_dir"])
    cape = CapeAdapter(api_url=cape_url, api_token=cape_token)
    vt = VirusTotalAdapter(api_key=vt_api_key, api_url=vt_api_url) if vt_api_key else None

    # Build agent registry for distributed coordination
    agent_registry = AgentRegistry()

    ctx = AgentContext(
        broker=broker,
        redis_client=redis_client,
        state_store=state_store,
        artifact_store=artifact_store,
        report_store=report_store,
        llm_provider=llm_provider,
        agent_registry=agent_registry,
        work_dir=cfg["storage"]["work_dir"],
    )

    # Distributed multi-agent system:
    # - MonitorAgent: passive health monitor + job submission (replaces CoordinatorAgent)
    # - All worker agents: self-activating via EVENTS_ALL subscription
    # - No central routing — agents claim jobs via atomic CAS
    monitor = MonitorAgent(ctx)
    agents = [
        monitor,
        SamplePrepAgent(ctx),
        MutationAgent(ctx),
        VariantGenerationAgent(ctx),
        BuildValidationAgent(ctx),
        SandboxSubmitAgent(ctx, cape_adapter=cape, vt_adapter=vt),
        ExecMonitorAgent(ctx, cape_adapter=cape, vt_adapter=vt, timeout_s=int(cfg["runtime"]["sandbox_timeout_s"])),
        BehaviorAnalysisAgent(ctx),
        DecisionAgent(ctx),
        ReportingAgent(ctx),
    ]
    tasks = [asyncio.create_task(a.start()) for a in agents]

    coord = monitor  # MonitorAgent handles job submission
    envelopes: list[tuple[str, JobEnvelope]] = []
    mutation_cfg = cfg.get("mutation", {})
    for sample in cfg.get("samples", []):
        envelope = JobEnvelope(
            sample_id=sample["sample_id"],
            project_name=sample["project_name"],
            source_path=sample["source_path"],
            language=sample["language"],
            sandbox_backend=sample.get("sandbox_backend", "cape"),
            sandbox_timeout_s=int(cfg["runtime"]["sandbox_timeout_s"]),
            priority=int(sample.get("priority", 5)),
            requested_strategies=sample.get("requested_strategies",
                                            [mutation_cfg.get("default_strategy", "strat_1")]),
            num_functions=int(sample.get("num_functions",
                                        mutation_cfg.get("num_functions_per_project", 3))),
            target_functions=sample.get("target_functions", []),
            metadata=sample.get("metadata", {}),
        )
        envelopes.append((sample["sample_id"], envelope))
        await coord.submit_job(envelope)

    print("START", "production_run", *[env.job_id for _, env in envelopes])

    start = time.time()
    max_wait_s = int(cfg["runtime"]["max_wait_s"])
    status_interval_s = int(cfg["runtime"]["status_interval_s"])
    last_status_t = 0.0

    while time.time() - start < max_wait_s:
        snapshots = []
        all_terminal = True
        for sample_id, env in envelopes:
            state = await state_store.get(env.job_id)
            status = state.current_status.value if state else "NONE"
            snapshots.append((sample_id, status))
            all_terminal = all_terminal and bool(state and state.current_status.is_terminal())

        now = time.time()
        if now - last_status_t >= status_interval_s:
            print("STATUS", int(now - start), snapshots)
            last_status_t = now

        if all_terminal:
            print("TERMINAL", int(time.time() - start))
            break
        await asyncio.sleep(2)

    final_states: dict[str, str] = {}
    for sample_id, env in envelopes:
        state = await state_store.get(env.job_id)
        if not state:
            final_states[sample_id] = "MISSING"
            print("FINAL", sample_id, "MISSING")
            continue

        final_states[sample_id] = state.current_status.value
        print(
            "FINAL",
            sample_id,
            state.current_status.value,
            "retries",
            state.retry_count,
            "sandbox_retries",
            state.sandbox_retry_count,
            "errors",
            len(state.error_history),
        )
        for err in state.error_history:
            print("ERROR", sample_id, err.agent, err.error_code, err.error_message)

    conn = sqlite3.connect(cfg["storage"]["db_path"])
    try:
        for row in conn.execute(
            "SELECT report_id, job_id, sample_id, report_path, summary_path, created_at "
            "FROM reports ORDER BY created_at DESC LIMIT 50"
        ):
            print("REPORT", row)
    finally:
        conn.close()

    for agent in agents:
        await agent.stop()
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

    if hasattr(broker, "close"):
        maybe = broker.close()
        if asyncio.iscoroutine(maybe):
            await maybe
    if redis_client is not None:
        await redis_client.aclose()

    print("DONE", final_states)
    return 0 if all(v == "CLOSED" for v in final_states.values()) else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Run production profile for the multi-agent framework")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to production JSON config")
    parser.add_argument("--dry-run", action="store_true", help="Resolve config/env and print effective settings without running")
    args = parser.parse_args()

    return asyncio.run(run_production(Path(args.config).resolve(), dry_run=args.dry_run))


if __name__ == "__main__":
    raise SystemExit(main())
