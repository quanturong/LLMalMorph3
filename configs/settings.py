"""Runtime settings for the multi-agent pipeline."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class PipelineSettings:
    # Feature flags
    use_agent_broker: bool = False
    llm_mode: str = "hybrid"  # local_only | cloud_only | mistral | deepseek | hybrid

    # Broker / state
    redis_url: str = "redis://localhost:6379/0"
    sqlite_path: str = "state.db"
    reports_dir: str = "reports"
    artifacts_dir: str = "artifacts"

    # Sandbox
    cape_base_url: str = "http://127.0.0.1:8000"
    cape_api_token: str = ""
    sandbox_timeout_s: int = 600

    # LLM
    mistral_api_key: str = ""
    deepseek_api_key: str = ""
    ollama_base_url: str = "http://localhost:11434"

    # Observability
    log_level: str = "INFO"
    metrics_port: int = 9100

    # Agent-local autonomy / feedback policies
    decision_enable_autonomy: bool = True
    decision_mutation_score_threshold: float = 5.5
    decision_mutation_max_iocs: int = 3


    @classmethod
    def from_env(cls) -> "PipelineSettings":
        def _bool(name: str, default: bool) -> bool:
            v = os.getenv(name)
            if v is None:
                return default
            return v.strip().lower() in {"1", "true", "yes", "on"}

        def _int(name: str, default: int) -> int:
            try:
                return int(os.getenv(name, str(default)))
            except ValueError:
                return default

        def _float(name: str, default: float) -> float:
            try:
                return float(os.getenv(name, str(default)))
            except ValueError:
                return default

        return cls(
            use_agent_broker=_bool("USE_AGENT_BROKER", False),
            llm_mode=os.getenv("LLM_MODE", "hybrid"),
            redis_url=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            sqlite_path=os.getenv("SQLITE_PATH", "state.db"),
            reports_dir=os.getenv("REPORTS_DIR", "reports"),
            artifacts_dir=os.getenv("ARTIFACTS_DIR", "artifacts"),
            cape_base_url=os.getenv("CAPE_BASE_URL", "http://127.0.0.1:8000"),
            cape_api_token=os.getenv("CAPE_API_TOKEN", ""),
            sandbox_timeout_s=_int("SANDBOX_TIMEOUT_S", 600),
            mistral_api_key=os.getenv("MISTRAL_API_KEY", ""),
            deepseek_api_key=os.getenv("DEEPSEEK_API_KEY", ""),
            ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            metrics_port=_int("METRICS_PORT", 9100),
            decision_enable_autonomy=_bool("DECISION_ENABLE_AUTONOMY", True),
            decision_mutation_score_threshold=_float("DECISION_MUTATION_SCORE_THRESHOLD", 5.5),
            decision_mutation_max_iocs=_int("DECISION_MUTATION_MAX_IOCS", 3),
        )
