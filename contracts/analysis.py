"""
Analysis result contracts.

IOCEntry                  — a single extracted indicator of compromise.
BehaviorAnalysisResult    — full structured output from BehaviorAnalysisAgent.
SandboxReportModel        — Pydantic mirror of the existing SandboxReport dataclass.
ComparisonResultModel     — Pydantic mirror of ComparisonResult.
BehaviorEquivalenceResult — API-call-trace diff between original and mutated binary.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ──────────────────────────────────────────────────────────────────────────────
# IOC Entry
# ──────────────────────────────────────────────────────────────────────────────

class IOCType(str, Enum):
    FILE      = "file"
    REGISTRY  = "registry"
    NETWORK   = "network"
    MUTEX     = "mutex"
    PROCESS   = "process"
    HASH      = "hash"
    URL       = "url"
    IP        = "ip"
    DOMAIN    = "domain"


class IOCSource(str, Enum):
    RULE_BASED = "rule_based"
    LLM        = "llm"
    BOTH       = "both"


class IOCEntry(BaseModel):
    ioc_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: IOCType
    value: str
    confidence: float = Field(ge=0.0, le=1.0)
    source: IOCSource = IOCSource.RULE_BASED
    context: Optional[str] = None         # brief description of where found

    @field_validator("value")
    @classmethod
    def value_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("IOC value must not be empty")
        return v.strip()


# ──────────────────────────────────────────────────────────────────────────────
# Analysis method
# ──────────────────────────────────────────────────────────────────────────────

class AnalysisMethod(str, Enum):
    RULE_ONLY         = "rule_only"
    LLM_VALIDATED     = "llm_validated"
    LLM_WITH_FALLBACK = "llm_with_fallback"


# ──────────────────────────────────────────────────────────────────────────────
# LLM structured output schema (internal to BehaviorAnalysisAgent)
# ──────────────────────────────────────────────────────────────────────────────

class BehaviorCategory(str, Enum):
    RANSOMWARE = "ransomware"
    STEALER    = "stealer"
    LOADER     = "loader"
    BACKDOOR   = "backdoor"
    DROPPER    = "dropper"
    WORM       = "worm"
    BOTNET     = "botnet"
    UNKNOWN    = "unknown"


class BehaviorLLMOutput(BaseModel):
    """Strict structured output expected from LLM in BehaviorAnalysisAgent."""
    primary_behavior_category: BehaviorCategory
    confidence: float = Field(ge=0.0, le=1.0)
    key_behaviors: List[str] = Field(max_length=5)
    anomalies: List[str] = Field(default_factory=list)
    analyst_summary: str = Field(max_length=2000)
    ioc_extraction: List[IOCEntry] = Field(default_factory=list)

    @field_validator("key_behaviors")
    @classmethod
    def limit_behaviors(cls, v: List[str]) -> List[str]:
        return v[:5]

    @field_validator("analyst_summary")
    @classmethod
    def no_evasion_language(cls, v: str) -> str:
        """Guardrail: reject summaries containing evasion improvement suggestions."""
        forbidden_phrases = [
            "improve evasion", "enhance stealth", "bypass detection",
            "evade antivirus", "avoid detection", "improve persistence",
            "better obfuscation", "more effective payload",
        ]
        lower = v.lower()
        for phrase in forbidden_phrases:
            if phrase in lower:
                raise ValueError(
                    f"LLM output contains forbidden phrase: '{phrase}'. "
                    "Analyst summaries must describe observed behavior only."
                )
        return v


# ──────────────────────────────────────────────────────────────────────────────
# Full behavior analysis result
# ──────────────────────────────────────────────────────────────────────────────

class BehaviorAnalysisResult(BaseModel):
    """Complete output from BehaviorAnalysisAgent, persisted in storage."""
    result_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str

    # Sandbox task reference
    sandbox_task_id: Any
    sandbox_backend: str

    # Scoring
    threat_score: float = Field(ge=0.0, le=10.0)
    detection_count: int = 0
    detection_names: List[str] = Field(default_factory=list)

    # Extracted intelligence
    iocs: List[IOCEntry] = Field(default_factory=list)
    ttp_ids: List[str] = Field(default_factory=list)     # MITRE ATT&CK IDs

    # Behavioral data (normalized from raw sandbox report)
    api_call_count: int = 0
    registry_ops_count: int = 0
    file_ops_count: int = 0
    network_ops_count: int = 0
    process_ops_count: int = 0
    mutex_count: int = 0
    dll_loaded_count: int = 0

    # Classification
    primary_category: BehaviorCategory = BehaviorCategory.UNKNOWN
    category_confidence: float = 0.0
    key_behaviors: List[str] = Field(default_factory=list)
    anomalies: List[str] = Field(default_factory=list)

    # LLM-generated narrative (validated, fact-only)
    analyst_narrative: Optional[str] = None

    # Meta
    analysis_method: AnalysisMethod = AnalysisMethod.RULE_ONLY
    analysis_duration_s: float = 0.0
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"


# ──────────────────────────────────────────────────────────────────────────────
# Sandbox Report Model  (Pydantic v2 equivalent of existing SandboxReport)
# ──────────────────────────────────────────────────────────────────────────────

class SandboxReportModel(BaseModel):
    """Pydantic mirror of src/sandbox_analyzer.SandboxReport dataclass."""
    task_id: Any = 0
    status: str = "pending"
    score: float = 0.0

    detections: List[str] = Field(default_factory=list)
    signatures: List[Dict[str, Any]] = Field(default_factory=list)

    api_calls: List[Dict[str, Any]] = Field(default_factory=list)
    api_call_count: int = 0
    registry_operations: List[Dict[str, Any]] = Field(default_factory=list)
    file_operations: List[Dict[str, Any]] = Field(default_factory=list)
    network_operations: List[Dict[str, Any]] = Field(default_factory=list)
    process_operations: List[Dict[str, Any]] = Field(default_factory=list)
    mutex_operations: List[str] = Field(default_factory=list)
    behavior_summary: Dict[str, Any] = Field(default_factory=dict)
    dll_loaded: List[str] = Field(default_factory=list)

    ttps: List[Dict[str, Any]] = Field(default_factory=list)

    sample_sha256: str = ""
    sample_name: str = ""
    sample_size: int = 0

    analysis_duration: float = 0.0
    submit_time: str = ""
    complete_time: str = ""

    raw_report: Dict[str, Any] = Field(default_factory=dict, exclude=True)
    error_message: str = ""

    @classmethod
    def from_dataclass(cls, report: Any) -> "SandboxReportModel":
        """Convert legacy SandboxReport dataclass to Pydantic model."""
        return cls(
            task_id=report.task_id,
            status=report.status,
            score=report.score,
            detections=report.detections,
            signatures=report.signatures,
            api_calls=report.api_calls,
            api_call_count=report.api_call_count,
            registry_operations=report.registry_operations,
            file_operations=report.file_operations,
            network_operations=report.network_operations,
            process_operations=report.process_operations,
            mutex_operations=report.mutex_operations,
            behavior_summary=report.behavior_summary,
            dll_loaded=report.dll_loaded,
            ttps=report.ttps,
            sample_sha256=report.sample_sha256,
            sample_name=report.sample_name,
            sample_size=report.sample_size,
            analysis_duration=report.analysis_duration,
            submit_time=report.submit_time,
            complete_time=report.complete_time,
            raw_report=report.raw_report,
            error_message=report.error_message,
        )


# ──────────────────────────────────────────────────────────────────────────────
# Comparison Result Model
# ──────────────────────────────────────────────────────────────────────────────

class ComparisonResultModel(BaseModel):
    """Pydantic mirror of src/sandbox_analyzer.ComparisonResult dataclass."""
    original_detections: int = 0
    mutated_detections: int = 0
    detection_delta: int = 0
    api_similarity: float = 0.0
    behavioral_preserved: bool = False
    new_signatures: List[str] = Field(default_factory=list)
    removed_signatures: List[str] = Field(default_factory=list)
    common_signatures: List[str] = Field(default_factory=list)
    score_delta: float = 0.0
    original_score: float = 0.0
    mutated_score: float = 0.0

    @classmethod
    def from_dataclass(cls, comparison: Any) -> "ComparisonResultModel":
        d = comparison.to_dict()
        return cls(**d)


# ──────────────────────────────────────────────────────────────────────────────
# Behavioral Equivalence Result
# ──────────────────────────────────────────────────────────────────────────────

class EquivalenceVerdict(str, Enum):
    EQUIVALENT          = "equivalent"          # API traces match closely
    MOSTLY_EQUIVALENT   = "mostly_equivalent"   # Minor divergence, core behavior preserved
    DIVERGENT           = "divergent"           # Significant behavioral change detected
    INCONCLUSIVE        = "inconclusive"        # Original baseline not available


class BehaviorEquivalenceResult(BaseModel):
    """
    Side-by-side API-call-trace diff between the original compiled binary
    and the mutated variant, both run through the same sandbox.

    Produced by BehaviorAnalysisAgent when original_raw_report_artifact_id
    is present in the job state.
    """
    result_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str

    # Sandbox task references
    original_task_id: Any = None
    mutated_task_id: Any = None

    # API-call set comparison
    original_api_calls: List[str] = Field(default_factory=list)
    mutated_api_calls: List[str] = Field(default_factory=list)
    api_calls_only_in_original: List[str] = Field(default_factory=list)
    api_calls_only_in_mutated: List[str] = Field(default_factory=list)
    api_call_jaccard_similarity: float = Field(default=0.0, ge=0.0, le=1.0)
    api_call_sequence_similarity: float = Field(default=0.0, ge=0.0, le=1.0)

    # Resource-access diff
    registry_keys_only_in_original: List[str] = Field(default_factory=list)
    registry_keys_only_in_mutated: List[str] = Field(default_factory=list)
    file_paths_only_in_original: List[str] = Field(default_factory=list)
    file_paths_only_in_mutated: List[str] = Field(default_factory=list)
    network_hosts_only_in_original: List[str] = Field(default_factory=list)
    network_hosts_only_in_mutated: List[str] = Field(default_factory=list)

    # TTP preservation
    original_ttp_ids: List[str] = Field(default_factory=list)
    mutated_ttp_ids: List[str] = Field(default_factory=list)
    ttp_preservation_rate: float = Field(default=0.0, ge=0.0, le=1.0)

    # IOC string preservation
    original_malicious_strings: List[str] = Field(default_factory=list)
    mutated_malicious_strings: List[str] = Field(default_factory=list)
    malicious_string_preservation_rate: float = Field(default=0.0, ge=0.0, le=1.0)

    # Scoring
    overall_equivalence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    verdict: EquivalenceVerdict = EquivalenceVerdict.INCONCLUSIVE
    verdict_confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    # Human-readable summary
    summary: str = ""
    limitations: List[str] = Field(default_factory=list)

    computed_at: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"
