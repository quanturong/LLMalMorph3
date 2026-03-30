"""
Report contracts: structured technical report and executive summary.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from .analysis import BehaviorAnalysisResult, ComparisonResultModel, IOCEntry
from .decisions import DecisionResult


class RiskLevel(str, Enum):
    CRITICAL       = "critical"
    HIGH           = "high"
    MEDIUM         = "medium"
    LOW            = "low"
    INFORMATIONAL  = "informational"


# ──────────────────────────────────────────────────────────────────────────────
# Technical Report  (structured, machine-readable first)
# ──────────────────────────────────────────────────────────────────────────────

class TechnicalReport(BaseModel):
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str

    # Sample metadata
    project_name: str
    language: str
    sample_sha256: str = ""
    sample_name: str = ""
    binary_size_bytes: int = 0

    # Analysis core data
    threat_score: float = 0.0
    detection_count: int = 0
    detection_names: List[str] = Field(default_factory=list)
    primary_category: str = "unknown"
    ioc_list: List[IOCEntry] = Field(default_factory=list)
    ttp_ids: List[str] = Field(default_factory=list)

    # Behavioral counts
    api_call_count: int = 0
    registry_ops_count: int = 0
    file_ops_count: int = 0
    network_ops_count: int = 0
    process_ops_count: int = 0
    dll_loaded_count: int = 0

    # Key behavioral observations
    key_behaviors: List[str] = Field(default_factory=list)
    anomalies: List[str] = Field(default_factory=list)

    # Comparison (only for mutated samples)
    comparison: Optional[ComparisonResultModel] = None
    is_mutated_sample: bool = False

    # Decision
    final_decision: Optional[DecisionResult] = None

    # Timestamps
    sandbox_duration_s: float = 0.0
    analysis_duration_s: float = 0.0
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"

    @classmethod
    def from_analysis(
        cls,
        analysis: BehaviorAnalysisResult,
        job_id: str,
        sample_id: str,
        correlation_id: str,
        project_name: str,
        language: str,
        decision: Optional[DecisionResult] = None,
        comparison: Optional[ComparisonResultModel] = None,
    ) -> "TechnicalReport":
        return cls(
            job_id=job_id,
            sample_id=sample_id,
            correlation_id=correlation_id,
            project_name=project_name,
            language=language,
            threat_score=analysis.threat_score,
            detection_count=analysis.detection_count,
            detection_names=analysis.detection_names,
            primary_category=analysis.primary_category.value,
            ioc_list=analysis.iocs,
            ttp_ids=analysis.ttp_ids,
            api_call_count=analysis.api_call_count,
            registry_ops_count=analysis.registry_ops_count,
            file_ops_count=analysis.file_ops_count,
            network_ops_count=analysis.network_ops_count,
            process_ops_count=analysis.process_ops_count,
            dll_loaded_count=analysis.dll_loaded_count,
            key_behaviors=analysis.key_behaviors,
            anomalies=analysis.anomalies,
            analysis_duration_s=analysis.analysis_duration_s,
            final_decision=decision,
            comparison=comparison,
            is_mutated_sample=(comparison is not None),
        )


# ──────────────────────────────────────────────────────────────────────────────
# Executive Summary  (LLM-generated narrative, derived from TechnicalReport)
# ──────────────────────────────────────────────────────────────────────────────

class ExecutiveSummary(BaseModel):
    summary_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    report_id: str
    job_id: str

    title: str
    risk_level: RiskLevel
    one_line_summary: str = Field(max_length=200)
    key_findings: List[str] = Field(max_length=5)
    recommended_actions: List[str] = Field(max_length=3, default_factory=list)
    full_narrative: str = Field(max_length=4000)

    generated_by: str = "llm"        # "llm" | "template"
    model_used: Optional[str] = None
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"

    @field_validator("key_findings")
    @classmethod
    def limit_findings(cls, v: List[str]) -> List[str]:
        return v[:5]

    @field_validator("recommended_actions")
    @classmethod
    def no_evasion_actions(cls, v: List[str]) -> List[str]:
        """Guardrail: recommendations must not suggest improving malware."""
        forbidden = [
            "improve evasion", "enhance stealth", "bypass", "obfuscate",
            "improve malware", "optimize payload",
        ]
        for action in v:
            lower = action.lower()
            for phrase in forbidden:
                if phrase in lower:
                    raise ValueError(
                        f"Recommended action contains forbidden phrase: '{phrase}'"
                    )
        return v[:3]

    @field_validator("full_narrative")
    @classmethod
    def narrative_is_factual(cls, v: str) -> str:
        """Light guardrail on full narrative."""
        evasion_phrases = [
            "improve evasion", "better at evading", "enhance stealth",
            "harder to detect", "more effective at bypassing",
        ]
        lower = v.lower()
        for phrase in evasion_phrases:
            if phrase in lower:
                raise ValueError(
                    f"Narrative contains evasion improvement suggestion: '{phrase}'"
                )
        return v
