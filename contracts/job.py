"""
Job envelope and workflow state models.

JobEnvelope  — immutable descriptor of the work to be done (created once).
JobState     — mutable runtime state of a job (updated as job progresses).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ──────────────────────────────────────────────────────────────────────────────
# Job Status Enum
# ──────────────────────────────────────────────────────────────────────────────

class JobStatus(str, Enum):
    CREATED               = "CREATED"
    SAMPLE_PREPARING      = "SAMPLE_PREPARING"
    SAMPLE_READY          = "SAMPLE_READY"
    MUTATING              = "MUTATING"
    MUTATION_READY        = "MUTATION_READY"
    VARIANT_GENERATING    = "VARIANT_GENERATING"
    VARIANT_READY         = "VARIANT_READY"
    BUILD_VALIDATING      = "BUILD_VALIDATING"
    BUILD_READY           = "BUILD_READY"
    BUILD_FAILED          = "BUILD_FAILED"
    SANDBOX_SUBMITTING    = "SANDBOX_SUBMITTING"
    SANDBOX_SUBMITTED     = "SANDBOX_SUBMITTED"
    EXECUTION_MONITORING  = "EXECUTION_MONITORING"
    EXECUTION_COMPLETE    = "EXECUTION_COMPLETE"
    EXECUTION_FAILED      = "EXECUTION_FAILED"
    BEHAVIOR_ANALYZING    = "BEHAVIOR_ANALYZING"
    BEHAVIOR_ANALYZED     = "BEHAVIOR_ANALYZED"
    DECIDING              = "DECIDING"
    DECISION_ISSUED       = "DECISION_ISSUED"
    REPORTING             = "REPORTING"
    REPORT_READY          = "REPORT_READY"
    CLOSED                = "CLOSED"
    FAILED                = "FAILED"
    ESCALATED             = "ESCALATED"
    RETRY_PENDING         = "RETRY_PENDING"

    # Terminal states — job will not progress further
    @classmethod
    def terminal_states(cls) -> frozenset["JobStatus"]:
        return frozenset({cls.CLOSED, cls.FAILED, cls.ESCALATED})

    def is_terminal(self) -> bool:
        return self in self.terminal_states()


# ──────────────────────────────────────────────────────────────────────────────
# State transition log entry
# ──────────────────────────────────────────────────────────────────────────────

class StateTransition(BaseModel):
    from_state: JobStatus
    to_state: JobStatus
    triggered_by: str            # agent name or "coordinator"
    event_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    reason: Optional[str] = None


# ──────────────────────────────────────────────────────────────────────────────
# Job Envelope  (immutable once created)
# ──────────────────────────────────────────────────────────────────────────────

class JobEnvelope(BaseModel):
    """Immutable descriptor of what a job should do."""
    job_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sample_id: str
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

    # Source material
    source_path: str
    project_name: str
    language: str                # "c" | "cpp" | "python"

    # Pipeline parameters
    requested_strategies: List[str] = Field(default_factory=list)
    strategy_mode: str = "single"      # "single" | "stack" (apply all requested strategies sequentially)
    max_generations: int = 1           # multi-generation evolution: how many mutation→build→test cycles
    num_functions: int = 3
    target_functions: List[str] = Field(default_factory=list)  # force specific functions by name
    llm_retry_attempts: int = 5       # per-function LLM retry attempts
    sandbox_backend: str = "cape"      # "cape" | "virustotal" | "inetsim"
    sandbox_timeout_s: int = 300

    # Job priority (1 = highest, 10 = lowest)
    priority: int = 5

    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    payload_version: str = "1.0"

    model_config = {"frozen": True}   # Prevent accidental mutation


# ──────────────────────────────────────────────────────────────────────────────
# Job State  (mutable runtime context)
# ──────────────────────────────────────────────────────────────────────────────

class ErrorRecord(BaseModel):
    agent: str
    error_code: str
    error_message: str
    is_retryable: bool
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class JobState(BaseModel):
    """Mutable runtime state of a job, persisted in state store."""
    job_id: str
    sample_id: str
    correlation_id: str

    # Current position in the workflow
    current_status: JobStatus = JobStatus.CREATED
    previous_status: Optional[JobStatus] = None
    agent_in_charge: Optional[str] = None

    # Project context (needed for autonomous dispatch/retries)
    project_name: str = ""
    language: str = ""
    requested_strategies: List[str] = Field(default_factory=list)
    strategy_mode: str = "single"      # "single" | "stack"
    max_generations: int = 1           # multi-generation evolution: total mutation cycles
    current_generation: int = 1        # which generation we are on now
    num_functions: int = 3
    target_functions: List[str] = Field(default_factory=list)
    llm_retry_attempts: int = 5       # per-function LLM retry attempts (from config)

    # Retry tracking
    retry_count: int = 0
    sandbox_retry_count: int = 0
    build_retry_count: int = 0
    llm_retry_count: int = 0
    feedback_loop_count: int = 0
    mutation_cycle_count: int = 0
    max_feedback_loops: int = 3

    # Artifact references (paths in artifact store)
    source_artifact_id: Optional[str] = None
    mutation_artifact_id: Optional[str] = None
    variant_artifact_id: Optional[str] = None
    compiled_artifact_id: Optional[str] = None
    original_compiled_artifact_id: Optional[str] = None   # original binary (for equivalence check)
    sandbox_task_id: Optional[Any] = None
    sandbox_backend: Optional[str] = None
    original_sandbox_task_id: Optional[Any] = None        # CAPE/VT task for original binary
    raw_report_artifact_id: Optional[str] = None
    original_raw_report_artifact_id: Optional[str] = None # sandbox report for original binary
    analysis_result_id: Optional[str] = None
    decision_id: Optional[str] = None
    report_id: Optional[str] = None
    equivalence_result_id: Optional[str] = None           # BehaviorEquivalenceResult artifact
    
    # Comparison tracking (for mutated samples)
    is_mutated_sample: bool = False
    original_job_id: Optional[str] = None          # Reference to original sample job
    original_analysis_result_id: Optional[str] = None  # Original sample analysis
    comparison_result_id: Optional[str] = None     # Comparison analysis result

    # VirusTotal data (populated by ReportingAgent VT submission)
    vt_comparison_artifact_id: Optional[str] = None
    vt_original_malicious: Optional[int] = None
    vt_variant_malicious: Optional[int] = None
    vt_detection_delta: Optional[int] = None
    vt_direction: Optional[str] = None

    # Build fix statistics (populated by BuildValidationAgent)
    fix_stats: Optional[Dict[str, Any]] = None

    # Error history
    error_history: List[ErrorRecord] = Field(default_factory=list)

    # State audit trail
    transitions: List[StateTransition] = Field(default_factory=list)

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

    def transition_to(
        self,
        new_status: JobStatus,
        triggered_by: str,
        event_id: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> None:
        """Record a state transition in the audit trail."""
        self.transitions.append(StateTransition(
            from_state=self.current_status,
            to_state=new_status,
            triggered_by=triggered_by,
            event_id=event_id,
            reason=reason,
        ))
        self.previous_status = self.current_status
        self.current_status = new_status
        self.last_updated = datetime.utcnow()
        if new_status.is_terminal():
            self.completed_at = datetime.utcnow()

    def add_error(self, agent: str, error_code: str, message: str, retryable: bool) -> None:
        self.error_history.append(ErrorRecord(
            agent=agent,
            error_code=error_code,
            error_message=message,
            is_retryable=retryable,
        ))
        self.last_updated = datetime.utcnow()
