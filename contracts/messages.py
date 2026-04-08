"""
Message envelope and all event/command types for the multi-agent pipeline.

Conventions:
  - *Command  = point-to-point directive (coordinator → specific agent)
  - *Event    = broadcast notification (agent → events stream → coordinator)
  - ErrorEvent = transient or permanent failure notification
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


# ──────────────────────────────────────────────────────────────────────────────
# Base Envelope
# ──────────────────────────────────────────────────────────────────────────────

class MessageEnvelope(BaseModel):
    """Standard wrapper for every message in the broker."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    parent_event_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    producer: str                     # agent name that emitted this
    consumer_target: str              # stream/topic name
    retry_count: int = 0
    payload_version: str = "1.0"
    event_type: str
    payload: Dict[str, Any] = Field(default_factory=dict)


# ──────────────────────────────────────────────────────────────────────────────
# Commands  (coordinator → agent)
# ──────────────────────────────────────────────────────────────────────────────

class SamplePrepCommand(BaseModel):
    """Instruct SamplePrepAgent to detect/parse the project."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    source_path: str
    project_name: str
    language: str
    num_functions: int = 3
    requested_strategies: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    retry_count: int = 0
    payload_version: str = "1.0"


class MutateCommand(BaseModel):
    """Instruct MutationAgent to mutate selected functions via LLM."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    source_artifact_id: str           # reference to parsed source in ArtifactStore
    project_name: str
    language: str
    mutation_strategy: str = "strat_1"
    requested_strategies: list[str] = Field(default_factory=list)
    num_functions: int = 3
    target_functions: list[str] = Field(default_factory=list)
    retry_attempts: int = 5
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    retry_count: int = 0
    payload_version: str = "1.0"


class GenerateVariantCommand(BaseModel):
    """Instruct VariantGenerationAgent to stitch mutated functions into variant source."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    source_artifact_id: str           # reference to original parsed source
    mutation_artifact_id: str         # reference to mutation results
    project_name: str
    language: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    retry_count: int = 0
    payload_version: str = "1.0"


class BuildValidateCommand(BaseModel):
    """Instruct BuildValidationAgent to compile and validate the variant."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    source_artifact_id: str           # reference to prepared source in ArtifactStore
    project_name: str
    language: str
    mutation_strategy: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    retry_count: int = 0
    payload_version: str = "1.0"


class SandboxSubmitCommand(BaseModel):
    """Instruct SandboxSubmitAgent to submit the compiled binary."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    compiled_artifact_id: str         # reference to binary in ArtifactStore
    sandbox_backend: str = "cape"
    sandbox_timeout_s: int = 300
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    retry_count: int = 0
    payload_version: str = "1.0"


class ExecMonitorCommand(BaseModel):
    """Instruct ExecMonitorAgent to poll sandbox status."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    sandbox_task_id: Any
    sandbox_backend: str = "cape"
    timeout_s: int = 300
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    retry_count: int = 0
    payload_version: str = "1.0"


class AnalyzeBehaviorCommand(BaseModel):
    """Instruct BehaviorAnalysisAgent to analyze the raw sandbox report."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    raw_report_artifact_id: str
    sandbox_backend: str = "cape"
    use_llm: bool = True
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    retry_count: int = 0
    payload_version: str = "1.0"


class DecideCommand(BaseModel):
    """Instruct DecisionAgent to determine next workflow action."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    analysis_result_id: str
    job_retry_count: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    retry_count: int = 0
    payload_version: str = "1.0"


class ReportCommand(BaseModel):
    """Instruct ReportingAgent to generate reports."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    analysis_result_id: str
    decision_id: str
    output_dir: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    retry_count: int = 0
    payload_version: str = "1.0"


# ──────────────────────────────────────────────────────────────────────────────
# Events  (agent → events stream → coordinator)
# ──────────────────────────────────────────────────────────────────────────────

class JobCreatedEvent(BaseModel):
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    source_path: str
    project_name: str
    language: str
    requested_strategies: list[str] = Field(default_factory=list)
    num_functions: int = 3
    sandbox_backend: str = "cape"
    priority: int = 5
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"


class SamplePreparedEvent(BaseModel):
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    source_artifact_id: str
    project_name: str
    language: str
    requested_strategies: list[str] = Field(default_factory=list)
    num_source_files: int
    num_functions_selected: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"


class MutationCompletedEvent(BaseModel):
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    mutation_artifact_id: str
    source_artifact_id: str
    project_name: str
    language: str
    strategy_used: str
    num_functions_mutated: int
    num_functions_failed: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"


class VariantGeneratedEvent(BaseModel):
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    variant_artifact_id: str          # reference to variant source directory
    source_artifact_id: str
    mutation_artifact_id: str
    project_name: str
    language: str
    num_files_generated: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"


class BuildValidatedEvent(BaseModel):
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    compiled_artifact_id: str
    binary_sha256: str
    binary_size_bytes: int
    compilation_time_s: float
    auto_fix_iterations: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"


class BuildFailedEvent(BaseModel):
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    error_message: str
    auto_fix_attempts: int = 0
    is_retryable: bool = False
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"


class SandboxSubmittedEvent(BaseModel):
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    sandbox_task_id: Any
    sandbox_backend: str
    submit_time: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"


class ExecutionCompletedEvent(BaseModel):
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    sandbox_task_id: Any
    sandbox_backend: str
    raw_report_artifact_id: str
    analysis_duration_s: float
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"


class ExecutionFailedEvent(BaseModel):
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    sandbox_task_id: Any
    sandbox_backend: str
    failure_reason: str            # "timeout" | "sandbox_error" | "no_report"
    is_retryable: bool = True
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"


class ReportParsedEvent(BaseModel):
    """Intermediate event when raw JSON report is successfully parsed."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    raw_report_artifact_id: str
    score: float
    detection_count: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"


class BehaviorAnalyzedEvent(BaseModel):
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    analysis_result_id: str
    score: float
    detection_count: int
    ioc_count: int
    ttp_count: int
    analysis_method: str           # "rule_only" | "llm_validated" | "llm_with_fallback"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"


class DecisionIssuedEvent(BaseModel):
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    decision_id: str
    action: str                    # see DecisionAction enum
    source: str                    # "rule_based" | "llm_advisory" | "policy_override"
    confidence: float
    autonomous_dispatched: bool = False
    next_mutation_strategy: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"


class ReportGeneratedEvent(BaseModel):
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    report_id: str
    report_path: str
    summary_path: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"


class JobClosedEvent(BaseModel):
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    final_status: str              # "CLOSED" | "FAILED" | "ESCALATED"
    report_id: Optional[str] = None
    total_duration_s: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"


class JobFailedEvent(BaseModel):
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    failure_stage: str
    error_message: str
    total_retries: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"


class ErrorEvent(BaseModel):
    """Emitted by any agent on error; coordinator reacts according to retry policy."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    error_code: str                # e.g. "SANDBOX_TIMEOUT", "LLM_BAD_OUTPUT"
    error_message: str
    agent: str
    stage: str
    is_retryable: bool
    retry_count: int = 0
    raw_exception: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"


class EscalationEvent(BaseModel):
    """Emitted when a job requires human analyst review."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str
    correlation_id: str
    reason: str
    triggered_by_agent: str
    severity: str = "medium"       # "low" | "medium" | "high" | "critical"
    context_summary: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"


# ──────────────────────────────────────────────────────────────────────────────
# Distributed Multi-Agent Messages
# ──────────────────────────────────────────────────────────────────────────────

class HeartbeatEvent(BaseModel):
    """Periodic liveness signal from each agent."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_name: str
    agent_status: str = "alive"    # "alive" | "busy" | "draining" | "shutting_down"
    current_job_id: Optional[str] = None
    capabilities: Dict[str, Any] = Field(default_factory=dict)
    uptime_s: float = 0.0
    jobs_processed: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"


class NegotiationRequest(BaseModel):
    """Peer-to-peer negotiation request between agents."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    from_agent: str
    to_agent: str              # specific agent name or "*" for broadcast
    request_type: str          # "capability_check" | "resource_available" | "strategy_suggest"
    job_id: str = ""
    payload: Dict[str, Any] = Field(default_factory=dict)
    timeout_s: float = 10.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"


class NegotiationResponse(BaseModel):
    """Response to a peer-to-peer negotiation request."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str            # matches NegotiationRequest.request_id
    from_agent: str
    to_agent: str
    accepted: bool = True
    payload: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"


class AgentRegistrationEvent(BaseModel):
    """Emitted by agents on startup to register with the agent registry."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_name: str
    capabilities: Dict[str, Any] = Field(default_factory=dict)
    activates_on: list[str] = Field(default_factory=list)  # event types
    command_stream: str = ""
    status: str = "online"     # "online" | "offline"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"
