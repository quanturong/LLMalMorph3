"""
Contracts package — Pydantic v2 models for all inter-agent messages, job state,
analysis results, decisions, and reports.

These models are the single source of truth for data shapes across the system.
No business logic lives here — only data contracts.
"""

from .messages import (
    MessageEnvelope,
    JobCreatedEvent,
    SamplePreparedEvent,
    BuildValidatedEvent,
    BuildFailedEvent,
    SandboxSubmittedEvent,
    ExecutionCompletedEvent,
    ExecutionFailedEvent,
    ReportParsedEvent,
    BehaviorAnalyzedEvent,
    DecisionIssuedEvent,
    ReportGeneratedEvent,
    JobClosedEvent,
    JobFailedEvent,
    ErrorEvent,
    EscalationEvent,
    # Commands
    SamplePrepCommand,
    BuildValidateCommand,
    SandboxSubmitCommand,
    ExecMonitorCommand,
    AnalyzeBehaviorCommand,
    DecideCommand,
    ReportCommand,
)
from .job import JobEnvelope, JobState, JobStatus
from .analysis import (
    IOCEntry,
    BehaviorAnalysisResult,
    AnalysisMethod,
    SandboxReportModel,
    ComparisonResultModel,
)
from .decisions import DecisionResult, DecisionAction, DecisionSource, PolicyRule
from .reports import TechnicalReport, ExecutiveSummary, RiskLevel

__all__ = [
    # Messages
    "MessageEnvelope",
    "JobCreatedEvent",
    "SamplePreparedEvent",
    "BuildValidatedEvent",
    "BuildFailedEvent",
    "SandboxSubmittedEvent",
    "ExecutionCompletedEvent",
    "ExecutionFailedEvent",
    "ReportParsedEvent",
    "BehaviorAnalyzedEvent",
    "DecisionIssuedEvent",
    "ReportGeneratedEvent",
    "JobClosedEvent",
    "JobFailedEvent",
    "ErrorEvent",
    "EscalationEvent",
    "SamplePrepCommand",
    "BuildValidateCommand",
    "SandboxSubmitCommand",
    "ExecMonitorCommand",
    "AnalyzeBehaviorCommand",
    "DecideCommand",
    "ReportCommand",
    # Job
    "JobEnvelope",
    "JobState",
    "JobStatus",
    # Analysis
    "IOCEntry",
    "BehaviorAnalysisResult",
    "AnalysisMethod",
    "SandboxReportModel",
    "ComparisonResultModel",
    # Decisions
    "DecisionResult",
    "DecisionAction",
    "DecisionSource",
    "PolicyRule",
    # Reports
    "TechnicalReport",
    "ExecutiveSummary",
    "RiskLevel",
]
