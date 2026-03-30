"""
Agents package — distributed multi-agent pipeline.

All agents are self-activating via event-driven activation (activates_on).
MonitorAgent replaces CoordinatorAgent for health monitoring only.
CoordinatorAgent is retained for backward compatibility.
"""

from .base_agent import BaseAgent, AgentContext
from .coordinator_agent import CoordinatorAgent
from .monitor_agent import MonitorAgent
from .sample_prep_agent import SamplePrepAgent
from .mutation_agent import MutationAgent
from .variant_generation_agent import VariantGenerationAgent
from .build_validation_agent import BuildValidationAgent
from .sandbox_submit_agent import SandboxSubmitAgent
from .exec_monitor_agent import ExecMonitorAgent
from .behavior_analysis_agent import BehaviorAnalysisAgent
from .decision_agent import DecisionAgent
from .reporting_agent import ReportingAgent

__all__ = [
    "BaseAgent",
    "AgentContext",
    "CoordinatorAgent",
    "MonitorAgent",
    "SamplePrepAgent",
    "MutationAgent",
    "VariantGenerationAgent",
    "BuildValidationAgent",
    "SandboxSubmitAgent",
    "ExecMonitorAgent",
    "BehaviorAnalysisAgent",
    "DecisionAgent",
    "ReportingAgent",
]
