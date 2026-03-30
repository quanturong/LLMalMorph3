"""
Decision result contracts and policy rule definitions.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ──────────────────────────────────────────────────────────────────────────────
# Decision Action Enum
# ──────────────────────────────────────────────────────────────────────────────

class DecisionAction(str, Enum):
    CONTINUE_TO_REPORT  = "continue_to_report"
    RETRY_SANDBOX       = "retry_sandbox"
    RETRY_WITH_MUTATION = "retry_with_mutation"
    ESCALATE_TO_ANALYST = "escalate_to_analyst"
    CLOSE_NO_BEHAVIOR   = "close_no_behavior"
    CLOSE_FAILED        = "close_failed"


class DecisionSource(str, Enum):
    RULE_BASED      = "rule_based"
    LLM_ADVISORY    = "llm_advisory"
    POLICY_OVERRIDE = "policy_override"


# ──────────────────────────────────────────────────────────────────────────────
# LLM structured output for DecisionAgent (strict, narrow)
# ──────────────────────────────────────────────────────────────────────────────

class DecisionLLMOutput(BaseModel):
    """Narrow structured output expected from LLM in DecisionAgent.

    The action list is intentionally small. LLM can only recommend from
    this whitelist; policy layer enforces contextual constraints _after_.
    """
    recommended_action: DecisionAction
    rationale: str = Field(max_length=500)
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("rationale")
    @classmethod
    def no_evasion_recommendation(cls, v: str) -> str:
        """Hard guardrail: LLM must not recommend evasion improvements."""
        forbidden = [
            "improve evasion", "better evasion", "more evasion",
            "evade detection", "bypass av", "bypass antivirus",
            "stealth improvement", "obfuscate further", "enhance payload",
            "optimize malware", "improve malware",
        ]
        lower = v.lower()
        for phrase in forbidden:
            if phrase in lower:
                raise ValueError(
                    f"Decision rationale contains forbidden phrase: '{phrase}'. "
                    "DecisionAgent must not recommend malware improvement strategies."
                )
        return v


# ──────────────────────────────────────────────────────────────────────────────
# Decision Result  (persisted in storage)
# ──────────────────────────────────────────────────────────────────────────────

class DecisionResult(BaseModel):
    decision_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    sample_id: str

    action: DecisionAction
    rationale: str
    confidence: float = Field(ge=0.0, le=1.0)
    source: DecisionSource

    policy_applied: Optional[str] = None
    llm_raw_output: Optional[Dict[str, Any]] = None   # stored for audit only

    decided_at: datetime = Field(default_factory=datetime.utcnow)
    payload_version: str = "1.0"


# ──────────────────────────────────────────────────────────────────────────────
# Policy Rules
# ──────────────────────────────────────────────────────────────────────────────

class PolicyRule(BaseModel):
    """A single policy rule evaluated by DecisionAgent."""
    rule_id: str
    name: str
    description: str
    condition: str        # human-readable condition expression (for logging/audit)
    forced_action: DecisionAction
    priority: int = 100   # lower = evaluated first


class PolicyConfig(BaseModel):
    """Full policy configuration loaded at startup."""
    max_sandbox_retries: int = 3
    max_build_retries: int = 5
    max_total_job_retries: int = 10

    # Score thresholds
    min_score_for_analysis: float = 0.1     # below this → CLOSE_NO_BEHAVIOR
    escalation_score_threshold: float = 8.0  # above this → ESCALATE_TO_ANALYST

    # Allowed actions per workflow status
    allowed_actions: Dict[str, List[DecisionAction]] = Field(default_factory=dict)

    # Hard rules (evaluated before LLM, override everything)
    hard_rules: List[PolicyRule] = Field(default_factory=list)

    def get_allowed_actions(self, workflow_status: str) -> List[DecisionAction]:
        return self.allowed_actions.get(workflow_status, list(DecisionAction))
