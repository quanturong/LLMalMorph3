"""
Decision policy engine — hard rules evaluated BEFORE and AFTER LLM advice.

The PolicyEngine is the last guardrail between an LLM recommendation and
an actual workflow action. It can override any LLM suggestion.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import List, Optional

from contracts.decisions import (
    DecisionAction,
    DecisionLLMOutput,
    DecisionResult,
    DecisionSource,
    PolicyConfig,
    PolicyRule,
)
from contracts.job import JobState, JobStatus

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Default policy
# ──────────────────────────────────────────────────────────────────────────────

def load_default_policy() -> PolicyConfig:
    disable_close = os.getenv("DECISION_DISABLE_CLOSE_NO_BEHAVIOR", "0").strip().lower() in {
        "1", "true", "yes", "on"
    }
    disable_high_score_escalation = (
        os.getenv("DECISION_DISABLE_HIGH_SCORE_ESCALATION", "0").strip().lower()
        in {"1", "true", "yes", "on"}
    )
    escalation_score_threshold = float(
        os.getenv("DECISION_ESCALATION_SCORE_THRESHOLD", "8.0")
    )
    hard_rules: List[PolicyRule] = [
        PolicyRule(
            rule_id="hard_001",
            name="sandbox_retry_cap",
            description="Never retry sandbox if sandbox_retry_count >= max",
            condition="sandbox_retry_count >= max_sandbox_retries",
            forced_action=DecisionAction.ESCALATE_TO_ANALYST,
            priority=1,
        ),
        PolicyRule(
            rule_id="hard_002",
            name="total_retry_cap",
            description="Never retry if total job retries >= max",
            condition="retry_count >= max_total_job_retries",
            forced_action=DecisionAction.CLOSE_FAILED,
            priority=2,
        ),
        PolicyRule(
            rule_id="hard_003",
            name="no_behavior_close",
            description="Close job if threat score below minimum",
            condition="threat_score < min_score_for_analysis",
            forced_action=DecisionAction.CLOSE_NO_BEHAVIOR,
            priority=10,
        ),
        PolicyRule(
            rule_id="hard_004",
            name="high_score_escalation",
            description="Escalate to analyst for very high threat score",
            condition="threat_score >= escalation_score_threshold",
            forced_action=DecisionAction.ESCALATE_TO_ANALYST,
            priority=20,
        ),
    ]

    if disable_close:
        hard_rules = [rule for rule in hard_rules if rule.rule_id != "hard_003"]
    if disable_high_score_escalation:
        hard_rules = [rule for rule in hard_rules if rule.rule_id != "hard_004"]

    return PolicyConfig(
        max_sandbox_retries=3,
        max_build_retries=5,
        max_total_job_retries=10,
        min_score_for_analysis=0.1,
        escalation_score_threshold=escalation_score_threshold,
        allowed_actions={
            JobStatus.DECISION_ISSUED.value: list(DecisionAction),
        },
        hard_rules=hard_rules,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Policy Engine
# ──────────────────────────────────────────────────────────────────────────────

class PolicyEngine:
    """
    Evaluates hard rules against job context BEFORE accepting LLM recommendations.
    Also performs post-LLM validation to catch policy violations in LLM output.
    """

    def __init__(self, config: Optional[PolicyConfig] = None) -> None:
        self.config = config or load_default_policy()

    def evaluate_pre_llm(
        self,
        job_state: JobState,
        threat_score: float,
    ) -> Optional[DecisionResult]:
        """
        Evaluate hard rules BEFORE calling LLM.
        If any hard rule fires, return the forced decision immediately
        (LLM will NOT be called).
        Returns None if LLM should be consulted.
        """
        rules = sorted(self.config.hard_rules, key=lambda r: r.priority)

        for rule in rules:
            forced = self._evaluate_rule(rule, job_state, threat_score)
            if forced is not None:
                logger.info(
                    "Hard rule '%s' fired for job %s → %s",
                    rule.name, job_state.job_id, forced.value,
                )
                return DecisionResult(
                    job_id=job_state.job_id,
                    sample_id=job_state.sample_id,
                    action=forced,
                    rationale=f"Policy rule '{rule.name}': {rule.description}",
                    confidence=1.0,
                    source=DecisionSource.POLICY_OVERRIDE,
                    policy_applied=rule.rule_id,
                )
        return None

    def apply_post_llm(
        self,
        llm_output: DecisionLLMOutput,
        job_state: JobState,
        threat_score: float,
    ) -> DecisionResult:
        """
        Validate LLM recommendation against policy.
        Override if necessary; otherwise accept with LLM_ADVISORY source.
        """
        # Check hard rules again (LLM may have been called concurrently)
        override = self.evaluate_pre_llm(job_state, threat_score)
        if override is not None:
            override.llm_raw_output = llm_output.model_dump()
            return override

        # Check allowed actions for current state
        # Convert LLM string literal to DecisionAction enum
        try:
            recommended = DecisionAction(llm_output.recommended_action)
        except ValueError:
            logger.warning(
                "LLM recommended unknown action '%s'. Falling back to ESCALATE_TO_ANALYST.",
                llm_output.recommended_action,
            )
            return DecisionResult(
                job_id=job_state.job_id,
                sample_id=job_state.sample_id,
                action=DecisionAction.ESCALATE_TO_ANALYST,
                rationale=f"LLM recommended unknown action '{llm_output.recommended_action}'.",
                confidence=1.0,
                source=DecisionSource.POLICY_OVERRIDE,
                llm_raw_output=llm_output.model_dump(),
            )

        # Check allowed actions for current state
        allowed = self.config.get_allowed_actions(job_state.current_status.value)
        if recommended not in allowed:
            logger.warning(
                "LLM recommended %s which is not in allowed actions for state %s. "
                "Falling back to ESCALATE_TO_ANALYST.",
                recommended.value,
                job_state.current_status.value,
            )
            return DecisionResult(
                job_id=job_state.job_id,
                sample_id=job_state.sample_id,
                action=DecisionAction.ESCALATE_TO_ANALYST,
                rationale=(
                    f"LLM recommended '{recommended.value}' "
                    f"which is not allowed in state '{job_state.current_status.value}'."
                ),
                confidence=1.0,
                source=DecisionSource.POLICY_OVERRIDE,
                llm_raw_output=llm_output.model_dump(),
            )

        # Accept LLM recommendation
        return DecisionResult(
            job_id=job_state.job_id,
            sample_id=job_state.sample_id,
            action=recommended,
            rationale=llm_output.rationale,
            confidence=llm_output.confidence,
            source=DecisionSource.LLM_ADVISORY,
            llm_raw_output=llm_output.model_dump(),
        )

    def _evaluate_rule(
        self,
        rule: PolicyRule,
        job_state: JobState,
        threat_score: float,
    ) -> Optional[DecisionAction]:
        """Evaluate a single policy rule. Returns forced action or None."""
        cfg = self.config

        if rule.rule_id == "hard_001":
            if job_state.sandbox_retry_count >= cfg.max_sandbox_retries:
                return rule.forced_action

        elif rule.rule_id == "hard_002":
            if job_state.retry_count >= cfg.max_total_job_retries:
                return rule.forced_action

        elif rule.rule_id == "hard_003":
            if threat_score < cfg.min_score_for_analysis:
                return rule.forced_action

        elif rule.rule_id == "hard_004":
            if threat_score >= cfg.escalation_score_threshold:
                return rule.forced_action

        return None
