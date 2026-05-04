"""
DecisionAgent — applies hard policy rules + optional LLM advisory.

Decision flow:
  1. PolicyEngine.evaluate_pre_llm()  → if hard rule fires, use it (no LLM)
  2. If no hard rule: call LLM with DecisionLLMOutput schema
  3. PolicyEngine.apply_post_llm()    → validate + possibly override LLM result
  4. _apply_local_mutation_policy()   → may promote to retry_with_mutation (research loop)
  5. Emit DecisionIssuedEvent with final action

LLM advisory allowed actions (whitelist — LLM never picks retry_with_mutation):
  - continue_to_report
  - retry_sandbox
  - escalate_to_analyst
  - close_no_behavior
  - close_failed

Policy layer may emit retry_with_mutation after step 4 regardless of LLM output.

Input command:  DecideCommand
Output event:   DecisionIssuedEvent
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

import structlog

from broker.topics import Topic
from contracts.decisions import (
    DecisionAction,
    DecisionLLMOutput,
    DecisionResult,
    DecisionSource,
)
from contracts.messages import DecisionIssuedEvent
from llm.provider import LLMRequest
from workflows.policy import PolicyEngine
from contracts.job import JobState, JobStatus

from .base_agent import BaseAgent

logger = structlog.get_logger(__name__)

_DECISION_PROMPT_PATH = (
    Path(__file__).resolve().parent.parent / "llm" / "prompts" / "decision_advisory.txt"
)

# Event signature: BehaviorAnalyzedEvent
_SIG_BEHAVIOR_ANALYZED = frozenset({"analysis_result_id", "ioc_count", "ttp_count", "analysis_method"})


class DecisionAgent(BaseAgent):
    """
    Apply policy engine + LLM advisory to decide next workflow action.

    Self-activates on: BehaviorAnalyzedEvent (BEHAVIOR_ANALYZED → DECIDING)
    Dispatches decisions directly — downstream agents self-activate on DecisionIssuedEvent.
    """

    agent_name = "DecisionAgent"
    command_stream = Topic.CMD_DECIDE
    consumer_group = Topic.CG_DECIDE
    event_consumer_group = Topic.CG_EVENTS_DECIDE

    activates_on = {
        _SIG_BEHAVIOR_ANALYZED: (JobStatus.BEHAVIOR_ANALYZED, JobStatus.DECIDING),
    }

    capabilities = {"stage": "decision", "uses_llm": True, "policy_engine": True}

    def __init__(
        self,
        ctx,
        policy_engine: Optional[PolicyEngine] = None,
        enable_autonomous_requests: Optional[bool] = None,
        mutation_score_threshold: Optional[float] = None,
        mutation_max_iocs: Optional[int] = None,
    ) -> None:
        super().__init__(ctx)
        self._policy = policy_engine or PolicyEngine()
        env_enable_autonomy = (
            os.getenv("DECISION_ENABLE_AUTONOMY", "1").strip().lower()
            in {"1", "true", "yes", "on"}
        )
        self._enable_autonomous_requests = (
            enable_autonomous_requests
            if enable_autonomous_requests is not None
            else env_enable_autonomy
        )
        self._mutation_score_threshold = (
            mutation_score_threshold
            if mutation_score_threshold is not None
            else float(os.getenv("DECISION_MUTATION_SCORE_THRESHOLD", "5.5"))
        )
        self._mutation_max_iocs = (
            mutation_max_iocs
            if mutation_max_iocs is not None
            else int(os.getenv("DECISION_MUTATION_MAX_IOCS", "3"))
        )
        self._disable_close_no_behavior = (
            os.getenv("DECISION_DISABLE_CLOSE_NO_BEHAVIOR", "0").strip().lower()
            in {"1", "true", "yes", "on"}
        )
        self._pending_decision_events: dict = {}

    async def handle_event(self, data: dict, claimed_state) -> None:
        """Extract command data from event + state."""
        cmd_data = {
            "job_id": data["job_id"],
            "sample_id": data.get("sample_id", ""),
            "correlation_id": data.get("correlation_id", ""),
            "analysis_result_id": data.get("analysis_result_id", ""),
            "job_retry_count": claimed_state.retry_count if claimed_state else 0,
        }
        await self.handle(cmd_data)
        # Transition to DECISION_ISSUED
        if self._ctx.state_store:
            state = await self._ctx.state_store.get(data["job_id"])
            if state and state.current_status == JobStatus.DECIDING:
                await self.transition_and_save(state, JobStatus.DECISION_ISSUED,
                                               reason="decision issued")
                pending = self._pending_decision_events.pop(data["job_id"], None)
                if pending:
                    await self._ctx.broker.publish(Topic.EVENTS_ALL, pending)

    async def handle(self, data: dict) -> None:
        job_id = data["job_id"]
        sample_id = data["sample_id"]
        analysis_result_id = data["analysis_result_id"]
        job_retry_count = data.get("job_retry_count", 0)

        log = logger.bind(job_id=job_id)

        analysis_result: Optional[dict] = None
        if self._ctx.artifact_store:
            analysis_result = await self._ctx.artifact_store.get_json(
                job_id, analysis_result_id
            )

        threat_score = float((analysis_result or {}).get("threat_score", 0.0))
        ioc_count = len((analysis_result or {}).get("iocs", []))

        # Build a minimal JobState for policy evaluation
        job_state = JobState(job_id=job_id, sample_id=sample_id,
                             correlation_id=data.get("correlation_id", ""))
        job_state.retry_count = job_retry_count
        job_state.transition_to(JobStatus.DECIDING, "DecisionAgent")

        # Also load full state if available (has sandbox_retry_count etc.)
        if self._ctx.state_store:
            stored_state = await self._ctx.state_store.get(job_id)
            if stored_state:
                job_state = stored_state
                # Ensure we're in DECIDING state for policy evaluation
                if job_state.current_status != JobStatus.DECIDING:
                    job_state.current_status = JobStatus.DECIDING

        hard_decision = self._policy.evaluate_pre_llm(job_state, threat_score)
        if hard_decision:
            log.info("decision_by_hard_policy",
                     action=hard_decision.action.value,
                     rule=hard_decision.policy_applied)
            await self._persist_and_emit(
                job_id, data, hard_decision, llm_used=False
            )
            return

        llm_recommendation: Optional[DecisionLLMOutput] = None
        if self._ctx.llm_provider:
            llm_recommendation = await self._ask_llm(
                job_id, threat_score, analysis_result or {}, log
            )

        if llm_recommendation:
            final_decision = self._policy.apply_post_llm(
                llm_recommendation, job_state, threat_score
            )
        else:
            ioc_count = len((analysis_result or {}).get("iocs", []))
            if threat_score == 0 and not ioc_count:
                final_action = DecisionAction.CLOSE_NO_BEHAVIOR
                rationale = "No behavioral indicators detected (rule fallback)"
            else:
                final_action = DecisionAction.CONTINUE_TO_REPORT
                rationale = "Proceeding to report (LLM unavailable, rule fallback)"
            final_decision = DecisionResult(
                job_id=job_id,
                sample_id=sample_id,
                action=final_action,
                rationale=rationale,
                source=DecisionSource.POLICY_OVERRIDE,
                confidence=0.6,
                policy_applied="fallback_no_llm",
            )

        original_decision = final_decision
        final_decision = self._apply_local_mutation_policy(
            final_decision=final_decision,
            job_state=job_state,
            threat_score=threat_score,
            ioc_count=ioc_count,
        )

        # Apply disable_close_no_behavior policy override only if not triggering mutation
        if (self._disable_close_no_behavior and 
            original_decision.action == DecisionAction.CLOSE_NO_BEHAVIOR and
            final_decision.action != DecisionAction.RETRY_WITH_MUTATION):
            final_decision = DecisionResult(
                job_id=final_decision.job_id,
                sample_id=final_decision.sample_id,
                action=DecisionAction.CONTINUE_TO_REPORT,
                rationale=(
                    "close_no_behavior disabled via DECISION_DISABLE_CLOSE_NO_BEHAVIOR; "
                    "forcing continue_to_report"
                ),
                confidence=max(0.7, float(getattr(final_decision, "confidence", 0.0)) or 0.7),
                source=DecisionSource.POLICY_OVERRIDE,
                policy_applied="disable_close_no_behavior",
                llm_raw_output=getattr(final_decision, "llm_raw_output", None),
            )

        autonomous_mutation_queued = False
        next_mutation_strategy = ""
        feedback_ctx = None
        if final_decision.action == DecisionAction.RETRY_WITH_MUTATION:
            next_mutation_strategy = self._pick_next_mutation_strategy(job_state)
            # Build feedback context first so it can be forwarded to MutationAgent via DecisionIssuedEvent
            feedback_ctx = self._build_feedback_context(
                analysis_result=analysis_result,
                job_state=job_state,
            )
            autonomous_mutation_queued = await self._try_autonomous_mutation_dispatch(
                cmd_data=data,
                job_state=job_state,
                mutation_strategy=next_mutation_strategy,
                feedback_context=feedback_ctx,
            )

        log.info("decision_final",
                 action=final_decision.action.value,
                 source=final_decision.source.value,
                 llm_used=llm_recommendation is not None)

        await self._persist_and_emit(
            job_id, data, final_decision,
            llm_used=llm_recommendation is not None,
            autonomous_mutation_queued=autonomous_mutation_queued,
            next_mutation_strategy=next_mutation_strategy,
            feedback_context=feedback_ctx,
        )

    # ──────────────────────────────────────────────────────────────────────
    # LLM call
    # ──────────────────────────────────────────────────────────────────────

    async def _ask_llm(
        self, job_id: str, threat_score: float, analysis_result: dict, log
    ) -> Optional[DecisionLLMOutput]:
        try:
            prompt_template = _load_prompt(_DECISION_PROMPT_PATH)
            context_json = json.dumps({
                "job_id": job_id,
                "threat_score": threat_score,
                "analysis_summary": _summarize_analysis(analysis_result),
            }, indent=2)
            prompt = prompt_template.replace("{{decision_context_json}}", context_json)

            request = LLMRequest(
                system_prompt=(
                    "You are a security orchestration agent. "
                    "Given analysis context, recommend ONE action from: "
                    "continue_to_report, retry_sandbox, escalate_to_analyst, "
                    "close_no_behavior, close_failed. "
                    "Respond ONLY as valid JSON."
                ),
                user_prompt=prompt,
                response_format="json",
                max_tokens=512,
                temperature=0.0,
            )
            return await self._ctx.llm_provider.generate_structured(
                request, DecisionLLMOutput
            )
        except Exception as exc:
            log.warning("decision_llm_failed", error=str(exc))
            return None

    # ──────────────────────────────────────────────────────────────────────
    # Persist + emit
    # ──────────────────────────────────────────────────────────────────────

    async def _persist_and_emit(
        self,
        job_id: str,
        cmd_data: dict,
        decision: DecisionResult,
        llm_used: bool,
        autonomous_mutation_queued: bool = False,
        next_mutation_strategy: str = "",
        feedback_context: dict | None = None,
    ) -> None:
        decision_dict = decision.model_dump(mode="json")
        decision_dict["created_at"] = datetime.now(tz=timezone.utc).isoformat()

        if self._ctx.artifact_store:
            decision_id = await self._ctx.artifact_store.store_json(
                job_id=job_id,
                artifact_type="decision_result",
                data=decision_dict,
            )
        else:
            decision_id = f"decision_{job_id[:8]}"

        event = DecisionIssuedEvent(
            job_id=job_id,
            sample_id=cmd_data["sample_id"],
            correlation_id=cmd_data["correlation_id"],
            decision_id=decision_id,
            action=decision.action.value,
            source=decision.source.value if hasattr(decision.source, "value") else str(decision.source),
            confidence=float(decision.confidence),
            autonomous_mutation_queued=autonomous_mutation_queued,
            next_mutation_strategy=next_mutation_strategy,
            feedback_context=feedback_context,
        )
        self._pending_decision_events[job_id] = event
        # event will be published by handle_event() after transition_and_save(DECISION_ISSUED)

    def _apply_local_mutation_policy(
        self,
        final_decision: DecisionResult,
        job_state: JobState,
        threat_score: float,
        ioc_count: int,
    ) -> DecisionResult:
        if final_decision.action in {
            DecisionAction.CLOSE_NO_BEHAVIOR,
            DecisionAction.CLOSE_FAILED,
            DecisionAction.ESCALATE_TO_ANALYST,
        }:
            # Check if we should trigger mutation even for low-activity samples
            if (threat_score >= self._mutation_score_threshold and 
                ioc_count <= self._mutation_max_iocs and
                job_state.feedback_loop_count < job_state.max_feedback_loops):
                return DecisionResult(
                    job_id=final_decision.job_id,
                    sample_id=final_decision.sample_id,
                    action=DecisionAction.RETRY_WITH_MUTATION,
                    rationale=(
                        "Local policy: trigger mutation-feedback loop for richer behavior "
                        f"coverage (score={threat_score:.2f}, ioc_count={ioc_count})."
                    ),
                    confidence=max(0.8, float(final_decision.confidence)),
                    source=DecisionSource.POLICY_OVERRIDE,
                    policy_applied="decision_local_policy_mutation_feedback",
                    llm_raw_output=final_decision.llm_raw_output,
                )
            return final_decision

        # Don't mutate if conditions not met
        if threat_score < self._mutation_score_threshold:
            return final_decision
        if ioc_count > self._mutation_max_iocs:
            return final_decision
        if job_state.feedback_loop_count >= job_state.max_feedback_loops:
            return final_decision

        return DecisionResult(
            job_id=final_decision.job_id,
            sample_id=final_decision.sample_id,
            action=DecisionAction.RETRY_WITH_MUTATION,
            rationale=(
                "Local policy: trigger mutation-feedback loop for richer behavior "
                f"coverage (score={threat_score:.2f}, ioc_count={ioc_count})."
            ),
            confidence=max(0.8, float(final_decision.confidence)),
            source=DecisionSource.POLICY_OVERRIDE,
            policy_applied="decision_local_policy_mutation_feedback",
            llm_raw_output=final_decision.llm_raw_output,
        )

    def _pick_next_mutation_strategy(self, job_state: JobState) -> str:
        strategies = job_state.requested_strategies or ["variant_source_generator"]
        idx = job_state.mutation_cycle_count % len(strategies)
        return str(strategies[idx]).strip() or "variant_source_generator"

    async def _try_autonomous_mutation_dispatch(
        self,
        cmd_data: dict,
        job_state: JobState,
        mutation_strategy: str,
        feedback_context: dict | None = None,
    ) -> bool:
        """Signal that autonomous mutation should proceed.

        The actual mutation is driven by MutationAgent self-activating on the
        DecisionIssuedEvent (action=retry_with_mutation).  This method only
        performs pre-mutation bookkeeping (recording the original analysis
        reference) and returns True so the event's autonomous_mutation_queued flag
        is set correctly.  No command is published here — the event itself is
        the trigger.
        """
        if not self._enable_autonomous_requests:
            return False
        if not job_state.source_artifact_id or not job_state.project_name or not job_state.language:
            return False

        log = logger.bind(job_id=cmd_data["job_id"])

        # Store original analysis reference before mutation (for comparison)
        if not job_state.is_mutated_sample and job_state.analysis_result_id:
            job_state.is_mutated_sample = True
            job_state.original_job_id = job_state.job_id
            job_state.original_analysis_result_id = job_state.analysis_result_id

            if self._ctx.state_store:
                await self._ctx.state_store.save(job_state)
                log.info("stored_original_reference",
                         original_analysis_id=job_state.original_analysis_result_id)

        # MutationAgent will self-activate on the DecisionIssuedEvent
        # (action=retry_with_mutation) — no explicit command dispatch needed.
        log.info("autonomous_mutation_queued",
                 strategy=mutation_strategy,
                 cycle=job_state.mutation_cycle_count)
        return True

    def _build_feedback_context(
        self,
        analysis_result: dict | None,
        job_state: JobState,
    ) -> dict:
        """Build feedback context from analysis/VT data to guide next mutation.

        The returned dict tells MutationAgent which AV engines detected the
        variant and what detection names they used, so the LLM can focus on
        evading those specific signatures.
        """
        ctx: dict = {
            "cycle": job_state.mutation_cycle_count,
            "previous_strategies": job_state.requested_strategies[:job_state.mutation_cycle_count + 1],
        }

        # VT detection delta from JobState
        if job_state.vt_variant_malicious is not None:
            ctx["vt_variant_detections"] = job_state.vt_variant_malicious
            ctx["vt_original_detections"] = job_state.vt_original_malicious
            ctx["vt_delta"] = job_state.vt_detection_delta

        # Extract detection details from analysis result
        if analysis_result:
            iocs = analysis_result.get("iocs", [])
            if iocs:
                ctx["detected_iocs"] = [
                    {"type": ioc.get("type", ""), "value": str(ioc.get("value", ""))[:100]}
                    for ioc in iocs[:20]
                ]
            # Behavior categories indicate what triggered detection
            categories = analysis_result.get("behavior_categories", [])
            if categories:
                ctx["behavior_categories"] = categories
            threat_score = analysis_result.get("threat_score", 0)
            if threat_score:
                ctx["threat_score"] = threat_score

            # Suggest focus areas based on detected behaviors
            suggestions = []
            cat_set = {c.lower() for c in categories} if categories else set()
            if cat_set & {"stealer", "exfiltration", "network"}:
                suggestions.append("Focus on obfuscating network-related strings and API calls")
            if cat_set & {"persistence", "registry"}:
                suggestions.append("Focus on obfuscating registry key paths and persistence mechanisms")
            if cat_set & {"injection", "process_manipulation"}:
                suggestions.append("Focus on obfuscating process injection API calls")
            if cat_set & {"file_operations", "dropper"}:
                suggestions.append("Focus on obfuscating file paths and file operation strings")
            if suggestions:
                ctx["mutation_suggestions"] = suggestions

        return ctx


def _summarize_analysis(analysis: dict) -> dict:
    """Produce a compact summary for LLM context."""
    return {
        "threat_score": analysis.get("threat_score", 0),
        "ioc_count": len(analysis.get("iocs", [])),
        "behavior_categories": analysis.get("behavior_categories", []),
        "summary": analysis.get("summary", "")[:400],
    }


def _load_prompt(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return (
        "Based on the following analysis context, recommend the next action:\n"
        "{{decision_context_json}}\n"
        'Respond JSON: {"action": "<action>", "reason": "<reason>", "confidence": 0.9}'
    )
