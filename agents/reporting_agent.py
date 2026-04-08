"""
ReportingAgent — generates TechnicalReport + ExecutiveSummary.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import structlog

from broker.topics import Topic
from contracts.analysis import BehaviorAnalysisResult, ComparisonResultModel
from contracts.decisions import DecisionResult
from contracts.job import JobStatus
from contracts.messages import ReportGeneratedEvent
from contracts.reports import ExecutiveSummary, RiskLevel, TechnicalReport
from llm.provider import LLMRequest

from .base_agent import BaseAgent

logger = structlog.get_logger(__name__)

_EXEC_SUMMARY_PROMPT_PATH = (
    Path(__file__).resolve().parent.parent / "llm" / "prompts" / "executive_summary.txt"
)

# Event signature: DecisionIssuedEvent with action=continue_to_report
_SIG_DECISION_REPORT = frozenset({"decision_id", "action", "confidence", "source"})


class ReportingAgent(BaseAgent):
    """
    Generate TechnicalReport + ExecutiveSummary.

    Self-activates on: DecisionIssuedEvent with action=continue_to_report
                       (DECISION_ISSUED → REPORTING)
    """

    agent_name = "ReportingAgent"
    command_stream = Topic.CMD_REPORT
    consumer_group = Topic.CG_REPORT
    event_consumer_group = Topic.CG_EVENTS_REPORT

    activates_on = {
        _SIG_DECISION_REPORT: (JobStatus.DECISION_ISSUED, JobStatus.REPORTING),
    }

    capabilities = {"stage": "reporting", "uses_llm": True}

    def __init__(self, ctx):
        super().__init__(ctx)
        self._pending_report_events: dict = {}

    async def handle_event(self, data: dict, claimed_state) -> None:
        """Handle decision events — generate report for continue_to_report, close otherwise."""
        action = data.get("action", "")
        job_id = data.get("job_id", "")
        log = logger.bind(job_id=job_id, action=action)

        if action != "continue_to_report":
            # State was already claimed DECISION_ISSUED → REPORTING by activates_on CAS.
            # We must close the job here — no other agent can claim REPORTING state.
            # (Mutation dispatch for retry_with_mutation was already done by DecisionAgent.)
            log.info("non_report_action_closing_job",
                     reason="state_claimed_reporting_must_close")
            if self._ctx.state_store:
                state = await self._ctx.state_store.get(job_id)
                if state and state.current_status == JobStatus.REPORTING:
                    await self.transition_and_save(state, JobStatus.REPORT_READY,
                                                   reason=f"action={action}, skipping report generation")
                    await self.transition_and_save(state, JobStatus.CLOSED,
                                                   reason=f"job closed via action={action}")
                    from contracts.messages import JobClosedEvent
                    closed_event = JobClosedEvent(
                        job_id=state.job_id,
                        sample_id=state.sample_id,
                        correlation_id=state.correlation_id,
                        final_status="CLOSED",
                        report_id=state.report_id,
                    )
                    await self.publish_event(closed_event)
                    log.info("job_closed_non_report_action")
            return

        cmd_data = {
            "job_id": data["job_id"],
            "sample_id": data.get("sample_id", ""),
            "correlation_id": data.get("correlation_id", ""),
            "analysis_result_id": claimed_state.analysis_result_id if claimed_state else "",
            "decision_id": data.get("decision_id", ""),
            "output_dir": f"{self._ctx.work_dir}/run_{data['job_id'][:8]}",
        }
        await self.handle(cmd_data)
        log.info("after_handle_completed", step="checkpoint_1")
        # Transition to REPORT_READY then CLOSED
        if self._ctx.state_store:
            log.info("state_store_available", step="checkpoint_2")
            state = await self._ctx.state_store.get(data["job_id"])
            log.info("state_fetched", current_status=(state.current_status.value if state else None), step="checkpoint_3")
            if state and state.current_status == JobStatus.REPORTING:
                log.info("transition_condition_true", step="checkpoint_4")
                await self.transition_and_save(state, JobStatus.REPORT_READY,
                                               reason="report generated")
                log.info("transitioned_to_report_ready", step="checkpoint_5")
                await self.transition_and_save(state, JobStatus.CLOSED,
                                               reason="job completed")
                log.info("transitioned_to_closed", step="checkpoint_6")
                # Publish deferred ReportGeneratedEvent after transitions
                pending = self._pending_report_events.pop(data["job_id"], None)
                if pending:
                    log.info("publishing_deferred_report_event", step="checkpoint_7")
                    await self._ctx.broker.publish(Topic.EVENTS_ALL, pending)
                    log.info("deferred_report_event_published", step="checkpoint_8")
                # Emit JobClosedEvent
                from contracts.messages import JobClosedEvent
                closed_event = JobClosedEvent(
                    job_id=state.job_id,
                    sample_id=state.sample_id,
                    correlation_id=state.correlation_id,
                    final_status="CLOSED",
                    report_id=state.report_id,
                )
                await self.publish_event(closed_event)
            else:
                log.warning("transition_condition_false", current_status=(state.current_status.value if state else "state_is_none"), step="checkpoint_cond_false")

    async def handle(self, data: dict) -> None:
        job_id = data["job_id"]
        sample_id = data["sample_id"]
        correlation_id = data["correlation_id"]
        analysis_result_id = data["analysis_result_id"]
        decision_id = data["decision_id"]
        output_dir = data.get("output_dir", f"{self._ctx.work_dir}/run_{job_id[:8]}")

        log = logger.bind(job_id=job_id)

        analysis_dict = {}
        decision_dict = {}
        if self._ctx.artifact_store:
            analysis_dict = await self._ctx.artifact_store.get_json(job_id, analysis_result_id) or {}
            decision_dict = await self._ctx.artifact_store.get_json(job_id, decision_id) or {}

        analysis_model = _build_analysis_model(job_id, sample_id, analysis_dict)
        decision_model = _build_decision_model(decision_dict)

        # Check if this is a mutated sample and load comparison data
        comparison_model = None
        is_mutated_sample = False
        
        if self._ctx.state_store:
            current_state = await self._ctx.state_store.get(job_id)
            if current_state and current_state.is_mutated_sample and current_state.original_analysis_result_id:
                log.info("processing_mutated_sample", 
                        original_job_id=current_state.original_job_id)
                is_mutated_sample = True
                
                # Get original analysis result
                original_analysis_dict = {}
                if self._ctx.artifact_store and current_state.original_job_id:
                    original_analysis_dict = await self._ctx.artifact_store.get_json(
                        current_state.original_job_id, current_state.original_analysis_result_id
                    ) or {}
                
                # Perform comparison if we have both original and mutated results
                if original_analysis_dict and analysis_dict:
                    comparison_model = await self._perform_comparison(
                        original_analysis_dict, analysis_dict, log
                    )
                    
                    # Store comparison result
                    if self._ctx.artifact_store and comparison_model:
                        comparison_id = await self._ctx.artifact_store.store_json(
                            job_id=job_id,
                            artifact_type="comparison_result",
                            data=comparison_model.model_dump(mode="json"),
                        )
                        current_state.comparison_result_id = comparison_id
                        await self._ctx.state_store.put(current_state)
                        log.info("comparison_stored", comparison_id=comparison_id)

        tech_report = TechnicalReport.from_analysis(
            analysis=analysis_model,
            job_id=job_id,
            sample_id=sample_id,
            correlation_id=correlation_id,
            project_name="unknown",
            language="c",
            decision=decision_model,
            comparison=comparison_model,
        )
        tech_report.is_mutated_sample = is_mutated_sample

        exec_summary = None
        if self._ctx.llm_provider:
            exec_summary = await self._generate_exec_summary(tech_report)
        if exec_summary is None:
            exec_summary = _fallback_exec_summary(tech_report)

        report_id = tech_report.report_id
        if self._ctx.report_store:
            report_path, summary_path = await asyncio.get_event_loop().run_in_executor(
                None, lambda: self._ctx.report_store.save(tech_report, exec_summary)
            )
        else:
            import os
            os.makedirs(output_dir, exist_ok=True)
            report_path = str(Path(output_dir) / "technical_report.json")
            summary_path = str(Path(output_dir) / "executive_summary.json")
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(tech_report.model_dump(mode="json"), f, indent=2)
            with open(summary_path, "w", encoding="utf-8") as f:
                json.dump(exec_summary.model_dump(mode="json"), f, indent=2)

        event = ReportGeneratedEvent(
            job_id=job_id,
            sample_id=sample_id,
            correlation_id=correlation_id,
            report_id=report_id,
            report_path=report_path,
            summary_path=summary_path or "",
        )
        self._pending_report_events[job_id] = event
        # event will be published by handle_event() after transition_and_save()

    async def _perform_comparison(self, original_dict: dict, mutated_dict: dict, log) -> Optional[ComparisonResultModel]:
        """Generate comparison between original and mutated sample analysis results."""
        try:
            from contracts.analysis import ComparisonResultModel
            
            # Extract behavioral metrics from both reports
            orig_detections = len(original_dict.get("detection_names", []))
            mut_detections = len(mutated_dict.get("detection_names", []))
            
            orig_score = float(original_dict.get("threat_score", 0.0))
            mut_score = float(mutated_dict.get("threat_score", 0.0))
            
            orig_api_count = original_dict.get("api_call_count", 0)
            mut_api_count = mutated_dict.get("api_call_count", 0)
            
            # Signature comparison (simplified)
            orig_detections_set = set(original_dict.get("detection_names", []))
            mut_detections_set = set(mutated_dict.get("detection_names", []))
            
            common_sigs = list(orig_detections_set & mut_detections_set)
            removed_sigs = list(orig_detections_set - mut_detections_set)  
            new_sigs = list(mut_detections_set - orig_detections_set)
            
            # API similarity (simplified based on counts)
            api_similarity = 1.0
            if orig_api_count > 0 or mut_api_count > 0:
                max_apis = max(orig_api_count, mut_api_count)
                min_apis = min(orig_api_count, mut_api_count)
                api_similarity = min_apis / max_apis if max_apis > 0 else 0.0
            
            # Behavioral preservation check
            behavioral_preserved = (
                api_similarity >= 0.7 and
                len(common_sigs) >= len(orig_detections_set) * 0.5
            )
            
            comparison = ComparisonResultModel(
                original_detections=orig_detections,
                mutated_detections=mut_detections,
                detection_delta=mut_detections - orig_detections,
                api_similarity=api_similarity,
                behavioral_preserved=behavioral_preserved,
                new_signatures=new_sigs,
                removed_signatures=removed_sigs,
                common_signatures=common_sigs,
                score_delta=mut_score - orig_score,
                original_score=orig_score,
                mutated_score=mut_score,
            )
            
            log.info("comparison_generated",
                    detection_delta=comparison.detection_delta,
                    score_delta=comparison.score_delta,
                    api_similarity=comparison.api_similarity,
                    behavioral_preserved=comparison.behavioral_preserved)
            
            return comparison
            
        except Exception as exc:
            log.warning("comparison_failed", error=str(exc))
            return None

    async def _generate_exec_summary(self, tech_report: TechnicalReport) -> Optional[ExecutiveSummary]:
        try:
            prompt = _load_prompt(_EXEC_SUMMARY_PROMPT_PATH).replace(
                "{{report_context_json}}",
                json.dumps(
                    {
                        "report_id": tech_report.report_id,
                        "job_id": tech_report.job_id,
                        "threat_score": tech_report.threat_score,
                        "primary_category": tech_report.primary_category,
                        "detection_count": tech_report.detection_count,
                        "key_behaviors": tech_report.key_behaviors,
                    },
                    indent=2,
                ),
            )
            request = LLMRequest(
                system_prompt=(
                    "You are a security report writer. "
                    "Provide factual executive summary only. "
                    "No evasion or anti-detection guidance."
                ),
                user_prompt=prompt,
                response_format="json",
                max_tokens=1024,
                temperature=0.2,
            )
            summary = await self._ctx.llm_provider.generate_structured(request, ExecutiveSummary)
            summary.report_id = tech_report.report_id
            summary.job_id = tech_report.job_id
            summary.risk_level = _risk_from_score(tech_report.threat_score)
            return summary
        except Exception:
            return None


def _build_analysis_model(job_id: str, sample_id: str, d: dict) -> BehaviorAnalysisResult:
    try:
        return BehaviorAnalysisResult.model_validate(d)
    except Exception:
        return BehaviorAnalysisResult(
            job_id=job_id,
            sample_id=sample_id,
            sandbox_task_id=d.get("sandbox_task_id", 0),
            sandbox_backend=d.get("sandbox_backend", "cape"),
            threat_score=float(d.get("threat_score", 0.0)),
            detection_count=int(d.get("detection_count", 0)),
            detection_names=d.get("detection_names", []),
            key_behaviors=d.get("key_behaviors", []),
            anomalies=d.get("anomalies", []),
        )


def _build_decision_model(d: dict) -> Optional[DecisionResult]:
    if not d:
        return None
    try:
        return DecisionResult.model_validate(d)
    except Exception:
        return None


def _risk_from_score(score: float) -> RiskLevel:
    if score >= 8.0:
        return RiskLevel.CRITICAL
    if score >= 6.0:
        return RiskLevel.HIGH
    if score >= 3.0:
        return RiskLevel.MEDIUM
    if score > 0.0:
        return RiskLevel.LOW
    return RiskLevel.INFORMATIONAL


def _fallback_exec_summary(tech_report: TechnicalReport) -> ExecutiveSummary:
    risk_level = _risk_from_score(tech_report.threat_score)
    return ExecutiveSummary(
        report_id=tech_report.report_id,
        job_id=tech_report.job_id,
        title=f"Malware Analysis Summary — {tech_report.sample_id}",
        risk_level=risk_level,
        one_line_summary=(
            f"Threat score {tech_report.threat_score:.1f}/10 with "
            f"{tech_report.detection_count} detections."
        ),
        key_findings=tech_report.key_behaviors[:5] or ["No major behaviors detected"],
        recommended_actions=[
            "Isolate affected systems for containment",
            "Block identified IOCs in security controls",
            "Escalate to incident response if related alerts are observed",
        ],
        full_narrative=(
            f"Sample {tech_report.sample_id} was analyzed with a threat score of "
            f"{tech_report.threat_score:.1f}/10 ({risk_level.value})."
        ),
        generated_by="template",
    )


def _load_prompt(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return (
        "Write an executive summary for the following report:\n"
        "{{report_context_json}}\n"
        'Respond JSON: {"title":"...","one_line_summary":"...","key_findings":["..."],'
        '"recommended_actions":["..."],"full_narrative":"...","risk_level":"low"}'
    )
