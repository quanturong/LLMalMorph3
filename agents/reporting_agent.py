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

    Self-activates on: DecisionIssuedEvent with any of these actions
                       (DECISION_ISSUED → REPORTING):
      - continue_to_report  → generate report, submit VT, CLOSED
      - close_no_behavior   → skip report, submit VT for metrics, CLOSED
      - close_failed        → skip report, submit VT for metrics, CLOSED
      - escalate_to_analyst → ESCALATED, publish EscalationEvent to analyst queue
    """

    agent_name = "ReportingAgent"
    command_stream = Topic.CMD_REPORT
    consumer_group = Topic.CG_REPORT
    event_consumer_group = Topic.CG_EVENTS_REPORT

    activates_on = {
        _SIG_DECISION_REPORT: (
            JobStatus.DECISION_ISSUED,
            JobStatus.REPORTING,
            # Claim all terminal actions (close/escalate/report).
            # retry_with_mutation is handled by MutationAgent; retry_sandbox by SandboxSubmitAgent.
            lambda d: d.get("action") in {
                "continue_to_report",
                "escalate_to_analyst",
                "close_no_behavior",
                "close_failed",
            },
        ),
    }

    capabilities = {"stage": "reporting", "uses_llm": True}

    def __init__(self, ctx, vt_adapter=None):
        super().__init__(ctx)
        self._pending_report_events: dict = {}
        self._vt = vt_adapter

    async def handle_event(self, data: dict, claimed_state) -> None:
        """Handle decision events — generate report for continue_to_report, close otherwise."""
        action = data.get("action", "")
        job_id = data.get("job_id", "")
        log = logger.bind(job_id=job_id, action=action)

        if action == "escalate_to_analyst":
            # True escalation: transition REPORTING → ESCALATED, publish EscalationEvent
            # to the analyst queue (DLQ / human-in-loop per SYSTEM_ARCHITECTURE.md §2).
            log.warning("escalating_to_analyst")
            if self._ctx.state_store:
                state = await self._ctx.state_store.get(job_id)
                if state and state.current_status == JobStatus.REPORTING:
                    await self.transition_and_save(state, JobStatus.ESCALATED,
                                                   reason="action=escalate_to_analyst")
                    from contracts.messages import EscalationEvent
                    escalation_event = EscalationEvent(
                        job_id=state.job_id,
                        sample_id=state.sample_id,
                        correlation_id=state.correlation_id,
                        reason="Decision agent recommended escalation",
                        triggered_by_agent="ReportingAgent",
                    )
                    await self._ctx.broker.publish(Topic.ESCALATION_ANALYST, escalation_event)
                    log.info("job_escalated_to_analyst")
            return

        if action in ("close_no_behavior", "close_failed"):
            # Terminal close: skip report generation, optionally submit to VT for metrics.
            log.info("non_report_action_closing_job",
                     reason="state_claimed_reporting_must_close")
            # Submit to VT even on close so evasion metrics are captured.
            if self._vt:
                await self._submit_to_virustotal(job_id, log)
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

        # ── VirusTotal submission (both original + variant) ──
        if self._vt and self._ctx.state_store:
            await self._submit_to_virustotal(data["job_id"], log)

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
            if current_state:
                # Detect mutated sample: either explicitly flagged, or inferred
                # from the pipeline having both original and variant reports
                # (the pipeline mutates BEFORE sandbox, so is_mutated_sample may
                #  not be set by DecisionAgent on the first pass).
                has_original_report = bool(current_state.original_raw_report_artifact_id)
                has_variant_report = bool(current_state.raw_report_artifact_id)
                explicitly_flagged = current_state.is_mutated_sample and current_state.original_analysis_result_id

                if explicitly_flagged:
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
                elif has_original_report and has_variant_report:
                    # Infer: pipeline mutated first, both binaries submitted to sandbox
                    is_mutated_sample = True
                    current_state.is_mutated_sample = True
                    log.info("inferred_mutated_sample",
                             original_report=current_state.original_raw_report_artifact_id,
                             variant_report=current_state.raw_report_artifact_id)

                    # Build comparison from the two raw sandbox reports
                    original_analysis_dict = {}
                    if self._ctx.artifact_store:
                        original_analysis_dict = await self._ctx.artifact_store.get_json(
                            job_id, current_state.original_raw_report_artifact_id
                        ) or {}
                    variant_analysis_dict = analysis_dict  # already loaded above

                    if original_analysis_dict and variant_analysis_dict:
                        comparison_model = await self._perform_comparison(
                            original_analysis_dict, variant_analysis_dict, log
                        )

                # Store comparison result if generated
                if comparison_model and self._ctx.artifact_store:
                    comparison_id = await self._ctx.artifact_store.store_json(
                        job_id=job_id,
                        artifact_type="comparison_result",
                        data=comparison_model.model_dump(mode="json"),
                    )
                    current_state.comparison_result_id = comparison_id
                    await self._ctx.state_store.save(current_state)
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

    async def _submit_to_virustotal(self, job_id: str, log) -> None:
        """Submit both original and variant binaries to VirusTotal, poll for results,
        compute engine-level comparison, and store as artifacts."""
        import hashlib
        import time as _time

        state = await self._ctx.state_store.get(job_id)
        if not state:
            return

        variant_art_id = state.compiled_artifact_id
        original_art_id = state.original_compiled_artifact_id
        if not variant_art_id or not original_art_id:
            log.info("vt_skip_no_binaries")
            return

        # Resolve file paths
        variant_path = None
        original_path = None
        if self._ctx.artifact_store:
            variant_path = await asyncio.get_event_loop().run_in_executor(
                None, lambda: self._ctx.artifact_store.get_path_sync(variant_art_id)
            )
            original_path = await asyncio.get_event_loop().run_in_executor(
                None, lambda: self._ctx.artifact_store.get_path_sync(original_art_id)
            )

        if not variant_path or not original_path:
            log.warning("vt_skip_paths_not_resolved",
                        variant_art_id=variant_art_id, original_art_id=original_art_id)
            return

        log.info("vt_submitting", variant=str(variant_path), original=str(original_path))

        try:
            # Helper: get SHA256 of local file
            def _sha256(fpath):
                h = hashlib.sha256()
                with open(fpath, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        h.update(chunk)
                return h.hexdigest()

            variant_sha = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _sha256(variant_path))
            original_sha = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _sha256(original_path))

            # Submit both
            var_aid = await self._vt.submit_file(str(variant_path))
            await asyncio.sleep(15)  # VT rate limit
            orig_aid = await self._vt.submit_file(str(original_path))

            log.info("vt_submitted", variant_aid=var_aid, original_aid=orig_aid)

            # Poll until done (max 5 min each)
            for label, aid in [("variant", var_aid), ("original", orig_aid)]:
                if not aid:
                    continue
                for _ in range(20):
                    done = await self._vt.is_complete(aid)
                    if done:
                        break
                    await asyncio.sleep(15)

            # Fetch results by hash
            async def _fetch_by_hash(sha):
                import requests as _req
                headers = {"x-apikey": self._vt._client.api_token}
                url = f"{self._vt._client.api_url}/api/v3/files/{sha}"
                resp = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: _req.get(url, headers=headers, timeout=30))
                if resp.status_code == 200:
                    return resp.json().get("data", {}).get("attributes", {})
                return None

            var_attrs = await _fetch_by_hash(variant_sha)
            await asyncio.sleep(1)
            orig_attrs = await _fetch_by_hash(original_sha)

            if not var_attrs or not orig_attrs:
                log.warning("vt_results_incomplete",
                            var_found=bool(var_attrs), orig_found=bool(orig_attrs))
                return

            # Parse stats
            orig_stats = orig_attrs.get("last_analysis_stats", {})
            var_stats = var_attrs.get("last_analysis_stats", {})
            orig_mal = orig_stats.get("malicious", 0)
            var_mal = var_stats.get("malicious", 0)
            orig_total = sum(orig_stats.values())
            var_total = sum(var_stats.values())

            # Engine-level diff
            orig_engines = orig_attrs.get("last_analysis_results", {})
            var_engines = var_attrs.get("last_analysis_results", {})
            all_engines = set(orig_engines.keys()) | set(var_engines.keys())

            flipped_off, flipped_on = [], []
            for eng in sorted(all_engines):
                o_mal = orig_engines.get(eng, {}).get("category", "undetected") in ("malicious", "suspicious")
                v_mal = var_engines.get(eng, {}).get("category", "undetected") in ("malicious", "suspicious")
                if o_mal and not v_mal:
                    flipped_off.append(eng)
                elif not o_mal and v_mal:
                    flipped_on.append(eng)

            direction = "unchanged"
            if var_mal < orig_mal:
                direction = "decreased"
            elif var_mal > orig_mal:
                direction = "increased"

            vt_comparison = {
                "original_sha256": original_sha,
                "variant_sha256": variant_sha,
                "original_detection": f"{orig_mal}/{orig_total}",
                "variant_detection": f"{var_mal}/{var_total}",
                "original_malicious_count": orig_mal,
                "variant_malicious_count": var_mal,
                "original_total_engines": orig_total,
                "variant_total_engines": var_total,
                "detection_delta": var_mal - orig_mal,
                "original_detection_ratio": round(orig_mal / orig_total, 4) if orig_total > 0 else 0,
                "variant_detection_ratio": round(var_mal / var_total, 4) if var_total > 0 else 0,
                "direction": direction,
                "engines_flipped_off": flipped_off,
                "engines_flipped_on": flipped_on,
                "engines_flipped_off_count": len(flipped_off),
                "engines_flipped_on_count": len(flipped_on),
                "original_threat_classification": orig_attrs.get("popular_threat_classification", {}),
                "variant_threat_classification": var_attrs.get("popular_threat_classification", {}),
            }

            # Store as artifact
            if self._ctx.artifact_store:
                vt_art_id = await self._ctx.artifact_store.store_json(
                    job_id=job_id,
                    artifact_type="vt_comparison",
                    data=vt_comparison,
                )
                state.vt_comparison_artifact_id = vt_art_id if hasattr(state, "vt_comparison_artifact_id") else None

            # Update state with summary fields
            state.vt_original_malicious = orig_mal
            state.vt_variant_malicious = var_mal
            state.vt_detection_delta = var_mal - orig_mal
            state.vt_direction = direction
            await self._ctx.state_store.save(state)

            # Update report file with VT data
            pending_evt = self._pending_report_events.get(job_id)
            if pending_evt and hasattr(pending_evt, "report_path") and pending_evt.report_path:
                try:
                    rpath = pending_evt.report_path
                    def _update_report():
                        import os as _os
                        if _os.path.exists(rpath):
                            with open(rpath, "r") as f:
                                rd = json.load(f)
                            rd["vt_comparison"] = vt_comparison
                            with open(rpath, "w") as f:
                                json.dump(rd, f, indent=2)
                    await asyncio.get_event_loop().run_in_executor(None, _update_report)
                except Exception:
                    pass  # non-critical

            log.info("vt_complete",
                     original=f"{orig_mal}/{orig_total}",
                     variant=f"{var_mal}/{var_total}",
                     delta=var_mal - orig_mal,
                     direction=direction,
                     flipped_off=len(flipped_off),
                     flipped_on=len(flipped_on))

        except Exception as exc:
            log.warning("vt_submission_failed", error=str(exc))

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
