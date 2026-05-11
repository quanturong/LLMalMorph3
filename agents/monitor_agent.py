"""
MonitorAgent — lightweight health monitor for the distributed pipeline.

Unlike the old CoordinatorAgent, this agent does NOT route messages.
It only:
  - Watches EVENTS_ALL for progress tracking
  - Tracks agent heartbeats via AgentRegistry
  - Detects stuck jobs (no state change within timeout)
  - Emits recovery events for stuck jobs (re-publish the last known event)
  - Provides job lifecycle logging and metrics
  - Can submit new jobs (entry point for the pipeline)

All workflow routing is handled by the agents themselves via self-activation.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, Set

import structlog

from broker.interface import AcknowledgeableMessage
from broker.topics import Topic
from contracts.job import JobEnvelope, JobState, JobStatus
from contracts.messages import (
    ErrorEvent,
    EscalationEvent,
    HeartbeatEvent,
    JobClosedEvent,
    JobCreatedEvent,
    JobFailedEvent,
    SamplePreparedEvent,
    VariantGeneratedEvent,
)
from workflows.state_machine import JobStateMachine

from .base_agent import AgentContext, BaseAgent

logger = structlog.get_logger(__name__)

_STUCK_JOB_TIMEOUT_S = 600  # 10 minutes without progress → stuck
_LONG_RUNNING_TIMEOUT_S = 1800  # 30 min for MUTATING / BUILD_VALIDATING
_LONG_RUNNING_STATES = frozenset({"MUTATING", "BUILD_VALIDATING", "EXECUTION_MONITORING"})
_STUCK_CHECK_INTERVAL_S = 60


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        logger.warning("invalid_int_env", name=name, value=os.environ.get(name), default=default)
        return default


_MAX_BUILD_RETRIES = _int_env("MAX_BUILD_RETRIES", 2)


class MonitorAgent(BaseAgent):
    """
    Passive monitor — observes all events without routing.

    Responsibilities:
      1. Job submission (entry point)
      2. Event logging / progress tracking
      3. Stuck job detection and recovery
      4. Agent health monitoring (via heartbeat)
      5. Terminal state detection (all jobs done)
    """

    agent_name = "MonitorAgent"
    command_stream = Topic.EVENTS_ALL
    consumer_group = Topic.CG_MONITOR

    # Monitor does NOT self-activate — it passively observes
    activates_on = {}

    def __init__(
        self,
        ctx: AgentContext,
        output_base_dir: str = "",
        stuck_timeout_s: float = _STUCK_JOB_TIMEOUT_S,
    ) -> None:
        super().__init__(ctx)
        self._sm = JobStateMachine()
        self._output_base_dir = output_base_dir or ctx.work_dir
        # If configured timeout is non-positive, disable stuck-job detection
        self._stuck_timeout_s = stuck_timeout_s if stuck_timeout_s and stuck_timeout_s > 0 else None

        # Track last event time per job
        self._job_last_event: Dict[str, float] = {}
        self._job_last_status: Dict[str, str] = {}
        self._active_jobs: Set[str] = set()
        self._stuck_check_task: Optional[asyncio.Task] = None

    # ──────────────────────────────────────────────────────────────────────
    # Job submission — entry point
    # ──────────────────────────────────────────────────────────────────────

    async def submit_job(self, envelope: JobEnvelope) -> str:
        """
        Create initial JobState and emit JobCreatedEvent.
        Other agents will self-activate from this event.
        """
        state = JobState(
            job_id=envelope.job_id,
            sample_id=envelope.sample_id,
            correlation_id=envelope.correlation_id,
            project_name=envelope.project_name,
            language=envelope.language,
            requested_strategies=envelope.requested_strategies,
            strategy_mode=envelope.strategy_mode,
            max_generations=envelope.max_generations,
            num_functions=envelope.num_functions,
            target_functions=envelope.target_functions,
            sandbox_backend=envelope.sandbox_backend,
            llm_retry_attempts=envelope.llm_retry_attempts,
        )
        if self._ctx.state_store:
            await self._ctx.state_store.save(state)

        event = JobCreatedEvent(
            job_id=envelope.job_id,
            sample_id=envelope.sample_id,
            correlation_id=envelope.correlation_id,
            source_path=envelope.source_path,
            project_name=envelope.project_name,
            language=envelope.language,
            requested_strategies=envelope.requested_strategies,
            strategy_mode=envelope.strategy_mode,
            max_generations=envelope.max_generations,
            num_functions=envelope.num_functions,
            sandbox_backend=envelope.sandbox_backend,
            priority=envelope.priority,
        )
        await self._ctx.broker.publish(Topic.EVENTS_ALL, event)
        self._active_jobs.add(envelope.job_id)
        self._job_last_event[envelope.job_id] = time.monotonic()
        self._job_last_status[envelope.job_id] = "CREATED"
        logger.info("job_submitted", job_id=envelope.job_id, project=envelope.project_name)
        return envelope.job_id

    # ──────────────────────────────────────────────────────────────────────
    # Start / Stop
    # ──────────────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start event observation + stuck job checker."""
        self._running = True
        self._start_time = time.monotonic()
        self._log.info("monitor_started")

        # Register
        await self._register()

        # Start heartbeat
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        # Start stuck job checker
        self._stuck_check_task = asyncio.create_task(self._stuck_job_checker())

        # Subscribe to EVENTS_ALL for passive observation
        await self._ctx.broker.subscribe(
            stream=Topic.EVENTS_ALL,
            consumer_group=self.consumer_group,
            consumer_name=self.agent_name,
            handler=self._dispatch,
        )

    async def stop(self) -> None:
        self._running = False
        if self._stuck_check_task:
            self._stuck_check_task.cancel()
        await super().stop()

    # ──────────────────────────────────────────────────────────────────────
    # Event handler — passive observation only
    # ──────────────────────────────────────────────────────────────────────

    async def handle(self, data: dict) -> None:
        """
        Observe events for tracking. NO routing logic.
        Just logs progress and updates tracking metadata.
        """
        job_id = data.get("job_id", "")
        if not job_id:
            # Handle heartbeat / registration events
            if "agent_name" in data and "agent_status" in data:
                await self._handle_heartbeat(data)
            return

        # Update tracking
        now = time.monotonic()
        self._job_last_event[job_id] = now
        self._active_jobs.add(job_id)

        # Detect terminal events
        if "final_status" in data:
            # JobClosedEvent
            self._active_jobs.discard(job_id)
            status = data.get("final_status", "CLOSED")
            self._job_last_status[job_id] = status
            logger.info("job_terminal", job_id=job_id, status=status)

        elif "failure_stage" in data and "error_message" in data:
            # JobFailedEvent
            self._active_jobs.discard(job_id)
            self._job_last_status[job_id] = "FAILED"
            logger.warning("job_failed", job_id=job_id,
                           stage=data.get("failure_stage"),
                           error=data.get("error_message", "")[:200])

        elif "error_code" in data and "agent" in data:
            # ErrorEvent — log but don't act (agents handle their own errors)
            logger.warning("agent_error_observed",
                           job_id=job_id, agent=data.get("agent"),
                           error=data.get("error_code"))

        elif "auto_fix_attempts" in data and "compiled_artifact_id" not in data:
            # BuildFailedEvent - auto-fix exhausted for this build attempt.
            # Re-arm the build stage a small number of times before making the
            # job terminal, otherwise transient compiler/worker failures become
            # unrecoverable FAILED rows.
            self._job_last_status[job_id] = "BUILD_FAILED"
            auto_fix = data.get("auto_fix_attempts", 0)
            logger.warning("build_failed_observed", job_id=job_id,
                           auto_fix_attempts=auto_fix)
            if self._ctx.state_store:
                state = await self._ctx.state_store.get(job_id)
                if state and not state.current_status.is_terminal():
                    error_message = data.get(
                        "error_message",
                        "Build failed after auto-fix exhausted",
                    )
                    state.add_error(
                        "BuildValidationAgent",
                        "BUILD_FAILED",
                        error_message[:1000],
                        state.build_retry_count < _MAX_BUILD_RETRIES,
                    )
                    recovered = await self._retry_build_failed_job(state, data)
                    if recovered:
                        return
                    await self._close_build_failed_job(state, data)

        else:
            # Progress event — update status tracking
            status = self._infer_status(data)
            if status:
                self._job_last_status[job_id] = status
                logger.debug("job_progress", job_id=job_id, status=status)

    def _infer_status(self, data: dict) -> str:
        """Infer job status from event fields (for tracking purposes)."""
        if "source_artifact_id" in data and "num_source_files" in data:
            return "SAMPLE_READY"
        elif "mutation_artifact_id" in data and "num_functions_mutated" in data:
            return "MUTATION_READY"
        elif "variant_artifact_id" in data and "num_files_generated" in data:
            return "VARIANT_READY"
        elif "compiled_artifact_id" in data and "binary_sha256" in data:
            return "BUILD_READY"
        elif "auto_fix_attempts" in data and "compiled_artifact_id" not in data:
            return "BUILD_FAILED"
        elif "sandbox_task_id" in data and "submit_time" in data:
            return "SANDBOX_SUBMITTED"
        elif "raw_report_artifact_id" in data and "analysis_duration_s" in data:
            return "EXECUTION_COMPLETE"
        elif "failure_reason" in data and "sandbox_task_id" in data:
            return "EXECUTION_FAILED"
        elif "analysis_result_id" in data and "ioc_count" in data:
            return "BEHAVIOR_ANALYZED"
        elif "decision_id" in data and "action" in data:
            return "DECISION_ISSUED"
        elif "report_id" in data and "report_path" in data:
            return "REPORT_READY"
        return ""

    # ──────────────────────────────────────────────────────────────────────
    # Heartbeat tracking
    # ──────────────────────────────────────────────────────────────────────

    async def _handle_heartbeat(self, data: dict) -> None:
        """Update agent registry from heartbeat events."""
        if self._ctx.agent_registry:
            await self._ctx.agent_registry.update_heartbeat(
                agent_name=data.get("agent_name", ""),
                status=data.get("agent_status", "alive"),
                current_job_id=data.get("current_job_id"),
                jobs_processed=data.get("jobs_processed", 0),
            )

    # ──────────────────────────────────────────────────────────────────────
    # Stuck job detection and recovery
    # ──────────────────────────────────────────────────────────────────────

    async def _stuck_job_checker(self) -> None:
        """Periodically check for jobs that haven't progressed."""
        try:
            while self._running:
                await asyncio.sleep(_STUCK_CHECK_INTERVAL_S)
                await self._check_stuck_jobs()
        except asyncio.CancelledError:
            pass

    async def _check_stuck_jobs(self) -> None:
        """Detect and attempt recovery of stuck jobs.

        Bug #18 fix: query actual DB status instead of trusting stale cache,
        and use a longer timeout for known long-running states (MUTATING,
        BUILD_VALIDATING) which naturally take 15-30 min without events.
        """
        now = time.monotonic()
        stuck_jobs = []

        for job_id in list(self._active_jobs):
            last_event_time = self._job_last_event.get(job_id, 0)
            idle_s = now - last_event_time

            # Query actual DB status — cache may be stale
            actual_status = self._job_last_status.get(job_id, "unknown")
            if self._ctx.state_store:
                state = await self._ctx.state_store.get(job_id)
                if state:
                    actual_status = state.current_status.value
                    # If actual status advanced beyond cache, refresh timer
                    if actual_status != self._job_last_status.get(job_id, ""):
                        self._job_last_status[job_id] = actual_status
                        self._job_last_event[job_id] = now
                        logger.info("job_progressed_silently", job_id=job_id,
                                    actual_status=actual_status)
                        continue
                    if state.current_status.is_terminal():
                        self._active_jobs.discard(job_id)
                        continue

                # If stuck-job detection disabled, skip
                if not self._stuck_timeout_s:
                    continue

                # Use longer timeout for long-running states
                timeout = (_LONG_RUNNING_TIMEOUT_S
                           if actual_status in _LONG_RUNNING_STATES
                           else self._stuck_timeout_s)

                if idle_s > timeout:
                    stuck_jobs.append(job_id)

        for job_id in stuck_jobs:
            actual = self._job_last_status.get(job_id, "unknown")
            logger.warning("stuck_job_detected", job_id=job_id,
                           last_status=actual,
                           idle_s=now - self._job_last_event.get(job_id, 0))
            await self._attempt_recovery(job_id)

    async def _attempt_recovery(self, job_id: str) -> None:
        """
        Try to recover a stuck job by re-emitting an appropriate event.
        The self-activating agents will pick it up if they can.
        """
        if not self._ctx.state_store:
            return

        state = await self._ctx.state_store.get(job_id)
        if state is None or state.current_status.is_terminal():
            self._active_jobs.discard(job_id)
            return

        status = state.current_status
        logger.info("attempting_recovery", job_id=job_id, status=status.value)

        if status == JobStatus.MUTATING:
            recovered = await self._recover_stuck_mutating_job(state)
            if recovered:
                self._job_last_event[job_id] = time.monotonic()
                self._job_last_status[job_id] = JobStatus.SAMPLE_READY.value
                return

        if status == JobStatus.VARIANT_READY:
            recovered = await self._recover_stuck_variant_ready_job(state)
            if recovered:
                self._job_last_event[job_id] = time.monotonic()
                self._job_last_status[job_id] = JobStatus.VARIANT_READY.value
                return

        # If job is stuck in a "doing" state, escalate
        # If stuck in a "ready" state, the agent that should claim it might be dead
        if state.retry_count >= 5:
            # Too many retries — escalate
            event = EscalationEvent(
                job_id=job_id,
                sample_id=state.sample_id,
                correlation_id=state.correlation_id,
                reason=f"Job stuck in {status.value} after {state.retry_count} retries",
                triggered_by_agent="MonitorAgent",
                severity="high",
            )
            await self._ctx.broker.publish(Topic.ESCALATION_ANALYST, event)
            self._active_jobs.discard(job_id)
        else:
            # Reset the tracking timer to give agents more time
            self._job_last_event[job_id] = time.monotonic()

    async def _retry_build_failed_job(self, state: JobState, data: dict) -> bool:
        """Requeue a failed build from the latest variant artifact."""
        if state.build_retry_count >= _MAX_BUILD_RETRIES:
            logger.warning(
                "build_retry_exhausted",
                job_id=state.job_id,
                build_retry_count=state.build_retry_count,
                max_build_retries=_MAX_BUILD_RETRIES,
            )
            return False

        variant_artifact_id = state.variant_artifact_id or self._latest_artifact_for_job(
            state.job_id,
            "variant_source",
        )
        if not variant_artifact_id:
            logger.warning("build_retry_missing_variant_artifact", job_id=state.job_id)
            return False

        payload = None
        if self._ctx.artifact_store:
            payload = await self._ctx.artifact_store.get_json(variant_artifact_id)

        source_artifact_id = (
            state.source_artifact_id
            or (payload or {}).get("source_artifact_id")
            or self._latest_artifact_for_job(state.job_id, "source_parse_result")
        )
        mutation_artifact_id = (
            state.mutation_artifact_id
            or (payload or {}).get("mutation_artifact_id")
            or self._latest_artifact_for_job(state.job_id, "mutation_result")
        )
        if not source_artifact_id or not mutation_artifact_id:
            logger.warning(
                "build_retry_missing_parent_artifacts",
                job_id=state.job_id,
                source_artifact_id=source_artifact_id,
                mutation_artifact_id=mutation_artifact_id,
            )
            return False

        state.build_retry_count += 1
        state.source_artifact_id = source_artifact_id
        state.mutation_artifact_id = mutation_artifact_id
        state.variant_artifact_id = variant_artifact_id
        state.compiled_artifact_id = None
        state.agent_in_charge = None
        state.transition_to(
            JobStatus.VARIANT_READY,
            triggered_by="MonitorAgent",
            reason=f"retry build after BUILD_FAILED ({state.build_retry_count}/{_MAX_BUILD_RETRIES})",
        )
        await self._ctx.state_store.save(state)

        event = VariantGeneratedEvent(
            job_id=state.job_id,
            sample_id=state.sample_id,
            correlation_id=state.correlation_id,
            variant_artifact_id=variant_artifact_id,
            source_artifact_id=source_artifact_id,
            mutation_artifact_id=mutation_artifact_id,
            project_name=(payload or {}).get("project_name", state.project_name),
            language=(payload or {}).get("language", state.language),
            num_files_generated=int((payload or {}).get("num_files_generated", 0) or 0),
        )
        await self._ctx.broker.publish(Topic.EVENTS_ALL, event)
        self._job_last_event[state.job_id] = time.monotonic()
        self._job_last_status[state.job_id] = JobStatus.VARIANT_READY.value
        logger.info(
            "build_retry_requeued",
            job_id=state.job_id,
            build_retry_count=state.build_retry_count,
            variant_artifact_id=variant_artifact_id,
        )
        return True

    async def _recover_stuck_variant_ready_job(self, state: JobState) -> bool:
        """Re-publish VariantGeneratedEvent for a VARIANT_READY job.

        BuildValidationAgent self-activates from VariantGeneratedEvent. If the
        event is lost after the state reaches VARIANT_READY, the job can sit in
        ready state forever. This recovery reconstructs the event from the
        persisted state and latest artifacts.
        """
        variant_artifact_id = state.variant_artifact_id or self._latest_artifact_for_job(
            state.job_id,
            "variant_source",
        )
        if not variant_artifact_id:
            logger.warning("variant_ready_recovery_missing_variant_artifact", job_id=state.job_id)
            return False

        payload = None
        if self._ctx.artifact_store:
            payload = await self._ctx.artifact_store.get_json(variant_artifact_id)

        source_artifact_id = (
            state.source_artifact_id
            or (payload or {}).get("source_artifact_id")
            or self._latest_artifact_for_job(state.job_id, "source_parse_result")
        )
        mutation_artifact_id = (
            state.mutation_artifact_id
            or (payload or {}).get("mutation_artifact_id")
            or self._latest_artifact_for_job(state.job_id, "mutation_result")
        )
        if not source_artifact_id or not mutation_artifact_id:
            logger.warning(
                "variant_ready_recovery_missing_parent_artifacts",
                job_id=state.job_id,
                source_artifact_id=source_artifact_id,
                mutation_artifact_id=mutation_artifact_id,
            )
            return False

        state.source_artifact_id = source_artifact_id
        state.mutation_artifact_id = mutation_artifact_id
        state.variant_artifact_id = variant_artifact_id
        state.agent_in_charge = None
        await self._ctx.state_store.save(state)

        event = VariantGeneratedEvent(
            job_id=state.job_id,
            sample_id=state.sample_id,
            correlation_id=state.correlation_id,
            variant_artifact_id=variant_artifact_id,
            source_artifact_id=source_artifact_id,
            mutation_artifact_id=mutation_artifact_id,
            project_name=(payload or {}).get("project_name", state.project_name),
            language=(payload or {}).get("language", state.language),
            num_files_generated=int((payload or {}).get("num_files_generated", 0) or 0),
        )
        await self._ctx.broker.publish(Topic.EVENTS_ALL, event)
        logger.info(
            "variant_ready_recovery_republished",
            job_id=state.job_id,
            variant_artifact_id=variant_artifact_id,
        )
        return True

    async def _close_build_failed_job(self, state: JobState, data: dict) -> None:
        error_message = data.get(
            "error_message",
            "Build failed after auto-fix exhausted",
        )
        try:
            if not state.current_status.is_terminal():
                self._sm.transition(
                    state,
                    JobStatus.FAILED,
                    "MonitorAgent",
                    reason="build failed after retries exhausted",
                )
            await self._ctx.state_store.save(state)
        except Exception:
            pass

        fail_evt = JobFailedEvent(
            job_id=state.job_id,
            sample_id=data.get("sample_id", state.sample_id),
            correlation_id=data.get("correlation_id", state.correlation_id),
            failure_stage="BUILD_VALIDATION",
            error_message=error_message[:500],
        )
        await self._ctx.broker.publish(Topic.EVENTS_ALL, fail_evt)
        self._active_jobs.discard(state.job_id)
        self._job_last_status[state.job_id] = JobStatus.FAILED.value

    async def _recover_stuck_mutating_job(self, state: JobState) -> bool:
        """Re-arm a MUTATING job whose activation event was lost after claim.

        MutationAgent self-activates from SamplePreparedEvent only when the DB
        status is SAMPLE_READY. If the previous event was consumed after CAS
        moved the job to MUTATING, republishing alone is not enough: the claim
        would fail. We persist the source artifact, move the job back to the
        ready state, then publish a fresh SamplePreparedEvent.
        """
        source_artifact_id = state.source_artifact_id
        if not source_artifact_id:
            source_artifact_id = self._latest_source_artifact_for_job(state.job_id)
            if source_artifact_id:
                state.source_artifact_id = source_artifact_id

        if not source_artifact_id:
            logger.warning("mutating_recovery_missing_source_artifact",
                           job_id=state.job_id)
            return False

        payload = None
        if self._ctx.artifact_store:
            payload = await self._ctx.artifact_store.get_json(source_artifact_id)

        num_source_files = 0
        num_functions_selected = 0
        if payload:
            num_source_files = len(payload.get("source_files", []))
            num_functions_selected = len(payload.get("functions", []))
            state.project_name = payload.get("project_name", state.project_name)
            state.language = payload.get("language", state.language)

        # Use transition_to directly here: MUTATING -> SAMPLE_READY is a
        # recovery rewind, not a normal workflow transition.
        state.transition_to(
            JobStatus.SAMPLE_READY,
            triggered_by="MonitorAgent",
            reason="recovery rewind for stuck MUTATING job",
        )
        state.agent_in_charge = None
        await self._ctx.state_store.save(state)

        event = SamplePreparedEvent(
            job_id=state.job_id,
            sample_id=state.sample_id,
            correlation_id=state.correlation_id,
            source_artifact_id=source_artifact_id,
            requested_strategies=state.requested_strategies,
            num_source_files=num_source_files,
            num_functions_selected=num_functions_selected,
            language=state.language,
            project_name=state.project_name,
        )
        await self._ctx.broker.publish(Topic.EVENTS_ALL, event)
        logger.info("mutating_recovery_republished_sample_ready",
                    job_id=state.job_id,
                    source_artifact_id=source_artifact_id,
                    functions=num_functions_selected)
        return True

    def _latest_source_artifact_for_job(self, job_id: str) -> str:
        return self._latest_artifact_for_job(job_id, "source_parse_result")

    def _latest_artifact_for_job(self, job_id: str, artifact_type: str) -> str:
        if not self._ctx.artifact_store:
            return ""
        try:
            artifacts = self._ctx.artifact_store.list_for_job(job_id)
        except Exception as exc:
            logger.warning("artifact_lookup_failed",
                           job_id=job_id, artifact_type=artifact_type, error=str(exc))
            return ""

        matching = [
            a for a in artifacts
            if a.get("type") == artifact_type
        ]
        if not matching:
            return ""
        matching.sort(key=lambda a: a.get("created_at", ""))
        return str(matching[-1].get("artifact_id", ""))

    # ──────────────────────────────────────────────────────────────────────
    # Query helpers
    # ──────────────────────────────────────────────────────────────────────

    def get_active_jobs(self) -> Set[str]:
        return set(self._active_jobs)

    def get_job_status(self, job_id: str) -> str:
        return self._job_last_status.get(job_id, "unknown")
