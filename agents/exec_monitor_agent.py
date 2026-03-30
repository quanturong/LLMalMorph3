"""
ExecMonitorAgent — polls sandbox until execution completes or times out.

This agent has *autonomous poll-loop*:
  polls CapeAdapter.get_task_status() with backoff until terminal state.

Input command:  ExecMonitorCommand
Output events:  ExecutionCompletedEvent | ExecutionFailedEvent
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import structlog

from broker.topics import Topic
from contracts.job import JobStatus
from contracts.messages import ExecutionCompletedEvent, ExecutionFailedEvent

from .base_agent import BaseAgent

logger = structlog.get_logger(__name__)

# Tuning constants
_POLL_INTERVAL_INITIAL_S = 15.0
_POLL_INTERVAL_MAX_S = 120.0
_POLL_BACKOFF_FACTOR = 1.5
_TASK_TIMEOUT_S = 600.0  # 10 minutes per submission

# Event signature: SandboxSubmittedEvent
_SIG_SANDBOX_SUBMITTED = frozenset({"sandbox_task_id", "sandbox_backend", "submit_time"})


class ExecMonitorAgent(BaseAgent):
    """
    Poll sandbox task status and emit completion/failure events.

    Self-activates on: SandboxSubmittedEvent (SANDBOX_SUBMITTED → EXECUTION_MONITORING)
    Has autonomous poll loop with exponential backoff.
    """

    agent_name = "ExecMonitorAgent"
    command_stream = Topic.CMD_EXEC_MONITOR
    consumer_group = Topic.CG_EXEC_MONITOR
    event_consumer_group = Topic.CG_EVENTS_EXEC_MONITOR

    activates_on = {
        _SIG_SANDBOX_SUBMITTED: (JobStatus.SANDBOX_SUBMITTED, JobStatus.EXECUTION_MONITORING),
    }

    capabilities = {"stage": "exec_monitor", "backend": "cape+virustotal", "autonomous_polling": True}

    def __init__(self, ctx, cape_adapter=None, vt_adapter=None,
                 timeout_s: float = _TASK_TIMEOUT_S) -> None:
        super().__init__(ctx)
        self._cape = cape_adapter
        self._vt = vt_adapter
        self._timeout_s = timeout_s
        self._pending_completed_events: dict = {}

    async def handle_event(self, data: dict, claimed_state) -> None:
        """Extract sandbox info from event and delegate."""
        cmd_data = {
            "job_id": data["job_id"],
            "sample_id": data.get("sample_id", ""),
            "correlation_id": data.get("correlation_id", ""),
            "sandbox_task_id": data.get("sandbox_task_id", ""),
            "sandbox_backend": data.get("sandbox_backend", "cape"),
        }
        await self.handle(cmd_data)
        # Transition to EXECUTION_COMPLETE (handle() stores event in _pending_completed_events)
        if self._ctx.state_store:
            state = await self._ctx.state_store.get(data["job_id"])
            if state and state.current_status == JobStatus.EXECUTION_MONITORING:
                if state.raw_report_artifact_id:
                    await self.transition_and_save(state, JobStatus.EXECUTION_COMPLETE,
                                                   reason="execution completed")
                    pending = self._pending_completed_events.pop(data["job_id"], None)
                    if pending:
                        await self._ctx.broker.publish(Topic.EVENTS_ALL, pending)

    async def handle(self, data: dict) -> None:
        job_id = data["job_id"]
        task_id = data["sandbox_task_id"]
        sandbox_backend = data.get("sandbox_backend", "cape")

        log = logger.bind(job_id=job_id, task_id=task_id)

        if sandbox_backend == "virustotal":
            adapter = self._vt
            if not adapter:
                raise RuntimeError("VirusTotalAdapter not configured in ExecMonitorAgent")
        else:
            adapter = self._cape
            if not adapter:
                raise RuntimeError("CapeAdapter not configured in ExecMonitorAgent")

        start_t = asyncio.get_event_loop().time()
        poll_interval = _POLL_INTERVAL_INITIAL_S
        poll_count = 0

        log.info("monitoring_started", timeout_s=self._timeout_s)

        while True:
            elapsed = asyncio.get_event_loop().time() - start_t

            # ── Timeout check ─────────────────────────────────────────────
            if elapsed >= self._timeout_s:
                log.warning("execution_timeout", elapsed_s=elapsed)
                event = ExecutionFailedEvent(
                    job_id=job_id,
                    sample_id=data["sample_id"],
                    correlation_id=data["correlation_id"],
                    failure_reason="timeout",
                    sandbox_task_id=task_id,
                    sandbox_backend=sandbox_backend,
                )
                await self._ctx.broker.publish(Topic.EVENTS_ALL, event)
                return

            # ── Poll status ───────────────────────────────────────────────
            try:
                status = await adapter.get_task_status(task_id)
                poll_count += 1
                log.debug("poll_result", status=status, poll=poll_count)
            except Exception as exc:
                log.warning("poll_error", error=str(exc))
                await asyncio.sleep(poll_interval)
                continue

            # ── Check for terminal status ─────────────────────────────────
            status_str = str(status).lower()
            if "completed" in status_str or "reported" in status_str:
                break
            if any(x in status_str for x in ("failed", "error", "aborted")):
                log.warning("sandbox_execution_error", status=status)
                event = ExecutionFailedEvent(
                    job_id=job_id,
                    sample_id=data["sample_id"],
                    correlation_id=data["correlation_id"],
                    failure_reason=f"sandbox_error:{status}",
                    sandbox_task_id=task_id,
                    sandbox_backend=sandbox_backend,
                )
                await self._ctx.broker.publish(Topic.EVENTS_ALL, event)
                return

            # ── Back-off ──────────────────────────────────────────────────
            await asyncio.sleep(poll_interval)
            poll_interval = min(poll_interval * _POLL_BACKOFF_FACTOR, _POLL_INTERVAL_MAX_S)

        # ── Fetch final report ────────────────────────────────────────────
        analysis_start = asyncio.get_event_loop().time()
        try:
            raw_report = await adapter.get_report(task_id)
        except Exception as exc:
            log.error("report_fetch_failed", error=str(exc))
            event = ExecutionFailedEvent(
                job_id=job_id,
                sample_id=data["sample_id"],
                correlation_id=data["correlation_id"],
                failure_reason=f"report_fetch_error:{exc}",
                sandbox_task_id=task_id,
                sandbox_backend=sandbox_backend,
            )
            await self._ctx.broker.publish(Topic.EVENTS_ALL, event)
            return

        analysis_duration_s = asyncio.get_event_loop().time() - analysis_start

        # ── Store report artifact ─────────────────────────────────────────
        if self._ctx.artifact_store and raw_report is not None:
            report_data = (
                raw_report.__dict__ if hasattr(raw_report, "__dict__") else raw_report
            )
            artifact_id = await self._ctx.artifact_store.store_json(
                job_id=job_id,
                artifact_type="sandbox_raw_report",
                data=_safe_serialisable(report_data),
            )
        else:
            artifact_id = f"report_{job_id[:8]}"

        event = ExecutionCompletedEvent(
            job_id=job_id,
            sample_id=data["sample_id"],
            correlation_id=data["correlation_id"],
            sandbox_task_id=task_id,
            raw_report_artifact_id=artifact_id,
            analysis_duration_s=round(analysis_duration_s, 2),
            sandbox_backend=sandbox_backend,
        )
        self._pending_completed_events[job_id] = event
        log.info("execution_completed_deferred", artifact_id=artifact_id,
                 duration_s=analysis_duration_s)
        # Persist raw_report_artifact_id so handle_event() can detect completion
        if self._ctx.state_store:
            _state = await self._ctx.state_store.get(job_id)
            if _state:
                _state.raw_report_artifact_id = artifact_id
                # Also poll the original binary submission if one was made
                if _state.original_sandbox_task_id:
                    await self._monitor_original_task(
                        job_id=job_id,
                        task_id=str(_state.original_sandbox_task_id),
                        adapter=adapter,
                        state=_state,
                        log=log,
                    )
                else:
                    await self._ctx.state_store.save(_state)

    async def _monitor_original_task(
        self,
        job_id: str,
        task_id: str,
        adapter,
        state,
        log,
    ) -> None:
        """
        Poll the original binary sandbox task until complete, then store its report.
        Best-effort: failures are logged but do not affect the main job status.
        """
        try:
            timeout = self._timeout_s
            start_t = asyncio.get_event_loop().time()
            poll_interval = _POLL_INTERVAL_INITIAL_S

            while True:
                elapsed = asyncio.get_event_loop().time() - start_t
                if elapsed >= timeout:
                    log.warning("original_task_monitoring_timeout", task_id=task_id)
                    break
                try:
                    status = await adapter.get_task_status(task_id)
                except Exception as exc:
                    log.warning("original_task_poll_error", task_id=task_id, error=str(exc))
                    await asyncio.sleep(poll_interval)
                    poll_interval = min(poll_interval * _POLL_BACKOFF_FACTOR, _POLL_INTERVAL_MAX_S)
                    continue

                status_str = str(status).lower()
                if "completed" in status_str or "reported" in status_str:
                    break
                if any(x in status_str for x in ("failed", "error", "aborted")):
                    log.warning("original_task_sandbox_error", task_id=task_id, status=status)
                    break

                await asyncio.sleep(poll_interval)
                poll_interval = min(poll_interval * _POLL_BACKOFF_FACTOR, _POLL_INTERVAL_MAX_S)

            raw_report = await adapter.get_report(task_id)
            if raw_report is not None and self._ctx.artifact_store:
                report_data = (
                    raw_report.__dict__ if hasattr(raw_report, "__dict__") else raw_report
                )
                orig_artifact_id = await self._ctx.artifact_store.store_json(
                    job_id=job_id,
                    artifact_type="original_sandbox_raw_report",
                    data=_safe_serialisable(report_data),
                )
                state.original_raw_report_artifact_id = orig_artifact_id
                log.info("original_task_report_stored",
                         task_id=task_id, artifact_id=orig_artifact_id)

        except Exception as e:
            log.warning("original_task_monitor_exception", task_id=task_id, error=str(e))
        finally:
            await self._ctx.state_store.save(state)


def _safe_serialisable(obj) -> dict:
    """Best-effort conversion to JSON-safe dict."""
    if isinstance(obj, dict):
        return {k: _safe_serialisable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_safe_serialisable(i) for i in obj]
    if hasattr(obj, "__dict__"):
        return _safe_serialisable(obj.__dict__)
    try:
        import json
        json.dumps(obj)
        return obj
    except TypeError:
        return str(obj)
