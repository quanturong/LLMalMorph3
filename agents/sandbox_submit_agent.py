"""
SandboxSubmitAgent — submits compiled binary to CAPE sandbox.

Input command:  SandboxSubmitCommand
Output event:   SandboxSubmittedEvent
Error event:    ErrorEvent (code SANDBOX_SUBMIT_FAILED, retryable=True)
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import structlog

from broker.topics import Topic
from contracts.job import JobStatus
from contracts.messages import SandboxSubmittedEvent

from .base_agent import BaseAgent

logger = structlog.get_logger(__name__)

# Event signature: BuildValidatedEvent
_SIG_BUILD_VALIDATED = frozenset({"compiled_artifact_id", "binary_sha256", "binary_size_bytes"})


class SandboxSubmitAgent(BaseAgent):
    """
    Submit a compiled binary artifact to the sandbox.

    Self-activates on: BuildValidatedEvent (BUILD_READY → SANDBOX_SUBMITTING)
    """

    agent_name = "SandboxSubmitAgent"
    command_stream = Topic.CMD_SANDBOX_SUBMIT
    consumer_group = Topic.CG_SANDBOX_SUBMIT
    event_consumer_group = Topic.CG_EVENTS_SANDBOX_SUBMIT

    activates_on = {
        _SIG_BUILD_VALIDATED: (JobStatus.BUILD_READY, JobStatus.SANDBOX_SUBMITTING),
    }

    capabilities = {"stage": "sandbox_submit", "backend": "cape+virustotal"}

    def __init__(self, ctx, cape_adapter=None, vt_adapter=None) -> None:
        super().__init__(ctx)
        self._cape = cape_adapter   # adapters.cape_adapter.CapeAdapter
        self._vt = vt_adapter       # adapters.virustotal_adapter.VirusTotalAdapter

    def __init__(self, ctx, cape_adapter=None, vt_adapter=None) -> None:
        super().__init__(ctx)
        self._cape = cape_adapter   # adapters.cape_adapter.CapeAdapter
        self._vt = vt_adapter       # adapters.virustotal_adapter.VirusTotalAdapter
        self._pending_submitted_events: dict = {}

    async def handle_event(self, data: dict, claimed_state) -> None:
        """Extract command data from event + state."""
        job_id = data["job_id"]
        log = logger.bind(job_id=job_id)
        cmd_data = {
            "job_id": job_id,
            "sample_id": data.get("sample_id", ""),
            "correlation_id": data.get("correlation_id", ""),
            "compiled_artifact_id": data.get("compiled_artifact_id", ""),
            "sandbox_backend": claimed_state.sandbox_backend or "cape" if claimed_state else "cape",
            "retry_count": 0,
        }
        try:
            await self.handle(cmd_data)
        except (OSError, FileNotFoundError, RuntimeError) as err:
            log.warning("sandbox_submit_failed_transitioning_to_failed", error=str(err))
            if self._ctx.state_store:
                state = await self._ctx.state_store.get(job_id)
                if state:
                    await self.transition_and_save(state, JobStatus.FAILED,
                                                   reason=f"sandbox_submit_failed: {err}")
            return
        # Transition to SANDBOX_SUBMITTED on success, THEN publish deferred event
        if self._ctx.state_store:
            state = await self._ctx.state_store.get(job_id)
            if state and state.current_status == JobStatus.SANDBOX_SUBMITTING:
                await self.transition_and_save(state, JobStatus.SANDBOX_SUBMITTED,
                                               reason="sandbox submitted")
                # Now publish the deferred SandboxSubmittedEvent (state is now SANDBOX_SUBMITTED)
                pending = self._pending_submitted_events.pop(job_id, None)
                if pending:
                    await self._ctx.broker.publish(Topic.EVENTS_ALL, pending)

    async def handle(self, data: dict) -> None:
        job_id = data["job_id"]
        compiled_artifact_id = data["compiled_artifact_id"]
        retry_count = data.get("retry_count", 0)
        sandbox_backend = data.get("sandbox_backend", "cape")

        log = logger.bind(job_id=job_id, retry_count=retry_count)

        # ── 0. Select backend adapter ─────────────────────────────────
        if sandbox_backend == "virustotal":
            adapter = self._vt
            if not adapter:
                raise RuntimeError("VirusTotalAdapter not configured in SandboxSubmitAgent")
        else:
            adapter = self._cape
            if not adapter:
                raise RuntimeError("CapeAdapter not configured in SandboxSubmitAgent")

        # ── 1. Resolve binary and submit to sandbox ────────────────────────
        # If artifact is encrypted, decrypt in-memory and upload bytes directly
        # to CAPE — no plaintext .exe ever touches disk.
        task_id = None
        binary_abs_path = "(in-memory)"
        store = self._ctx.artifact_store

        if store and hasattr(store, 'decrypt_to_bytes'):
            try:
                pe_bytes = store.decrypt_to_bytes(compiled_artifact_id)
                if pe_bytes and hasattr(adapter, 'submit_bytes'):
                    # Determine original filename for CAPE
                    raw_path = store.get_path_sync(compiled_artifact_id)
                    fname = Path(raw_path).stem + ".exe" if raw_path else "sample.exe"
                    task_id = await adapter.submit_bytes(pe_bytes, filename=fname)
                    binary_abs_path = f"(encrypted:{fname})"
                    log.info("submitted_from_memory", filename=fname, size=len(pe_bytes))
                    del pe_bytes  # release memory immediately
            except Exception as exc:
                log.debug("in_memory_submit_failed_fallback_to_file", error=str(exc))
                task_id = None  # fall through to file-based path

        # Fallback: file-based submit (unencrypted artifacts or adapters without submit_bytes)
        if task_id in (None, "", "None"):
            binary_path: Path | None = None
            if store:
                binary_path = await store.get_path(job_id, compiled_artifact_id)

            if binary_path is None or not binary_path.exists():
                recovered = self._recover_binary_from_build_output(job_id)
                if recovered is not None and recovered.exists():
                    binary_path = recovered
                    log.warning("artifact_missing_recovered_from_build", recovered_path=str(binary_path))
                else:
                    raise FileNotFoundError(
                        f"Compiled binary artifact not found: {compiled_artifact_id}"
                    )

            binary_abs_path = str(binary_path.resolve())
            log.info("submitting_to_sandbox", binary=binary_abs_path)

            # ── 2. Submit file to sandbox (CAPE or VT) ────────────────────
            task_id = await adapter.submit_file(binary_abs_path)
            if task_id in (None, "", "None"):
                # One recovery retry if the artifact disappeared mid-run (e.g., AV quarantine)
                recovered = self._recover_binary_from_build_output(job_id)
                if recovered is not None and recovered.exists():
                    recovered_abs = str(recovered.resolve())
                    if recovered_abs != binary_abs_path:
                        log.warning("retry_submit_with_recovered_binary", recovered_path=recovered_abs)
                        task_id = await adapter.submit_file(recovered_abs)
                        binary_abs_path = recovered_abs

        if task_id in (None, "", "None"):
            raise RuntimeError("Sandbox submit returned empty task_id")
        submit_time = datetime.now(tz=timezone.utc).isoformat()

        log.info("sandbox_submitted", task_id=task_id)

        # ── 3. Emit event ─────────────────────────────────────────────────
        event = SandboxSubmittedEvent(
            job_id=job_id,
            sample_id=data["sample_id"],
            correlation_id=data["correlation_id"],
            sandbox_task_id=str(task_id),
            sandbox_backend=sandbox_backend,
            submit_time=submit_time,
        )
        # Defer event publish — will be emitted after state transitions to SANDBOX_SUBMITTED
        # to prevent ExecMonitorAgent from receiving event before state is ready
        self._pending_submitted_events[job_id] = event
        log.info("sandbox_submit_event_deferred", task_id=task_id)

        # ── 4. Submit original binary for behavioral equivalence (best-effort) ──
        if self._ctx.state_store:
            _state = await self._ctx.state_store.get(job_id)
            if _state and _state.original_compiled_artifact_id:
                await self._submit_original_binary(
                    job_id=job_id,
                    original_compiled_artifact_id=_state.original_compiled_artifact_id,
                    adapter=adapter,
                    state=_state,
                    log=log,
                )

    async def _submit_original_binary(
        self,
        job_id: str,
        original_compiled_artifact_id: str,
        adapter,
        state,
        log,
    ) -> None:
        """Submit the original (unmodified) binary to the sandbox for equivalence checking."""
        try:
            orig_path: Optional[Path] = None
            if self._ctx.artifact_store:
                orig_path = await self._ctx.artifact_store.get_path(
                    job_id, original_compiled_artifact_id
                )
            if orig_path is None or not orig_path.exists():
                orig_path = Path(self._ctx.work_dir) / f"orig_build_{job_id[:8]}"
                if not orig_path.exists():
                    log.warning("original_binary_not_found_skipping_equivalence_submit")
                    return

            orig_task_id = await adapter.submit_file(str(orig_path.resolve()))
            if orig_task_id in (None, "", "None"):
                log.warning("original_sandbox_submit_returned_empty_task_id")
                return

            state.original_sandbox_task_id = str(orig_task_id)
            await self._ctx.state_store.save(state)
            log.info("original_binary_sandbox_submitted", original_task_id=orig_task_id)
        except Exception as e:
            # Non-fatal — equivalence check degrades gracefully
            log.warning("original_binary_submit_exception", error=str(e))

    def _recover_binary_from_build_output(self, job_id: str) -> Optional[Path]:
        """Best-effort recovery when artifact path is missing at submit time."""
        build_dir = Path(self._ctx.work_dir) / f"build_{job_id[:8]}"
        if not build_dir.exists() or not build_dir.is_dir():
            return None

        candidates = sorted(
            build_dir.glob("*.exe"),
            key=lambda p: p.stat().st_mtime if p.exists() else 0,
            reverse=True,
        )
        return candidates[0] if candidates else None
