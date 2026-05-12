"""
BuildValidationAgent — compiles project and attempts auto-fix on errors.

This agent has *autonomous sub-loop* via ProjectAutoFixer:
  it may call LLM multiple times per job to fix compilation errors.

Input command:  BuildValidateCommand
Output events:  BuildValidatedEvent | BuildFailedEvent
"""

from __future__ import annotations

import asyncio
import hashlib
import multiprocessing
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

import structlog

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
_AUTOMATION = _SRC / "automation"
if str(_AUTOMATION) not in sys.path:
    sys.path.insert(0, str(_AUTOMATION))

from project_compiler import ProjectCompiler  # type: ignore
from project_detector import ProjectDetector  # type: ignore
from vendor_classifier import classify_source_file  # type: ignore

from broker.topics import Topic
from contracts.job import JobStatus
from contracts.messages import BuildFailedEvent, BuildValidatedEvent

from .base_agent import BaseAgent

logger = structlog.get_logger(__name__)

# Enhanced retry configuration based on pipeline analysis
_MAX_FIX_ATTEMPTS = 5  # Increased from 3 for better success rate
_PERMISSIVE_RETRY_ATTEMPTS = 2  # Separate permissive mode retries
_MAX_SURGICAL_FIX_ATTEMPTS = 3  # For large files
_VSG_STRATEGY_NAMES = {"variant_source_generator", "vsg", "mutation_vsg"}


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        logger.warning("invalid_int_env", name=name, value=os.environ.get(name), default=default)
        return default


_AUTOFIX_LLM_TIMEOUT_S = _int_env("AUTOFIX_LLM_TIMEOUT_S", 180)
_BUILD_VALIDATION_TIMEOUT_S = _int_env("BUILD_VALIDATION_TIMEOUT_S", 1800)

# Malware-specific compilation patterns
_MALWARE_COMPILE_FLAGS = [
    "/SUBSYSTEM:WINDOWS",  # GUI application
    "/ENTRY:DllMain",      # If DLL
    "/NODEFAULTLIB:msvcrt.lib",  # Avoid runtime conflicts
    "/MANIFEST:NO",        # No manifest for stealth
    "/DEBUG:NONE",         # No debug info
    "/OPT:REF",           # Remove unreferenced code
    "/OPT:ICF",            # Identical COMDAT folding
]


def _resolve_fixer_model() -> str:
    """Resolve the LLM model for auto-fixer from environment.

    Prefers the configured cloud/fixer model over hard-coded legacy defaults.
    Returns a model name suitable for get_llm_provider().
    """
    cloud_url = os.environ.get("CLOUD_URL", "")
    if cloud_url:
        # CLOUD_URL is set -> use the configured fixer/cloud model when available.
        return (
            os.environ.get("FIXER_MODEL")
            or os.environ.get("LLM_CLOUD_MODEL")
            or os.environ.get("CLOUD_MODEL")
            or "devstral-small-2:24b"
        )
    return "deepseek-chat"

# Event signature: VariantGeneratedEvent
_SIG_VARIANT_GENERATED = frozenset({"variant_artifact_id", "num_files_generated", "mutation_artifact_id"})


class BuildValidationAgent(BaseAgent):
    """
    Compile source → auto-fix errors → emit pass/fail.

    Self-activates on: VariantGeneratedEvent (VARIANT_READY → BUILD_VALIDATING)
    Has local 3-tier retry loop (standard → permissive → surgical RAG).
    """

    agent_name = "BuildValidationAgent"
    command_stream = Topic.CMD_BUILD_VALIDATE
    consumer_group = Topic.CG_BUILD_VALIDATE
    event_consumer_group = Topic.CG_EVENTS_BUILD_VALIDATE

    activates_on = {
        _SIG_VARIANT_GENERATED: (JobStatus.VARIANT_READY, JobStatus.BUILD_VALIDATING),
    }

    capabilities = {"stage": "build_validation", "compiler": "msvc", "arch": "x86",
                     "languages": ["c", "cpp", "python", "javascript"]}

    def __init__(self, ctx, fixer_model: str = "") -> None:
        super().__init__(ctx)
        # Stores BuildValidatedEvent keyed by job_id until state transitions to BUILD_READY.
        # Deferred so SandboxSubmitAgent sees BUILD_READY before consuming the event.
        self._pending_validated_events: dict = {}
        self._fixer_model = fixer_model.strip()

    async def handle_event(self, data: dict, claimed_state) -> None:
        """Build command data from event + state."""
        if claimed_state and self._ctx.state_store:
            claimed_state.variant_artifact_id = (
                data.get("variant_artifact_id") or claimed_state.variant_artifact_id
            )
            claimed_state.source_artifact_id = (
                data.get("source_artifact_id") or claimed_state.source_artifact_id
            )
            claimed_state.mutation_artifact_id = (
                data.get("mutation_artifact_id") or claimed_state.mutation_artifact_id
            )
            await self._ctx.state_store.save(claimed_state)

        cmd_data = {
            "job_id": data["job_id"],
            "sample_id": data.get("sample_id", ""),
            "correlation_id": data.get("correlation_id", ""),
            "source_artifact_id": data.get("variant_artifact_id", ""),
            "project_name": data.get("project_name", "")
                            or (claimed_state.project_name if claimed_state else ""),
            "language": data.get("language", "")
                        or (claimed_state.language if claimed_state else "c"),
            "mutation_strategy": (claimed_state.requested_strategies[0]
                                  if claimed_state and claimed_state.requested_strategies else ""),
        }
        await self.handle(cmd_data)
        # Transition based on whether a binary was produced
        if self._ctx.state_store:
            state = await self._ctx.state_store.get(data["job_id"])
            if state and state.current_status == JobStatus.BUILD_VALIDATING:
                if state.compiled_artifact_id:
                    await self.transition_and_save(state, JobStatus.BUILD_READY,
                                                   reason="build validated")
                    # Now that state is BUILD_READY, publish the deferred event so
                    # SandboxSubmitAgent can successfully claim it.
                    pending = self._pending_validated_events.pop(data["job_id"], None)
                    if pending:
                        await self._ctx.broker.publish(Topic.EVENTS_ALL, pending)
                else:
                    await self.transition_and_save(state, JobStatus.BUILD_FAILED,
                                                   reason="build failed - no binary produced")

    async def handle(self, data: dict) -> None:
        job_id = data["job_id"]
        sample_id = data["sample_id"]
        source_artifact_id = data["source_artifact_id"]
        project_name = data.get("project_name", "")
        correlation_id = data["correlation_id"]

        log = logger.bind(job_id=job_id, project=project_name)

        try:
            # ── 1. Retrieve source artifact ───────────────────────────────────
            source_payload = await self._load_artifact(job_id, source_artifact_id, log)
            if source_payload is None:
                error_msg = f"Source artifact not found: {source_artifact_id}"
                log.warning("build_failed_missing_artifact", artifact_id=source_artifact_id)
                await self._emit_build_failed(job_id, sample_id, correlation_id, error_msg)
                return

            # Preserve the original project root. For variant artifacts, the
            # materialization step below rewrites source_payload["source_path"]
            # to a temporary build tree.
            original_source_path = str(source_payload.get("source_path", "") or "")
            source_payload["_original_source_path"] = original_source_path

            # Check if this is a variant artifact with pre-assembled files
            variant_files = source_payload.get("variant_files")
            if variant_files:
                source_path = await self._materialize_variant_files(
                    job_id=job_id,
                    variant_files=variant_files,
                    source_payload=source_payload,
                    log=log,
                )
                if not source_path:
                    error_msg = "Failed to materialize variant files to disk"
                    log.warning("build_failed_materialize", job_id=job_id)
                    await self._emit_build_failed(job_id, sample_id, correlation_id, error_msg)
                    return
                # Inject materialized path back so downstream helpers can use it
                source_payload["source_path"] = source_path
            else:
                source_path = source_payload.get("source_path", "")
                if not source_path or not os.path.exists(source_path):
                    error_msg = f"Source path does not exist: {source_path}"
                    log.warning("build_failed_missing_source", source_path=source_path)
                    await self._emit_build_failed(job_id, sample_id, correlation_id, error_msg)
                    return

            mutation_strategy = (data.get("mutation_strategy") or "").strip().lower()
            if not mutation_strategy:
                requested = source_payload.get("requested_strategies") or []
                if requested:
                    mutation_strategy = str(requested[0]).strip().lower()

            build_source_path = await self._resolve_build_source_path(
                job_id=job_id,
                source_payload=source_payload,
                mutation_strategy=mutation_strategy,
                log=log,
            )

            # ── 1b. Load mutation data for LLM context + final rollback ───────
            # Build a compact list of {original_name, original_body, mutated_body,
            # source_file} for functions that were actually changed. Passed into
            # the build subprocess for mutation-aware LLM prompts; rollback is
            # only used after all LLM tiers have failed.
            mutation_data: list = []
            _mut_aid = source_payload.get("mutation_artifact_id", "")
            if _mut_aid:
                try:
                    _mut_payload = await self._load_artifact(job_id, _mut_aid, log)
                    if _mut_payload:
                        _MAX_BODY_BYTES = 80_000  # skip pathologically large bodies
                        _mut_source_files = [
                            str(_mf.get("source_file", "") or "")
                            for _mf in (_mut_payload.get("mutated_functions") or [])
                            if _mf.get("source_file")
                        ]
                        _mut_root = _infer_mutation_source_root(
                            _mut_source_files,
                            original_source_path,
                        )
                        for _mf in (_mut_payload.get("mutated_functions") or []):
                            _ob = _mf.get("original_body", "")
                            _mb = _mf.get("mutated_body", "")
                            _sf = _mf.get("source_file", "")
                            _fn = _mf.get("original_name", "")
                            if _ob and _mb and _sf and _ob != _mb:
                                if len(_ob) + len(_mb) <= _MAX_BODY_BYTES:
                                    _rel = _relative_source_path(_sf, _mut_root)
                                    mutation_data.append({
                                        "original_name": _fn,
                                        "original_body": _ob,
                                        "mutated_body": _mb,
                                        "source_file": _sf,
                                        "source_relpath": _rel,
                                        "build_file": os.path.normpath(
                                            os.path.join(build_source_path, _rel)
                                        ),
                                    })
                    if mutation_data:
                        log.info("mutation_data_loaded_for_rollback", count=len(mutation_data))
                except Exception as _mde:
                    log.warning("mutation_data_load_failed", error=str(_mde))

            # ── 2. Detect target project + compile ───────────────────────────
            loop = asyncio.get_event_loop()
            detector = ProjectDetector(build_source_path)
            projects = await loop.run_in_executor(None, lambda: detector.detect_projects(recursive=True))
            if not projects:
                error_msg = f"No project detected at {build_source_path}"
                log.warning("build_failed_no_project", build_path=build_source_path)
                await self._emit_build_failed(job_id, sample_id, correlation_id, error_msg)
                return
            
            project_obj = next((p for p in projects if p.name == project_name), projects[0])
            
            # Enhanced malware compilation preparation (C/C++ only)
            project_language = project_obj.get_language()
            if project_language in ('c', 'cpp'):
                await self._prepare_malware_compilation(project_obj, log)
            
            # Setup compilation parameters
            # Use x86 for malware samples (most use 32-bit inline assembly)
            # Smart compiler selection: analyze source to pick MSVC vs GCC
            if project_language in ('c', 'cpp'):
                best_compiler = ProjectCompiler.analyze_best_compiler(project_obj)
            else:
                best_compiler = 'auto'
            compiler = ProjectCompiler(compiler=best_compiler, msvc_arch="x86")
            output_dir = str(Path(self._ctx.work_dir) / f"build_{job_id[:8]}")
            output_name = f"{project_obj.name}_{job_id[:8]}"

            # For Python/JS projects, use simple single-attempt compilation
            # (PyInstaller/pkg don't benefit from MSVC-style fix loops)
            if project_language in ('python', 'javascript'):
                t0 = loop.time()
                compile_result = await loop.run_in_executor(
                    None,
                    lambda: compiler.compile_project(
                        project=project_obj,
                        output_dir=output_dir,
                        output_name=output_name,
                        auto_generate_headers=False,
                    ),
                )
                compilation_time_s = loop.time() - t0
                fix_stats = {"total_attempts": 0}
                auto_fix_attempts = 0
            else:
                # Enhanced compilation with advanced retry logic (C/C++)
                t0 = loop.time()
                source_count = len(getattr(project_obj, "source_files", []) or [])
                effective_build_timeout_s = max(
                    _BUILD_VALIDATION_TIMEOUT_S,
                    min(
                        _int_env("BUILD_VALIDATION_MAX_TIMEOUT_S", 7200),
                        source_count * _int_env("BUILD_VALIDATION_TIMEOUT_PER_FILE_S", 60),
                    ),
                )
                try:
                    compile_result, fix_stats = await loop.run_in_executor(
                        None,
                        lambda: _run_advanced_compile_in_process(
                            project=project_obj,
                            compiler_name=best_compiler,
                            output_dir=output_dir,
                            output_name=output_name,
                            job_id=job_id,
                            sample_id=sample_id,
                            fixer_model=self._fixer_model,
                            timeout_s=effective_build_timeout_s,
                            mutation_data=mutation_data,
                            original_source_path=original_source_path,
                        ),
                    )
                except TimeoutError:
                    error_msg = (
                        f"Build validation timed out after {effective_build_timeout_s}s"
                    )
                    log.warning(
                        "build_validation_timeout",
                        timeout_s=effective_build_timeout_s,
                        source_files=source_count,
                    )
                    await self._emit_build_failed(job_id, sample_id, correlation_id, error_msg)
                    return
                compilation_time_s = loop.time() - t0
                auto_fix_attempts = fix_stats.get("total_attempts", 0)
                fix_stats["compilation_time_s"] = round(compilation_time_s, 3)

                # ── 3b. Per-function rollback if all tiers failed ─────────────
                # When AutoFixer is exhausted and the same file keeps failing
                # (e.g. LLM changed arg types or stripped comment markers),
                # restore original function bodies and retry once.
                if not (compile_result and compile_result.success):
                    rolled_back = await self._try_rollback_mutated_functions(
                        job_id=job_id,
                        source_payload=source_payload,
                        build_source_path=build_source_path,
                        log=log,
                    )
                    if rolled_back > 0:
                        log.info("rollback_retry_start", rolled_back=rolled_back)
                        _fixer_model = self._fixer_model or _resolve_fixer_model()
                        try:
                            post_rollback_patches = self._apply_deterministic_build_normalizers(
                                project_obj,
                                log,
                            )
                            if post_rollback_patches:
                                fix_stats.setdefault("error_categories", []).append(
                                    "rollback_deterministic_normalized"
                                )
                                log.info(
                                    "rollback_deterministic_normalized",
                                    patches=post_rollback_patches,
                                )
                        except Exception as _rb_norm_exc:  # noqa: BLE001
                            log.warning(
                                "rollback_deterministic_normalize_failed",
                                error=str(_rb_norm_exc),
                            )
                        try:
                            rb_result = await loop.run_in_executor(
                                None,
                                lambda: _run_compile_project_in_process(
                                    project=project_obj,
                                    compiler_name=best_compiler,
                                    output_dir=output_dir,
                                    output_name=f"{output_name}_rb",
                                    timeout_s=effective_build_timeout_s,
                                    compile_kwargs={
                                        "max_fix_attempts": 2,
                                        "auto_fix": True,
                                        "llm_model": _fixer_model,
                                        "preserve_function_names": set(),
                                        "auto_generate_headers": False,
                                        "extra_fix_context": _build_mutation_fix_context(
                                            build_source_path,
                                            mutation_data,
                                        ),
                                    },
                                ),
                            )
                            fix_stats["rollback_triggered"] = True
                            fix_stats["rollback_count"] = rolled_back
                            auto_fix_attempts += getattr(rb_result, "auto_fix_attempts", 0)
                            fix_stats["total_attempts"] += getattr(rb_result, "auto_fix_attempts", 0)
                            if rb_result and rb_result.success:
                                compile_result = rb_result
                                log.info("compile_success_after_rollback", rolled_back=rolled_back)
                            else:
                                log.warning("rollback_compile_still_failed")
                        except Exception as _rb_exc:
                            log.warning("rollback_compile_exception", error=str(_rb_exc))

            # ── 4. Emit result event ──────────────────────────────────────────
            if compile_result and compile_result.success:
                exe_path = compile_result.executable_path or ""
                binary_sha256 = ""
                binary_size_bytes = 0
                if exe_path and os.path.exists(exe_path):
                    try:
                        binary_sha256 = await loop.run_in_executor(
                            None, lambda: _sha256_file(exe_path)
                        )
                        binary_size_bytes = os.path.getsize(exe_path)
                    except OSError as hash_err:
                        # AV may quarantine the file immediately; treat as success with no hash
                        log.warning("pe_hash_failed", exe_path=exe_path, error=str(hash_err))
                        binary_sha256 = f"unavailable_{job_id[:8]}"
                        binary_size_bytes = 0

                # Store compiled binary as artifact
                artifact_id = f"binary_{job_id[:8]}"
                if self._ctx.artifact_store and exe_path and os.path.exists(exe_path):
                    try:
                        artifact_id = await self._ctx.artifact_store.store(
                            job_id=job_id,
                            sample_id=sample_id,
                            artifact_type="compiled_binary",
                            source_path=exe_path,
                        )
                    except OSError as store_err:
                        log.warning("artifact_store_failed", exe_path=exe_path, error=str(store_err))

                event = BuildValidatedEvent(
                    job_id=job_id,
                    sample_id=sample_id,
                    correlation_id=correlation_id,
                    compiled_artifact_id=artifact_id,
                    binary_sha256=binary_sha256,
                    binary_size_bytes=binary_size_bytes,
                    compilation_time_s=round(compilation_time_s, 3),
                    auto_fix_iterations=auto_fix_attempts,
                )
                # Defer publish until after transition_and_save(BUILD_READY) so that
                # SandboxSubmitAgent.claim_job(expected=BUILD_READY) succeeds.
                self._pending_validated_events[job_id] = event
                log.info("build_validated", artifact_id=artifact_id, sha256=binary_sha256)
                # Update state store so handle_event() can detect success via compiled_artifact_id
                if self._ctx.state_store:
                    _state = await self._ctx.state_store.get(job_id)
                    if _state:
                        _state.compiled_artifact_id = artifact_id
                        _state.fix_stats = fix_stats
                        # Also compile the original (unmodified) binary for equivalence checking
                        original_source = source_payload.get("source_path", "")
                        if original_source and os.path.exists(original_source):
                            orig_artifact_id = await self._compile_original_binary(
                                job_id=job_id,
                                sample_id=sample_id,
                                source_path=original_source,
                                project_name=project_name,
                                compiler=compiler,
                                loop=loop,
                                log=log,
                            )
                            if orig_artifact_id:
                                _state.original_compiled_artifact_id = orig_artifact_id
                                log.info("original_binary_compiled", artifact_id=orig_artifact_id)
                            else:
                                log.warning("original_binary_compile_failed",
                                            source=original_source)
                        await self._ctx.state_store.save(_state)
            else:
                error_msg = compile_result.errors if compile_result else "Compiler not available"
                
                # Enhanced error reporting with categorization
                error_category = self._categorize_build_error(error_msg)
                detailed_error = self._format_detailed_error(error_msg, fix_stats, error_category)
                
                # Persist fix_stats to state before emitting failure
                if self._ctx.state_store:
                    _state = await self._ctx.state_store.get(job_id)
                    if _state:
                        _state.fix_stats = fix_stats
                        await self._ctx.state_store.save(_state)

                event = BuildFailedEvent(
                    job_id=job_id,
                    sample_id=sample_id,
                    correlation_id=correlation_id,
                    auto_fix_attempts=auto_fix_attempts,
                    error_message=detailed_error[:1000],
                )
                await self._ctx.broker.publish(Topic.EVENTS_ALL, event)
                log.warning(
                    "build_failed_final", 
                    auto_fix_attempts=auto_fix_attempts,
                    error_category=error_category,
                    fix_loop_detected=fix_stats.get("fix_loop_detected", False),
                    rollback_triggered=fix_stats.get("rollback_triggered", False),
                )
                
        except Exception as e:
            error_msg = f"Build validation setup failed: {str(e)}"
            log.error("build_failed_exception", error=str(e))
            await self._emit_build_failed(job_id, sample_id, correlation_id, error_msg)

    async def _load_artifact(self, job_id: str, artifact_id: str, log) -> Optional[dict]:
        if self._ctx.artifact_store:
            return await self._ctx.artifact_store.get_json(job_id, artifact_id)
        return None

    async def _compile_original_binary(
        self,
        job_id: str,
        sample_id: str,
        source_path: str,
        project_name: str,
        compiler,
        loop,
        log,
    ) -> Optional[str]:
        """
        Compile the unmodified original source for behavioral equivalence checking.
        Returns the artifact_id of the original binary, or None on failure.
        The build is best-effort — failures do not abort the main job.
        """
        try:
            detector = ProjectDetector(source_path)
            projects = await loop.run_in_executor(None, lambda: detector.detect_projects(recursive=True))
            if not projects:
                return None
            project_obj = next((p for p in projects if p.name == project_name), projects[0])

            output_dir = str(Path(self._ctx.work_dir) / f"orig_build_{job_id[:8]}")
            output_name = f"{project_obj.name}_orig_{job_id[:8]}"
            result = await loop.run_in_executor(
                None,
                lambda: compiler.compile_project(
                    project=project_obj,
                    output_dir=output_dir,
                    output_name=output_name,
                    auto_generate_headers=False,
                ),
            )
            if not (result and result.success and result.executable_path
                    and os.path.exists(result.executable_path)):
                return None

            artifact_id = f"orig_binary_{job_id[:8]}"
            if self._ctx.artifact_store:
                artifact_id = await self._ctx.artifact_store.store(
                    job_id=job_id,
                    sample_id=sample_id,
                    artifact_type="original_compiled_binary",
                    source_path=result.executable_path,
                )
            return artifact_id
        except Exception as e:
            log.warning("original_compile_exception", error=str(e))
            return None

    async def _materialize_variant_files(
        self,
        job_id: str,
        variant_files: dict[str, str],
        source_payload: dict,
        log,
    ) -> str:
        """Write variant_files dict {rel_path: content} to a temp build directory.

        Also copies non-variant files (headers, project files, resources) from
        the original source directory so that compilation succeeds.
        """
        build_dir = Path(self._ctx.work_dir) / f"variant_build_{job_id[:8]}"
        build_dir.mkdir(parents=True, exist_ok=True)

        # Copy original source tree first (headers, project files, etc.)
        original_source_path = source_payload.get("source_path", "")
        if original_source_path and os.path.isdir(original_source_path):
            shutil.copytree(original_source_path, str(build_dir), dirs_exist_ok=True)
            log.info("original_source_copied", source=original_source_path)

        # Overwrite with mutated variant files
        for rel_path, content in variant_files.items():
            file_path = build_dir / rel_path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content, encoding="utf-8")

        log.info(
            "variant_files_materialized",
            build_dir=str(build_dir),
            num_files=len(variant_files),
        )
        return str(build_dir)

    async def _resolve_build_source_path(
        self,
        job_id: str,
        source_payload: dict,
        mutation_strategy: str,
        log,
    ) -> str:
        source_path = str(source_payload.get("source_path", ""))
        if not mutation_strategy or mutation_strategy not in _VSG_STRATEGY_NAMES:
            return source_path

        variant_file = await self._run_variant_source_generator(source_payload, log)
        if not variant_file:
            log.warning("mutation_variant_fallback_original_source", strategy=mutation_strategy)
            return source_path

        source_root = Path(source_path)
        source_root = source_root if source_root.is_dir() else source_root.parent
        source_root = source_root.resolve()

        mutated_root = (Path(self._ctx.work_dir) / f"mut_src_{job_id[:8]}").resolve()
        shutil.copytree(source_root, mutated_root, dirs_exist_ok=True)

        target_source_file = self._pick_target_source_file(source_payload)
        if target_source_file is None:
            log.warning("mutation_target_file_missing_fallback", strategy=mutation_strategy)
            return source_path

        try:
            rel_target = target_source_file.resolve().relative_to(source_root)
        except ValueError:
            rel_target = Path(target_source_file.name)

        dest_file = mutated_root / rel_target
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(variant_file, dest_file)

        log.info(
            "mutation_variant_applied",
            strategy=mutation_strategy,
            variant_file=str(variant_file),
            destination_file=str(dest_file),
            mutated_source_root=str(mutated_root),
        )
        return str(mutated_root)

    async def _run_variant_source_generator(self, source_payload: dict, log) -> Optional[Path]:
        cached_dir = (
            os.getenv("VSG_CACHED_DIR", "").strip()
            or str(source_payload.get("variant_cached_dir", "")).strip()
        )
        if not cached_dir or not Path(cached_dir).exists():
            log.warning("mutation_cached_dir_missing", cached_dir=cached_dir)
            return None

        target_source_file = self._pick_target_source_file(source_payload)
        if target_source_file is None:
            log.warning("mutation_no_target_source_file")
            return None

        # When num_functions=0 (adaptive mode), use the actual number of mutated
        # functions stored in the payload, falling back to 2.
        _cfg_num = int(source_payload.get("num_functions", 0))
        if _cfg_num > 0:
            num_functions_merge_back = _cfg_num
        else:
            # Try to infer from existing mutation data
            _mutated = source_payload.get("mutated_functions", [])
            num_functions_merge_back = max(1, len(_mutated)) if _mutated else 2
        func_gen_scheme = os.getenv("VSG_FUNC_GEN_SCHEME", "sequential")

        cmd = [
            sys.executable,
            str((_SRC / "variant_source_generator.py").resolve()),
            "--source_code_file_path",
            str(target_source_file),
            "--cached_dir",
            cached_dir,
            "--num_functions_merge_back",
            str(num_functions_merge_back),
            "--func_gen_scheme",
            func_gen_scheme,
        ]

        loop = asyncio.get_event_loop()

        def _invoke_vsg() -> subprocess.CompletedProcess[str]:
            return subprocess.run(cmd, check=False, capture_output=True, text=True)

        proc = await loop.run_in_executor(None, _invoke_vsg)
        if proc.returncode != 0:
            log.warning(
                "mutation_generator_failed",
                return_code=proc.returncode,
                stderr=(proc.stderr or "")[:1000],
            )
            return None

        variant_root = Path(cached_dir) / "variant_source_code" / func_gen_scheme
        if not variant_root.exists():
            log.warning("mutation_variant_output_missing", variant_root=str(variant_root))
            return None

        original_name = target_source_file.name
        same_name_candidates = sorted(
            variant_root.rglob(f"*{target_source_file.suffix}"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for cand in same_name_candidates:
            if original_name.split(".")[0] in cand.name:
                return cand

        return same_name_candidates[0] if same_name_candidates else None

    def _pick_target_source_file(self, source_payload: dict) -> Optional[Path]:
        source_path = Path(str(source_payload.get("source_path", "")))
        source_files = source_payload.get("source_files") or []
        _ALL_SOURCE_EXTS = {".c", ".cpp", ".cc", ".cxx", ".py", ".js", ".mjs"}
        if source_files:
            for file_path in source_files:
                p = Path(str(file_path))
                if p.exists() and p.suffix.lower() in _ALL_SOURCE_EXTS:
                    return p

        if source_path.is_file() and source_path.suffix.lower() in _ALL_SOURCE_EXTS:
            return source_path

        if source_path.is_dir():
            for pattern in ("*.c", "*.cpp", "*.cc", "*.cxx", "*.py", "*.js", "*.mjs"):
                found = list(source_path.rglob(pattern))
                if found:
                    return found[0]
        return None

    def _compile_with_advanced_retry(
        self,
        compiler: ProjectCompiler,
        project,
        output_dir: str,
        output_name: str,
        job_id: str,
        sample_id: str,
        log,
        fixer_model: str = "",
        mutation_data: list = None,
        original_source_path: str = "",
    ) -> tuple[Optional[object], dict]:
        """
        Advanced compilation with three-tier retry strategy:
        1. Standard compilation with auto-fix
        2. Permissive mode retry
        3. Surgical fix for large files
        4. Final targeted rollback after all LLM tiers fail
        
        Returns (compile_result, fix_stats)
        """
        os.environ.setdefault("AUTOFIX_LLM_TIMEOUT_S", str(_AUTOFIX_LLM_TIMEOUT_S))
        auto_generate_project_headers = (
            os.getenv("AUTO_GENERATE_PROJECT_HEADERS", "0").strip().lower()
            in {"1", "true", "yes", "on"}
        )

        fix_stats = {
            "total_attempts": 0,
            "standard_attempts": 0,
            "permissive_attempts": 0,
            "surgical_attempts": 0,
            "fix_loop_detected": False,
            "rollback_triggered": False,
            "error_categories": [],
            "initial_error_count": 0,
            "final_error_count": 0,
        }

        last_result = None  # Track last compile result for error counts

        # If source scan detected x86 inline asm, rebuild compiler as x86
        if getattr(project, '_requires_x86', False):
            log.info("compiler_switched_x86", reason="x86_inline_asm_detected")
            compiler = ProjectCompiler(compiler="auto", msvc_arch="x86")

        # ── Build the AutoFixer "preserve" whitelist from the ORIGINAL source.
        # Any function defined in the input project must survive the autofixer;
        # this stops the LLM from "fixing" a build error by deleting the
        # offending function. Read once, reuse for all retry tiers.
        preserve_funcs: set = set()
        try:
            from src.automation.semantic_validator import get_semantic_validator
            sv = get_semantic_validator()
            if sv and sv.available:
                _vendor_whitelist_skipped = 0
                for sf in getattr(project, 'source_files', []) or []:
                    _classification = classify_source_file(sf, read_content=False)
                    if _classification.is_vendor:
                        _vendor_whitelist_skipped += 1
                        continue
                    try:
                        with open(sf, 'r', encoding='utf-8', errors='ignore') as _fh:
                            _src = _fh.read()
                    except OSError:
                        continue
                    _ext = os.path.splitext(sf)[1].lower()
                    _lang = 'cpp' if _ext in ('.cpp', '.cc', '.cxx', '.hpp') else 'c'
                    preserve_funcs.update(sv.extract_function_names(_src, _lang))
                # Defensive: never whitelist 'main' (legitimate WinMain/main rewrites).
                preserve_funcs.discard('main')
                if preserve_funcs:
                    log.info(
                        "autofix_whitelist_built",
                        n_functions=len(preserve_funcs),
                        vendor_files_skipped=_vendor_whitelist_skipped,
                    )
                elif _vendor_whitelist_skipped:
                    log.info(
                        "autofix_whitelist_empty_after_vendor_filter",
                        vendor_files_skipped=_vendor_whitelist_skipped,
                    )
        except Exception as e:  # noqa: BLE001 — best-effort, never fail build
            log.warning("autofix_whitelist_build_failed", error=str(e))

        # Stricter line-loss cap for production runs (was 0.30 default).
        _autofix_min_line_ratio = float(
            os.environ.get("AUTOFIX_MIN_LINE_RATIO", "0.65")
        )
        _autofix_max_deleted = int(
            os.environ.get("AUTOFIX_MAX_DELETED_FUNCTIONS", "1")
        )

        # ── Pre-fix: deterministic missing-header patcher ────────────────────
        # Scan for C3861 "identifier not found" caused by dead API injection
        # (strat_2) referencing APIs whose headers aren't included.  Fix by
        # injecting #include + #pragma comment(lib, ...) into the affected
        # source files — zero LLM calls, zero retries wasted.
        try:
            patched = self._patch_missing_headers_deterministic(project, log)
            if patched:
                log.info("prefix_header_patch_applied", files_patched=patched)
                fix_stats["error_categories"].append("missing_headers_autopatched")
        except Exception as _ph_exc:
            log.warning("prefix_header_patch_failed", error=str(_ph_exc))

        try:
            guarded = self._patch_missing_include_guards(project, log)
            if guarded:
                fix_stats["error_categories"].append("missing_include_guards_patched")
        except Exception as _ig_exc:
            log.warning("missing_include_guard_patch_failed", error=str(_ig_exc))

        try:
            local_includes = self._patch_missing_local_includes(project, original_source_path, log)
            if local_includes:
                fix_stats["error_categories"].append("missing_local_includes_restored")
        except Exception as _li_exc:
            log.warning("missing_local_include_patch_failed", error=str(_li_exc))

        try:
            parent_includes = self._normalize_parent_local_includes(project, log)
            if parent_includes:
                fix_stats["error_categories"].append("parent_local_includes_normalized")
        except Exception as _pi_exc:
            log.warning("parent_local_include_normalize_failed", error=str(_pi_exc))

        try:
            normalized = self._normalize_generated_forward_declarations(project, log)
            if normalized:
                fix_stats["error_categories"].append("generated_forward_decls_normalized")
        except Exception as _fd_exc:
            log.warning("generated_forward_declarations_normalize_failed", error=str(_fd_exc))

        try:
            relocated = self._normalize_generated_declaration_includes(project, log)
            if relocated:
                fix_stats["error_categories"].append("generated_decl_includes_relocated")
        except Exception as _gi_exc:
            log.warning("generated_declaration_include_relocate_failed", error=str(_gi_exc))

        try:
            deduped = self._dedupe_typedef_blocks(project, log)
            if deduped:
                fix_stats["error_categories"].append("duplicate_typedef_blocks_removed")
        except Exception as _td_exc:
            log.warning("duplicate_typedef_block_remove_failed", error=str(_td_exc))

        try:
            sdk_aliases = self._normalize_sdk_tag_alias_typedefs(project, log)
            if sdk_aliases:
                fix_stats["error_categories"].append("sdk_tag_alias_typedefs_normalized")
        except Exception as _sa_exc:
            log.warning("sdk_tag_alias_typedef_normalize_failed", error=str(_sa_exc))

        try:
            shadowed = self._normalize_sdk_symbol_shadowing(project, log)
            if shadowed:
                fix_stats["error_categories"].append("sdk_symbol_shadowing_normalized")
        except Exception as _ss_exc:
            log.warning("sdk_symbol_shadowing_normalize_failed", error=str(_ss_exc))

        try:
            nt_conflicts = self._normalize_nt_header_local_conflicts(project, log)
            if nt_conflicts:
                fix_stats["error_categories"].append("nt_header_local_conflicts_normalized")
        except Exception as _nt_exc:
            log.warning("nt_header_local_conflict_normalize_failed", error=str(_nt_exc))

        try:
            mingw_shadowed = self._neutralize_mingw_sdk_shadow_headers(project, log)
            if mingw_shadowed:
                fix_stats["error_categories"].append("mingw_sdk_shadow_headers_neutralized")
        except Exception as _mw_exc:
            log.warning("mingw_sdk_shadow_header_normalize_failed", error=str(_mw_exc))

        try:
            corecrt_headers = self._normalize_missing_corecrt_headers(project, log)
            if corecrt_headers:
                fix_stats["error_categories"].append("corecrt_headers_normalized")
        except Exception as _ch_exc:
            log.warning("corecrt_header_normalize_failed", error=str(_ch_exc))

        try:
            sdk_typedefs = self._normalize_sdk_typedef_redefinitions(project, log)
            if sdk_typedefs:
                fix_stats["error_categories"].append("sdk_typedef_redefinitions_normalized")
        except Exception as _tr_exc:
            log.warning("sdk_typedef_redefinition_normalize_failed", error=str(_tr_exc))

        try:
            local_redecls = self._normalize_conflicting_local_redeclarations(project, log)
            if local_redecls:
                fix_stats["error_categories"].append("conflicting_local_redeclarations_removed")
        except Exception as _lr_exc:
            log.warning("conflicting_local_redeclaration_normalize_failed", error=str(_lr_exc))

        try:
            extra_braces = self._normalize_extra_file_scope_closing_braces(project, log)
            if extra_braces:
                fix_stats["error_categories"].append("extra_file_scope_braces_removed")
        except Exception as _eb_exc:
            log.warning("extra_file_scope_brace_normalize_failed", error=str(_eb_exc))

        try:
            scoped_strings = self._normalize_generated_string_scope_blocks(project, log)
            if scoped_strings:
                fix_stats["error_categories"].append("generated_string_scopes_normalized")
        except Exception as _gs_exc:
            log.warning("generated_string_scope_normalize_failed", error=str(_gs_exc))

        try:
            win_macros = self._normalize_legacy_windows_version_macros(project, log)
            if win_macros:
                fix_stats["error_categories"].append("legacy_windows_macros_normalized")
        except Exception as _wm_exc:
            log.warning("legacy_windows_macro_normalize_failed", error=str(_wm_exc))

        try:
            nt_peb = self._normalize_nt_peb_fallback_types(project, log)
            if nt_peb:
                fix_stats["error_categories"].append("nt_peb_fallback_types_added")
        except Exception as _np_exc:
            log.warning("nt_peb_fallback_type_normalize_failed", error=str(_np_exc))

        try:
            localized_dups = self._localize_duplicate_global_symbols(project, log)
            if localized_dups:
                fix_stats["error_categories"].append("duplicate_global_symbols_localized")
        except Exception as _dg_exc:
            log.warning("duplicate_global_symbol_localize_failed", error=str(_dg_exc))

        _fixer_model = (fixer_model or _resolve_fixer_model()).strip()
        log.info("autofix_model_selected", model=_fixer_model)
        _mutation_fix_context = _build_mutation_fix_context(
            getattr(project, "root_dir", ""),
            mutation_data or [],
        )
        if _mutation_fix_context:
            log.info("mutation_fix_context_enabled", functions=len(mutation_data or []))

        # Tier 1: Standard compilation with auto-fix
        log.info("compile_attempt_standard", attempt=1)
        try:
            result = compiler.compile_project(
                project=project,
                output_dir=output_dir,
                output_name=output_name,
                max_fix_attempts=_MAX_FIX_ATTEMPTS,
                auto_fix=True,
                llm_model=_fixer_model,
                preserve_function_names=preserve_funcs,
                autofix_min_line_ratio=_autofix_min_line_ratio,
                autofix_max_deleted_functions=_autofix_max_deleted,
                extra_fix_context=_mutation_fix_context,
                auto_generate_headers=auto_generate_project_headers,
            )
            fix_stats["total_attempts"] += getattr(result, "auto_fix_attempts", 0)
            fix_stats["standard_attempts"] += getattr(result, "auto_fix_attempts", 0)
            last_result = result
            if fix_stats["initial_error_count"] == 0 and result and result.errors:
                fix_stats["initial_error_count"] = result.errors.count("error")
            
            if result and result.success:
                log.info("compile_success_standard")
                fix_stats["final_error_count"] = 0
                return result, fix_stats
                
        except Exception as e:
            log.warning("compile_exception_standard", error=str(e))
            fix_stats["error_categories"].append("exception_standard")

        if last_result and not getattr(last_result, "success", False):
            try:
                deterministic_patches = self._apply_deterministic_build_normalizers(project, log)
                if deterministic_patches:
                    fix_stats["error_categories"].append("post_autofix_deterministic_normalized")
                    log.info(
                        "compile_attempt_post_autofix_deterministic",
                        patches=deterministic_patches,
                    )
                    result = compiler.compile_project(
                        project=project,
                        output_dir=output_dir,
                        output_name=f"{output_name}_deterministic",
                        max_fix_attempts=0,
                        auto_fix=False,
                        preserve_function_names=preserve_funcs,
                        auto_generate_headers=auto_generate_project_headers,
                    )
                    last_result = result
                    if result and result.success:
                        log.info("compile_success_post_autofix_deterministic")
                        fix_stats["final_error_count"] = 0
                        return result, fix_stats
            except Exception as _pd_exc:
                log.warning("post_autofix_deterministic_retry_failed", error=str(_pd_exc))

        # Deterministic dynamic header retry: use the compiler's own missing
        # identifier diagnostics to look up SDK headers, then recompile once
        # before spending permissive/surgical attempts.
        if last_result and not getattr(last_result, "success", False):
            missing_symbols = self._extract_missing_header_symbols(
                "\n".join([
                    str(getattr(last_result, "errors", "") or ""),
                    str(getattr(last_result, "output", "") or ""),
                ])
            )
            if missing_symbols:
                try:
                    patched = self._patch_missing_headers_deterministic(
                        project,
                        log,
                        candidate_symbols=missing_symbols,
                    )
                    if patched:
                        log.info(
                            "dynamic_missing_header_retry",
                            files_patched=patched,
                            symbols=sorted(missing_symbols)[:20],
                        )
                        fix_stats["error_categories"].append("dynamic_missing_headers_autopatched")
                        result = compiler.compile_project(
                            project=project,
                            output_dir=output_dir,
                            output_name=f"{output_name}_headers",
                            max_fix_attempts=1,
                            auto_fix=True,
                            llm_model=_fixer_model,
                            preserve_function_names=preserve_funcs,
                            autofix_min_line_ratio=_autofix_min_line_ratio,
                            autofix_max_deleted_functions=_autofix_max_deleted,
                            extra_fix_context=_mutation_fix_context,
                            auto_generate_headers=auto_generate_project_headers,
                        )
                        fix_stats["total_attempts"] += getattr(result, "auto_fix_attempts", 0)
                        fix_stats["standard_attempts"] += getattr(result, "auto_fix_attempts", 0)
                        last_result = result
                        if result and result.success:
                            log.info("compile_success_after_dynamic_header_patch")
                            fix_stats["final_error_count"] = 0
                            return result, fix_stats
                except Exception as hdr_retry_exc:  # noqa: BLE001
                    log.warning("dynamic_missing_header_retry_failed", error=str(hdr_retry_exc))

        # Tier 2: Permissive mode retry
        log.info("compile_attempt_permissive", attempts=_PERMISSIVE_RETRY_ATTEMPTS)
        for perm_attempt in range(_PERMISSIVE_RETRY_ATTEMPTS):
            try:
                # Enable permissive compilation flags
                result = compiler.compile_project(
                    project=project,
                    output_dir=output_dir,
                    output_name=f"{output_name}_perm_{perm_attempt}",
                    max_fix_attempts=2,
                    auto_fix=True,
                    permissive_mode=True,
                    llm_model=_fixer_model,
                    preserve_function_names=preserve_funcs,
                    autofix_min_line_ratio=_autofix_min_line_ratio,
                    autofix_max_deleted_functions=_autofix_max_deleted,
                    extra_fix_context=_mutation_fix_context,
                    auto_generate_headers=auto_generate_project_headers,
                )
                fix_stats["total_attempts"] += getattr(result, "auto_fix_attempts", 0)
                fix_stats["permissive_attempts"] += getattr(result, "auto_fix_attempts", 0)
                last_result = result
                
                if result and result.success:
                    log.info("compile_success_permissive", attempt=perm_attempt + 1)
                    fix_stats["final_error_count"] = 0
                    return result, fix_stats
                    
            except Exception as e:
                log.warning(
                    "compile_exception_permissive", 
                    attempt=perm_attempt + 1,
                    error=str(e)
                )
                fix_stats["error_categories"].append(f"exception_permissive_{perm_attempt}")

        # Tier 3: Surgical fix with RAG (Fix History retrieval)
        log.info("compile_attempt_surgical_rag", attempts=_MAX_SURGICAL_FIX_ATTEMPTS)
        try:
            # Force surgical mode by setting max_code_length=1
            # RAG (Fix History) is auto-enabled via fix_history_path in compile_project
            result = compiler.compile_project(
                project=project,
                output_dir=output_dir,
                output_name=f"{output_name}_surgical",
                max_fix_attempts=_MAX_SURGICAL_FIX_ATTEMPTS,
                auto_fix=True,
                llm_fixer_max_code_length=1,  # Force surgical mode on all files
                llm_model=_fixer_model,
                preserve_function_names=preserve_funcs,
                autofix_min_line_ratio=_autofix_min_line_ratio,
                autofix_max_deleted_functions=_autofix_max_deleted,
                extra_fix_context=_mutation_fix_context,
                auto_generate_headers=auto_generate_project_headers,
            )
            fix_stats["total_attempts"] += getattr(result, "auto_fix_attempts", 0)
            fix_stats["surgical_attempts"] += getattr(result, "auto_fix_attempts", 0)
            last_result = result
            
            if result and result.success:
                log.info("compile_success_surgical_rag")
                fix_stats["final_error_count"] = 0
                return result, fix_stats
                    
        except Exception as e:
            log.warning("compile_exception_surgical", error=str(e))
            fix_stats["error_categories"].append("exception_surgical")

        # ── Targeted rollback: all LLM tiers exhausted ───────────────────────
        # Roll back only the mutated functions whose files still have errors.
        # More surgical than full rollback — other mutations survive.
        if mutation_data:
            try:
                _rb_probe = last_result or compiler.compile_project(
                    project=project,
                    output_dir=output_dir + "_rbprobe",
                    output_name=output_name + "_rbprobe",
                    max_fix_attempts=0,
                    auto_fix=False,
                    auto_generate_headers=auto_generate_project_headers,
                )
                error_files = _extract_error_files(_rb_probe) if _rb_probe else set()
                if error_files:
                    rolled = _apply_targeted_rollback(
                        project.root_dir,
                        original_source_path,
                        mutation_data,
                        error_files,
                        log,
                    )
                    if rolled > 0:
                        fix_stats["targeted_rollback_count"] = rolled
                        log.info(
                            "targeted_rollback_post_llm",
                            count=rolled,
                            error_files=len(error_files),
                        )
                        post_rb_patches = self._apply_deterministic_build_normalizers(project, log)
                        if post_rb_patches:
                            fix_stats["error_categories"].append("targeted_rollback_deterministic_normalized")
                        try:
                            rb_missing = self._extract_missing_header_symbols(
                                "\n".join([
                                    str(getattr(last_result, "errors", "") or ""),
                                    str(getattr(last_result, "output", "") or ""),
                                ])
                            )
                            patched = self._patch_missing_headers_deterministic(
                                project,
                                log,
                                candidate_symbols=rb_missing,
                            )
                            if patched:
                                fix_stats["error_categories"].append("rollback_missing_headers_autopatched")
                                log.info(
                                    "rollback_missing_headers_patched",
                                    files_patched=patched,
                                    symbols=sorted(rb_missing)[:20],
                                )
                        except Exception as _rb_hdr_exc:  # noqa: BLE001
                            log.warning("rollback_missing_header_patch_failed", error=str(_rb_hdr_exc))

                        rb_result = compiler.compile_project(
                            project=project,
                            output_dir=output_dir + "_rb",
                            output_name=output_name + "_rb",
                            max_fix_attempts=0,
                            auto_fix=False,
                            auto_generate_headers=auto_generate_project_headers,
                        )
                        if rb_result and rb_result.success:
                            fix_stats["targeted_rollback_success"] = True
                            log.info("compile_success_targeted_rollback")
                            return rb_result, fix_stats
                        last_result = rb_result
            except Exception as _rb_exc:
                log.warning("targeted_rollback_error", error=str(_rb_exc))

        # Final attempt: Return last result (never None — None produces misleading 'Compiler not available' message)
        if last_result and last_result.errors:
            fix_stats["final_error_count"] = last_result.errors.count("error")
        log.warning("compile_failed_all_tiers", fix_stats=fix_stats)
        return last_result, fix_stats

    async def _prepare_malware_compilation(self, project, log):
        """
        Prepare malware-specific compilation settings.
        Apply permissive flags and disable security features.
        Also performs pre-compilation source scanning to detect legacy code
        patterns (x86 inline asm, K&R syntax, C89 implicit int, CRT conflict)
        and adjusts compiler flags before the first attempt.
        """
        try:
            # Add malware-specific compilation flags
            if hasattr(project, 'compile_flags'):
                if not project.compile_flags:
                    project.compile_flags = []
                project.compile_flags.extend(_MALWARE_COMPILE_FLAGS)
            
            # Disable security features that might interfere
            if hasattr(project, 'security_flags'):
                project.security_flags = False
                
            # Set permissive mode for known problematic patterns
            if hasattr(project, 'permissive_mode'):
                project.permissive_mode = True

            # ── Pre-compilation source scan for legacy malware patterns ────────
            detected = await self._scan_source_legacy_patterns(project, log)

            if detected.get("x86_inline_asm"):
                # __asm / _emit requires 32-bit target — switch ProjectCompiler to x86
                if hasattr(project, 'target_arch'):
                    project.target_arch = "x86"
                # Tag so _compile_with_advanced_retry can rebuild compiler with x86
                project._requires_x86 = True
                log.warning(
                    "legacy_pattern_x86_inline_asm",
                    note="Switching compiler target to x86 (32-bit) for __asm/_emit code",
                )

            if detected.get("implicit_int_c89"):
                # Force C compilation with /TC + suppress implicit-int warnings
                _extra = ["/TC", "/wd4430", "/wd4431"]
                if hasattr(project, 'compile_flags'):
                    project.compile_flags.extend(_extra)
                project._extra_compile_flags = getattr(project, '_extra_compile_flags', []) + _extra
                log.warning(
                    "legacy_pattern_implicit_int_c89",
                    note="Detected C89 implicit-int style; added /TC /wd4430 /wd4431",
                )

            if detected.get("krc_function_syntax"):
                # K&R param lists: compile as C89/90 with /TC + /w (ignore K&R warnings)
                _extra = ["/TC", "/w"]
                if hasattr(project, 'compile_flags'):
                    project.compile_flags.extend(_extra)
                project._extra_compile_flags = getattr(project, '_extra_compile_flags', []) + _extra
                log.warning(
                    "legacy_pattern_krc_syntax",
                    note="Detected K&R old-style parameter declarations; added /TC /w",
                )

            if detected.get("crt_linkage_conflict"):
                # Mixed CRT: remove /MT, use /MD (dynamic CRT) + ignore LNK4098
                if hasattr(project, 'compile_flags'):
                    project.compile_flags = [
                        f for f in project.compile_flags
                        if f not in ("/MT", "/MTd", "/MT ", "/MTd ")
                    ]
                    project.compile_flags.extend(["/MD", "/IGNORE:4098"])
                project._crt_dynamic = True
                log.warning(
                    "legacy_pattern_crt_conflict",
                    note="Detected CRT linkage conflict; switched to /MD (dynamic CRT)",
                )
            
            log.info(
                "malware_compilation_prepared",
                flags_added=len(_MALWARE_COMPILE_FLAGS),
                permissive_mode=True,
                legacy_patterns_detected=detected,
            )
            
        except Exception as e:
            log.warning("malware_compilation_prep_failed", error=str(e))

    async def _scan_source_legacy_patterns(self, project, log) -> dict:
        """
        Scan source files for legacy code patterns that require special compiler
        flags or architecture switches:
          - x86_inline_asm : __asm / _emit keywords → need x86 target
          - implicit_int_c89: function definitions with no return type → /TC /wd4430
          - krc_function_syntax: K&R parameter list style → /TC /w
          - crt_linkage_conflict: mixed CRT indicators → /MD
        """
        import re

        patterns = {
            # __asm { ... } or _emit  — x86-only inline assembly
            "x86_inline_asm": re.compile(
                r'\b(__asm\b|_emit\b)',
                re.IGNORECASE,
            ),
            # C89 implicit int: function defined without return type
            # e.g. "foo(int x) {" at file scope
            "implicit_int_c89": re.compile(
                r'^\s*[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*\)\s*\{',
                re.MULTILINE,
            ),
            # K&R: parameter name list followed by type declarations before '{'
            # e.g.  "foo(a, b)\n  int a;\n  char *b;\n{"
            "krc_function_syntax": re.compile(
                r'\)\s*\n(?:\s*[A-Za-z_][A-Za-z0-9_ *]*\s+[A-Za-z_][A-Za-z0-9_]*\s*;\s*\n)+\s*\{',
                re.MULTILINE,
            ),
            # CRT conflict indicator: manual CRT routine declarations that clash
            "crt_linkage_conflict": re.compile(
                r'int\s+strcmp\s*\(|extern\s+int\s+strcmp\s*\(|int\s+strlen\s*\(',
                re.IGNORECASE,
            ),
        }

        detected: dict[str, bool] = {k: False for k in patterns}
        source_files = getattr(project, 'source_files', []) or []

        loop = asyncio.get_event_loop()

        def _scan_files():
            results: dict[str, bool] = {k: False for k in patterns}
            for sf in source_files:
                path = str(sf) if not isinstance(sf, str) else sf
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                    for key, rx in patterns.items():
                        if not results[key] and rx.search(content):
                            results[key] = True
                except OSError:
                    pass
            return results

        try:
            detected = await loop.run_in_executor(None, _scan_files)
        except Exception as scan_err:
            log.warning("source_scan_failed", error=str(scan_err))

        if any(detected.values()):
            log.info("source_scan_results", **detected)
        return detected

    def _categorize_build_error(self, error_message: str) -> str:
        """Categorize build errors for better analysis and retry strategy."""
        if not error_message:
            return "unknown"
            
        error_lower = error_message.lower()

        # ── Legacy malware source patterns (check first — most actionable) ──
        # x86 inline assembly: __asm / _emit not supported on x64 target
        if ("c4235" in error_lower or
                ("__asm" in error_lower and "x64" in error_lower) or
                ("_emit" in error_lower and ("c2415" in error_lower or "c4235" in error_lower)) or
                "inline assembly not supported" in error_lower):
            return "x86_inline_asm"

        # C89 implicit int: missing type specifier (MSVC C4430)
        if ("c4430" in error_lower or
                "c4431" in error_lower or
                "missing type specifier" in error_lower):
            return "implicit_int_c89"

        # K&R old-style function parameter declarations
        if ("c2085" in error_lower or
                "not in formal parameter list" in error_lower or
                "old-style parameter declaration" in error_lower):
            return "krc_function_syntax"

        # CRT linkage conflict: mixed runtime / strcmp unresolved
        if ("lnk4098" in error_lower or
                ("lnk2019" in error_lower and any(sym in error_lower
                 for sym in ("strcmp", "strlen", "memcpy", "__acrt", "_crt"))) or
                ("already defined" in error_lower and
                 any(lib in error_lower for lib in ("libcmt", "msvcrt")))):
            return "crt_linkage_conflict"

        # ── Generic patterns ──────────────────────────────────────────────────
        # Malware-specific patterns
        if any(pattern in error_lower for pattern in [
            "access denied", "permission denied", "virus", "malware", "threat"
        ]):
            return "security_blocked"
            
        # Missing dependencies  
        if any(pattern in error_lower for pattern in [
            "no such file", "cannot find", "undefined reference", "unresolved external"
        ]):
            return "missing_dependency"
            
        # Syntax/parsing errors
        if any(pattern in error_lower for pattern in [
            "syntax error", "parse error", "expected", "unexpected token"
        ]):
            return "syntax_error"
            
        # Compiler/toolchain issues
        if any(pattern in error_lower for pattern in [
            "compiler not found", "cl.exe", "gcc", "toolchain"
        ]):
            return "toolchain_error"
            
        # Memory/resource issues
        if any(pattern in error_lower for pattern in [
            "out of memory", "stack overflow", "heap", "allocation failed"
        ]):
            return "resource_error"
            
        # Version/compatibility issues
        if any(pattern in error_lower for pattern in [
            "version", "incompatible", "deprecated", "obsolete"
        ]):
            return "compatibility_error"
            
        return "compilation_error"

    # ── Known-API → (header_to_include, pragma_lib_or_None) mapping ──────────
    # Only APIs that strat_2 / strat_5 dead-code injection might use.
    # All entries here are deterministically fixable: just add the #include.
    _MISSING_HEADER_MAP: dict[str, tuple[str, str | None]] = {
        # WinInet (strat_2 legacy pool — prompt updated but old runs may exist)
        "InternetOpenA":        ("<wininet.h>",  "wininet.lib"),
        "InternetOpenW":        ("<wininet.h>",  "wininet.lib"),
        "InternetConnectA":     ("<wininet.h>",  "wininet.lib"),
        "InternetConnectW":     ("<wininet.h>",  "wininet.lib"),
        "HttpOpenRequestA":     ("<wininet.h>",  "wininet.lib"),
        "HttpSendRequestA":     ("<wininet.h>",  "wininet.lib"),
        "InternetReadFile":     ("<wininet.h>",  "wininet.lib"),
        "InternetCloseHandle":  ("<wininet.h>",  "wininet.lib"),
        "InternetOpenUrlA":     ("<wininet.h>",  "wininet.lib"),
        "InternetOpenUrlW":     ("<wininet.h>",  "wininet.lib"),
        # Urlmon
        "URLDownloadToFileA":   ("<urlmon.h>",   "urlmon.lib"),
        "URLDownloadToFileW":   ("<urlmon.h>",   "urlmon.lib"),
        # TlHelp32 (if not already included)
        "CreateToolhelp32Snapshot": ("<tlhelp32.h>", None),
        "Process32First":       ("<tlhelp32.h>", None),
        "Process32Next":        ("<tlhelp32.h>", None),
        "Thread32First":        ("<tlhelp32.h>", None),
        "Thread32Next":         ("<tlhelp32.h>", None),
        # ShellAPI (usually pulled by shlobj.h but not always)
        "ShellExecute":         ("<shellapi.h>", "shell32.lib"),
        "ShellExecuteA":        ("<shellapi.h>", "shell32.lib"),
        "ShellExecuteW":        ("<shellapi.h>", "shell32.lib"),
        "ShellExecuteEx":       ("<shellapi.h>", "shell32.lib"),
        "ShellExecuteExA":      ("<shellapi.h>", "shell32.lib"),
        "ShellExecuteExW":      ("<shellapi.h>", "shell32.lib"),
        "SHELLEXECUTEINFO":     ("<shellapi.h>", "shell32.lib"),
        "SHELLEXECUTEINFOA":    ("<shellapi.h>", "shell32.lib"),
        "SHELLEXECUTEINFOW":    ("<shellapi.h>", "shell32.lib"),
        # Wintrust
        "WinVerifyTrust":       ("<wintrust.h>", "wintrust.lib"),
        # Psapi
        "EnumProcesses":        ("<psapi.h>",    "psapi.lib"),
        "GetModuleFileNameExA": ("<psapi.h>",    "psapi.lib"),
        # Ntdll / winternl
        "NtQueryInformationProcess": ("<winternl.h>", None),
    }

    def _patch_missing_include_guards(self, project, log) -> int:
        """
        Add include guards to project headers that have none.

        Legacy projects can include the same physical header through multiple
        relative paths. If the header lacks a guard, the pipeline's copied build
        tree can expose duplicate typedef/default-argument errors even though a
        hand-built baseline happened to pass. This is generic and local to the
        header content; set AUTO_PATCH_HEADER_GUARDS=0 to disable.
        """
        if os.getenv("AUTO_PATCH_HEADER_GUARDS", "1").strip().lower() in {"0", "false", "no", "off"}:
            return 0

        header_paths: set[Path] = set()
        for raw in getattr(project, "header_files", []) or []:
            p = Path(str(raw))
            if p.exists() and p.suffix.lower() in {".h", ".hpp", ".hh", ".hxx"}:
                header_paths.add(p.resolve())

        root = Path(str(getattr(project, "root_dir", "") or ""))
        if root.exists() and root.is_dir():
            for pattern in ("*.h", "*.hpp", "*.hh", "*.hxx"):
                for p in root.rglob(pattern):
                    try:
                        if p.stat().st_size <= 512 * 1024:
                            header_paths.add(p.resolve())
                    except OSError:
                        continue

        patched = 0
        for path in sorted(header_paths, key=lambda p: str(p).lower()):
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            first_lines = "\n".join(content.lstrip().splitlines()[:20])
            if "#pragma once" in first_lines or re.search(r'^\s*#\s*ifndef\b', first_lines, re.MULTILINE):
                continue
            if not re.search(r'\b(typedef|struct|class|enum|extern|void|int|BOOL|DWORD|HRESULT)\b', content):
                continue

            digest = hashlib.sha1(str(path).lower().encode("utf-8")).hexdigest()[:10].upper()
            stem = re.sub(r'[^A-Za-z0-9]+', '_', path.stem).upper().strip("_") or "HEADER"
            guard = f"LLMALMORPH_{stem}_{digest}_"
            new_content = f"#ifndef {guard}\n#define {guard}\n\n{content.rstrip()}\n\n#endif /* {guard} */\n"
            try:
                path.write_text(new_content, encoding="utf-8")
                patched += 1
            except OSError as exc:
                log.warning("include_guard_patch_write_failed", file=str(path), error=str(exc))

        if patched:
            log.info("missing_include_guards_patched", headers=patched)
        return patched

    def _patch_missing_local_includes(self, project, original_source_path: str, log) -> int:
        """
        Restore missing quoted local headers by searching the sample tree.

        Some configs point to a build subdirectory while a required local header
        sits in a sibling copy/source tree. The original project may compile via
        its IDE project file, but the flattened pipeline build sees
        ``fatal error: cannot open include file``. This copies the matching
        header into the including file's directory inside the temporary build.
        """
        if os.getenv("AUTO_RESTORE_LOCAL_INCLUDES", "1").strip().lower() in {"0", "false", "no", "off"}:
            return 0

        source_files = [Path(str(p)) for p in (getattr(project, "source_files", []) or [])]
        if not source_files:
            return 0

        include_re = re.compile(r'^\s*#\s*include\s+"([^"]+)"', re.MULTILINE)
        missing: list[tuple[Path, str]] = []
        for src in source_files:
            try:
                content = src.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for include_name in include_re.findall(content):
                include_path = src.parent / include_name
                if include_path.exists():
                    continue
                # Existing include dirs can already satisfy it; avoid copying.
                if any((Path(str(d)) / include_name).exists() for d in getattr(project, "include_dirs", []) or []):
                    continue
                missing.append((src, include_name))

        if not missing:
            return 0

        search_roots: list[Path] = []
        for raw in [original_source_path, getattr(project, "root_dir", "")]:
            p = Path(str(raw))
            if p.exists():
                p = p if p.is_dir() else p.parent
                for parent in [p, *p.parents[:5]]:
                    if parent.exists() and parent not in search_roots:
                        search_roots.append(parent)

        copied = 0
        for src, include_name in missing:
            include_basename = Path(include_name).name.lower()
            candidates: list[Path] = []
            for root in search_roots:
                try:
                    for cand in root.rglob(Path(include_name).name):
                        if cand.is_file() and cand.name.lower() == include_basename:
                            candidates.append(cand)
                except OSError:
                    continue
            if not candidates:
                continue

            # Prefer headers from the nearest common ancestry / shortest path.
            candidates = sorted(
                {c.resolve() for c in candidates},
                key=lambda c: (len(c.parts), len(str(c))),
            )
            target = src.parent / include_name
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(candidates[0], target)
                copied += 1
                log.info(
                    "missing_local_include_restored",
                    include=include_name,
                    target=str(target),
                    source=str(candidates[0]),
                )
            except OSError as exc:
                log.warning(
                    "missing_local_include_restore_failed",
                    include=include_name,
                    target=str(target),
                    error=str(exc),
                )

        return copied

    @staticmethod
    def _extract_missing_header_symbols(error_text: str) -> set[str]:
        """Extract identifiers that the compiler says are undeclared/missing."""
        symbols: set[str] = set()
        patterns = [
            r"error\s+C3861:\s*'([^']+)':\s*identifier not found",
            r"error\s+C2065:\s*'([^']+)':\s*undeclared identifier",
            r"'([^']+)'\s+was not declared in this scope",
            r"use of undeclared identifier\s+'([^']+)'",
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, error_text or "", re.IGNORECASE):
                symbol = match.group(1).strip()
                if re.fullmatch(r"[A-Za-z_]\w*", symbol):
                    symbols.add(symbol)
        return symbols

    def _patch_missing_headers_deterministic(
        self,
        project,
        log,
        candidate_symbols: Optional[set[str]] = None,
    ) -> int:
        """
        Scan project source files for identifiers that can be resolved by
        adding a known or SDK-discovered #include.  Injects the include (and
        optional #pragma comment lib) at the top of the affected file, just
        after the last existing #include line, without touching any other code.

        Returns the number of files that were patched.
        """
        import re as _re

        try:
            from automation.win32_header_index import headers_for_symbols
        except Exception:  # noqa: BLE001 - SDK index is best-effort only
            headers_for_symbols = None  # type: ignore[assignment]

        source_files: list[str] = getattr(project, "source_files", []) or []
        root_dir = Path(str(getattr(project, "root_dir", "") or ""))
        if root_dir.exists() and root_dir.is_dir():
            # ProjectDetector can occasionally under-report source files for
            # old VS/DSP projects or materialized variant trees. The compiler
            # command may still compile those files, so the deterministic
            # header patcher must discover them from the build root too.
            discovered = []
            for pattern in ("*.c", "*.cc", "*.cpp", "*.cxx", "*.C", "*.CPP"):
                try:
                    discovered.extend(str(p) for p in root_dir.rglob(pattern))
                except OSError:
                    continue
            source_files = list(dict.fromkeys([*source_files, *discovered]))
        if not source_files:
            return 0

        max_dynamic_headers = max(0, int(os.environ.get("DYNAMIC_HEADER_PATCH_MAX", "8")))
        candidate_symbols = set(candidate_symbols or set())
        patched_count = 0
        for src_path in source_files:
            try:
                content = open(src_path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue

            needed: dict[str, tuple[str, str | None]] = {}

            # Prefer SDK-derived symbol -> header knowledge so new Win32 API
            # families do not require per-sample rules in this agent.
            if headers_for_symbols and max_dynamic_headers and candidate_symbols:
                identifiers = {
                    symbol for symbol in candidate_symbols
                    if _re.search(r'\b' + _re.escape(symbol) + r'\b', content)
                }
                try:
                    dynamic_headers = headers_for_symbols(identifiers)
                except Exception as dyn_exc:  # noqa: BLE001
                    dynamic_headers = {}
                    log.debug("dynamic_header_index_lookup_failed", error=str(dyn_exc))

                existing_includes = {
                    inc.lower()
                    for inc in _re.findall(
                        r'^\s*#\s*include\s+[<"]([^>"]+)[>"]',
                        content,
                        _re.MULTILINE,
                    )
                }
                has_windows_h = "windows.h" in existing_includes
                windows_transitive_headers = {
                    "fileapi.h",
                    "libloaderapi.h",
                    "processthreadsapi.h",
                    "winbase.h",
                    "wingdi.h",
                    "winnt.h",
                    "winreg.h",
                    "winuser.h",
                    "wtypes.h",
                }
                grouped_headers: dict[str, set[str]] = {}
                for symbol, hdr in dynamic_headers.items():
                    short_hdr = hdr.strip("<>").strip('"').lower()
                    if short_hdr in existing_includes or short_hdr in content.lower():
                        continue
                    if has_windows_h and short_hdr in windows_transitive_headers:
                        continue
                    # winsock.h is usually the wrong direction for modern SDK
                    # builds; the compiler's include-order mitigation handles
                    # winsock2.h when it is genuinely needed.
                    if short_hdr == "winsock.h":
                        continue
                    grouped_headers.setdefault(hdr, set()).add(symbol)

                for hdr, symbols in sorted(
                    grouped_headers.items(),
                    key=lambda item: (-len(item[1]), item[0].lower()),
                ):
                    needed[hdr] = (hdr, None)
                    if len(needed) >= max_dynamic_headers:
                        break

            # Fallback for curated mappings that also carry optional lib hints.
            for api, (hdr, lib) in self._MISSING_HEADER_MAP.items():
                if candidate_symbols and api not in candidate_symbols:
                    continue
                if _re.search(r'\b' + _re.escape(api) + r'\b', content):
                    # Only add if the header is not already present
                    if hdr.strip("<>") not in content and hdr.strip('"') not in content:
                        needed[hdr] = (hdr, lib)

            if not needed:
                continue

            # Build the inject block: #include lines + #pragma comment(lib, ...) lines
            inject_lines: list[str] = []
            for hdr, lib in sorted(needed.values(), key=lambda x: x[0]):
                inject_lines.append(f"#include {hdr}")
                if lib and f'"{lib}"' not in content:
                    inject_lines.append(f'#pragma comment(lib, "{lib}")')
            inject_block = "\n".join(inject_lines) + "\n"

            # Insert after the last #include / #pragma comment line in the file
            # (preserves existing header order, avoids forward-declaration issues)
            last_include_end = 0
            for m in _re.finditer(
                r'^[ \t]*(?:#include\s+[<"][^>"]+[>"]|#pragma\s+comment\s*\(\s*lib\b[^\)]*\))',
                content,
                _re.MULTILINE,
            ):
                last_include_end = m.end()

            if last_include_end:
                new_content = content[:last_include_end] + "\n" + inject_block + content[last_include_end:]
            else:
                # Fallback: prepend
                new_content = inject_block + content

            try:
                open(src_path, "w", encoding="utf-8").write(new_content)
                log.info(
                    "missing_header_patched",
                    file=os.path.basename(src_path),
                    headers=[h for h, _ in needed.values()],
                )
                patched_count += 1
            except OSError as write_err:
                log.warning("missing_header_patch_write_failed",
                            file=src_path, error=str(write_err))

        return patched_count

    @staticmethod
    def _extract_exact_function_declarations(content: str) -> list[str]:
        """Extract exact declarations from top-level function definitions."""
        declarations: list[str] = []
        lines = content.splitlines()
        i = 0
        brace_depth = 0
        control_keywords = {"if", "for", "while", "switch", "else", "do", "return", "sizeof", "For", "iFor", "jFor"}
        while i < len(lines):
            stripped = lines[i].strip()
            current_depth = brace_depth
            brace_depth += lines[i].count('{') - lines[i].count('}')
            if current_depth != 0:
                i += 1
                continue
            if (
                not stripped
                or stripped.startswith(('#', '//', '/*'))
                or stripped.endswith(';')
                or '(' not in stripped
            ):
                i += 1
                continue

            sig_parts = [stripped]
            j = i
            while '{' not in sig_parts[-1] and j + 1 < len(lines):
                j += 1
                part = lines[j].strip()
                sig_parts.append(part)
                if part.endswith(';'):
                    break

            joined = ' '.join(part for part in sig_parts if part).strip()
            if '{' not in joined or ';' in joined.split('{', 1)[0]:
                i += 1
                continue

            signature = joined.split('{', 1)[0].strip()
            if signature.startswith(('if ', 'for ', 'while ', 'switch ')):
                i += 1
                continue
            if not re.search(r'\b[A-Za-z_]\w*\s*\([^;{}]*\)\s*$', signature):
                i += 1
                continue
            name_match = re.search(r'\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*$', signature)
            if name_match and name_match.group(1) in control_keywords:
                i += 1
                continue
            if name_match:
                prefix = signature[:name_match.start(1)].strip()
                if not prefix or prefix.endswith(('=', ',', '(', '!', '&&', '||')):
                    i += 1
                    continue
            if name_match and name_match.group(1) in {"main", "WinMain", "wWinMain", "DllMain", "_DllMain", "_start"}:
                body_depth = 0
                k = j
                while k < len(lines):
                    body_depth += lines[k].count('{') - lines[k].count('}')
                    if body_depth <= 0 and '{' in lines[j]:
                        break
                    k += 1
                i = max(i + 1, k + 1)
                brace_depth = 0
                continue

            declarations.append(signature + ';')
            body_depth = 0
            k = j
            while k < len(lines):
                body_depth += lines[k].count('{') - lines[k].count('}')
                if body_depth <= 0 and '{' in lines[j]:
                    break
                k += 1
            i = max(i + 1, k + 1)
            brace_depth = 0

        return declarations

    def _normalize_generated_forward_declarations(self, project, log) -> int:
        """
        Replace function-reordering forward declaration blocks with exact
        signatures extracted from the current definitions.
        """
        marker = "/* Forward declarations (auto-generated for function reordering) */"
        patched = 0
        for src_path in getattr(project, "source_files", []) or []:
            try:
                path = Path(src_path)
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if marker not in content:
                continue

            declarations = self._extract_exact_function_declarations(content)
            if not declarations:
                continue

            lines = content.splitlines()
            start = next((idx for idx, line in enumerate(lines) if marker in line), None)
            if start is None:
                continue
            end = start + 1
            while end < len(lines):
                stripped = lines[end].strip()
                if not stripped:
                    end += 1
                    break
                if not stripped.endswith(';'):
                    break
                end += 1

            replacement = [marker] + declarations + [""]
            new_lines = lines[:start] + replacement + lines[end:]
            new_content = "\n".join(new_lines)
            if content.endswith("\n"):
                new_content += "\n"
            if new_content == content:
                continue

            try:
                path.write_text(new_content, encoding="utf-8")
                patched += 1
                log.info("generated_forward_declarations_normalized", file=path.name, declarations=len(declarations))
            except OSError as exc:
                log.warning("generated_forward_declarations_normalize_failed", file=str(path), error=str(exc))

        return patched

    def _normalize_generated_declaration_includes(self, project, log) -> int:
        """
        Move generated *_declarations.h includes below local type declarations
        when a source file also carries generated function-reordering forward
        declarations. This avoids prototypes in generated headers referencing
        project-local types before they are defined.
        """
        marker = "/* Forward declarations (auto-generated for function reordering) */"
        include_re = re.compile(r'^\s*#\s*include\s+"[^"]*_declarations\.h"\s*$', re.MULTILINE)
        patched = 0
        for src_path in getattr(project, "source_files", []) or []:
            try:
                path = Path(src_path)
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if marker not in content or "_declarations.h" not in content:
                continue

            includes = [m.group(0) for m in include_re.finditer(content)]
            if not includes:
                continue

            marker_pos = content.find(marker)
            before_marker = content[:marker_pos]
            after_marker = content[marker_pos:]
            cleaned_before = include_re.sub("", before_marker)
            # Collapse excessive blank lines left by include removal.
            cleaned_before = re.sub(r'\n{3,}', '\n\n', cleaned_before)
            include_block = "\n".join(dict.fromkeys(includes))
            new_content = cleaned_before.rstrip() + "\n\n" + include_block + "\n\n" + after_marker.lstrip()
            if new_content == content:
                continue

            try:
                path.write_text(new_content, encoding="utf-8")
                patched += 1
                log.info("generated_declaration_include_relocated", file=path.name, includes=len(includes))
            except OSError as exc:
                log.warning("generated_declaration_include_relocate_failed", file=str(path), error=str(exc))

        return patched

    def _dedupe_typedef_blocks(self, project, log) -> int:
        """Remove repeated typedef struct/union/enum blocks with the same tag."""
        typedef_re = re.compile(
            r'(?P<block>typedef\s+(?P<kind>struct|union|enum)\s+(?P<tag>_[A-Za-z_]\w*|[A-Za-z_]\w*)\s*\{.*?\}\s*[^;]*;)',
            re.DOTALL,
        )
        patched = 0
        for src_path in getattr(project, "source_files", []) or []:
            try:
                path = Path(src_path)
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            seen: set[tuple[str, str]] = set()
            duplicate_count = 0

            def _replace(match: re.Match) -> str:
                nonlocal duplicate_count
                key = (match.group("kind"), match.group("tag"))
                if key in seen:
                    duplicate_count += 1
                    return ""
                seen.add(key)
                return match.group("block")

            new_content = typedef_re.sub(_replace, content)
            if duplicate_count == 0 or new_content == content:
                continue
            new_content = re.sub(r'\n{3,}', '\n\n', new_content)
            try:
                path.write_text(new_content, encoding="utf-8")
                patched += 1
                log.info("duplicate_typedef_blocks_removed", file=path.name, duplicates=duplicate_count)
            except OSError as exc:
                log.warning("duplicate_typedef_block_remove_failed", file=str(path), error=str(exc))

        return patched

    def _normalize_sdk_tag_alias_typedefs(self, project, log) -> int:
        """
        Remove local incomplete ``typedef struct tagX X;`` aliases when ``X`` is
        a known SDK type, and rewrite accidental ``tagX`` value declarations to
        use ``X``.  This fixes LLM/autofix attempts that shadow Win32 typedefs
        such as CHOOSECOLOR with a function-local incomplete tag.
        """
        try:
            from automation.win32_header_index import headers_for_symbols
        except Exception:  # noqa: BLE001
            headers_for_symbols = None  # type: ignore[assignment]

        typedef_re = re.compile(
            r'^[ \t]*typedef\s+struct\s+tag(?P<alias>[A-Za-z_]\w*)\s+(?P=alias)\s*;\s*$',
            re.MULTILINE,
        )
        patched = 0
        for src_path in getattr(project, "source_files", []) or []:
            try:
                path = Path(src_path)
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            aliases = {m.group("alias") for m in typedef_re.finditer(content)}
            if not aliases:
                continue

            sdk_aliases: set[str] = set()
            if headers_for_symbols:
                try:
                    sdk_aliases = set(headers_for_symbols(aliases).keys())
                except Exception:
                    sdk_aliases = set()
            if not sdk_aliases:
                continue

            def _remove_typedef(match: re.Match) -> str:
                alias = match.group("alias")
                return "" if alias in sdk_aliases else match.group(0)

            new_content = typedef_re.sub(_remove_typedef, content)
            for alias in sdk_aliases:
                new_content = re.sub(r'\btag' + re.escape(alias) + r'\b', alias, new_content)
            new_content, removed_dupes = self._remove_duplicate_sdk_local_declarations(
                new_content,
                sdk_aliases,
            )
            new_content = re.sub(r'\n{3,}', '\n\n', new_content)

            if new_content == content:
                continue
            try:
                path.write_text(new_content, encoding="utf-8")
                patched += 1
                log.info(
                    "sdk_tag_alias_typedefs_normalized",
                    file=path.name,
                    aliases=sorted(sdk_aliases),
                    duplicate_declarations_removed=removed_dupes,
                )
            except OSError as exc:
                log.warning("sdk_tag_alias_typedef_normalize_failed", file=str(path), error=str(exc))

        return patched

    def _normalize_sdk_symbol_shadowing(self, project, log) -> int:
        """
        Rename local function-pointer variables that shadow SDK function names.

        LLM fixes sometimes introduce a variable with the exact name of a
        Windows API function. If that function is declared by SDK headers, the
        local variable collides. Use the SDK symbol index to detect and rename
        only those local variables in their file.
        """
        try:
            from automation.win32_header_index import headers_for_symbols
        except Exception:  # noqa: BLE001
            headers_for_symbols = None  # type: ignore[assignment]
        if not headers_for_symbols:
            return 0

        var_decl_re = re.compile(
            r'(?P<type>\b[A-Za-z_]\w*_t\b)\s+(?P<name>[A-Za-z_]\w*)\s*=\s*(?:NULL|nullptr|0)\s*;'
        )
        patched = 0
        for src_path in getattr(project, "source_files", []) or []:
            try:
                path = Path(src_path)
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            names = {m.group("name") for m in var_decl_re.finditer(content)}
            if not names:
                continue
            try:
                sdk_names = set(headers_for_symbols(names).keys())
            except Exception:
                sdk_names = set()
            if not sdk_names:
                continue

            new_content = content
            renamed: list[str] = []
            for name in sorted(sdk_names, key=len, reverse=True):
                replacement = f"p_{name}"
                if re.search(r'\b' + re.escape(replacement) + r'\b', new_content):
                    continue
                new_content = re.sub(r'\b' + re.escape(name) + r'\b', replacement, new_content)
                renamed.append(name)

            if renamed and new_content != content:
                try:
                    path.write_text(new_content, encoding="utf-8")
                    patched += 1
                    log.info("sdk_symbol_shadowing_normalized", file=path.name, symbols=renamed)
                except OSError as exc:
                    log.warning("sdk_symbol_shadowing_write_failed", file=str(path), error=str(exc))

        return patched

    def _normalize_nt_header_local_conflicts(self, project, log) -> int:
        """
        Remove winternl.h when a file carries its own NT enum/type subset.

        Old samples often define PROCESSINFOCLASS locally because they need
        values absent from the SDK enum. Adding winternl.h creates redefinition
        errors while still not replacing the custom values. Prefer local types.
        """
        include_re = re.compile(r'^\s*#\s*include\s*<winternl\.h>\s*\n?', re.IGNORECASE | re.MULTILINE)
        local_processinfo_re = re.compile(
            r'\b(?:typedef\s+)?enum\s+(?:_PROCESSINFOCLASS|PROCESSINFOCLASS)\b|\benum\s+PROCESSINFOCLASS\b'
        )
        patched = 0
        for src_path in getattr(project, "source_files", []) or []:
            try:
                path = Path(src_path)
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "<winternl.h>" not in content.lower():
                continue
            if not local_processinfo_re.search(content):
                continue
            if "NtQueryInformationProcess" not in content and "ZwQueryInformationProcess" not in content:
                continue

            new_content = include_re.sub("", content)
            if new_content == content:
                continue
            try:
                path.write_text(new_content, encoding="utf-8")
                patched += 1
                log.info("nt_header_local_conflict_normalized", file=path.name, removed="<winternl.h>")
            except OSError as exc:
                log.warning("nt_header_local_conflict_write_failed", file=str(path), error=str(exc))

        return patched

    def _neutralize_mingw_sdk_shadow_headers(self, project, log) -> int:
        """
        Prevent local MinGW runtime headers from shadowing the Windows SDK in
        MSVC builds.

        Some source bundles carry MinGW copies of ``windows.h`` / ``_mingw.h``.
        When the pipeline compiles with MSVC and adds the temporary project
        directory to the include path, those local headers can be selected
        before the SDK headers and then fail on MinGW-only dependencies such as
        ``_mingw_mac.h``.  This is a build-tree normalization only: rename the
        local MinGW headers out of the include search path so MSVC resolves the
        real SDK headers.
        """
        root = Path(str(getattr(project, "root_dir", "") or ""))
        if not root.exists() or not root.is_dir():
            return 0

        neutralized = 0
        shadow_names = {
            "windows.h", "_mingw.h", "mingw.h",
            "stdio.h", "stdlib.h", "string.h", "wchar.h", "time.h",
            "ctype.h", "stdint.h", "inttypes.h", "errno.h", "stddef.h",
        }
        for header in list(root.rglob("*.h")):
            if header.name.lower() not in shadow_names:
                continue
            try:
                content = header.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            probe = content[:4096].lower()
            if "mingw-w64 runtime" not in probe and "_mingw" not in probe:
                continue

            disabled = header.with_name(header.name + ".msvc_disabled")
            suffix = 1
            while disabled.exists():
                disabled = header.with_name(f"{header.name}.msvc_disabled.{suffix}")
                suffix += 1
            try:
                header.rename(disabled)
                neutralized += 1
                log.info(
                    "mingw_sdk_shadow_header_neutralized",
                    header=str(header),
                    moved_to=str(disabled),
                )
            except OSError as exc:
                log.warning(
                    "mingw_sdk_shadow_header_neutralize_failed",
                    header=str(header),
                    error=str(exc),
                )

        return neutralized

    def _normalize_missing_corecrt_headers(self, project, log) -> int:
        """Replace private CRT implementation headers with public CRT headers."""
        include_re = re.compile(
            r'^\s*#\s*include\s*[<"]corecrt_wstdio\.h[>"]\s*$',
            re.IGNORECASE | re.MULTILINE,
        )
        patched = 0
        files = list(getattr(project, "source_files", []) or []) + list(getattr(project, "header_files", []) or [])
        for file_path in files:
            path = Path(file_path)
            if path.suffix.lower() not in {".h", ".hpp", ".c", ".cc", ".cpp", ".cxx"}:
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "corecrt_wstdio.h" not in content:
                continue
            new_content, count = include_re.subn("#include <stdio.h>", content)
            if count == 0 or new_content == content:
                continue
            try:
                path.write_text(new_content, encoding="utf-8")
                patched += 1
                log.info("corecrt_private_header_normalized", file=path.name, replacements=count)
            except OSError as exc:
                log.warning("corecrt_private_header_write_failed", file=str(path), error=str(exc))
        return patched

    def _normalize_sdk_typedef_redefinitions(self, project, log) -> int:
        """
        Remove local typedef struct/union/enum definitions that redefine types
        already provided by the Windows SDK.

        This is intentionally symbol-driven.  It extracts aliases from local
        typedef blocks, asks the SDK symbol index which aliases are SDK-owned,
        and removes only those local blocks.  It fixes generated/copy-pasted
        declarations like ``typedef struct _X { ... } X, *PX;`` colliding with
        winnt.h without relying on sample-specific type names.
        """
        typedef_re = re.compile(
            r'(?P<block>\btypedef\s+(?P<kind>struct|union|enum)\s+'
            r'(?P<tag>_[A-Za-z_]\w*|tag[A-Za-z_]\w*|[A-Za-z_]\w*)\s*'
            r'\{.*?\}\s*(?P<aliases>[^;{}]+)\s*;\s*)',
            re.DOTALL,
        )
        patched = 0

        for src_path in getattr(project, "source_files", []) or []:
            try:
                path = Path(src_path)
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            matches = list(typedef_re.finditer(content))
            if not matches:
                continue

            aliases_by_match: dict[int, set[str]] = {}
            protected_match_indexes: set[int] = set()
            all_aliases: set[str] = set()
            for idx, match in enumerate(matches):
                block = match.group("block")
                if re.search(r'\b(?:TAILQ_ENTRY|STAILQ_ENTRY|LIST_ENTRY|SLIST_ENTRY|TAILQ_HEAD|STAILQ_HEAD|LIST_HEAD|SLIST_HEAD)\s*\(', block):
                    # BSD queue element/head typedefs commonly use generic names
                    # like STRING/PSTRING that also exist in SDK headers.  They
                    # are project-local data structures, not SDK redefinitions.
                    protected_match_indexes.add(idx)
                    continue
                raw_aliases = match.group("aliases")
                aliases = {
                    m.group(1)
                    for m in re.finditer(r'\*?\s*([A-Za-z_]\w*)\b', raw_aliases)
                }
                # Pointer aliases such as PLUID_AND_ATTRIBUTES are useful for
                # lookup too, but the non-pointer alias is the key collision.
                aliases_by_match[idx] = aliases
                all_aliases.update(aliases)

            if not all_aliases:
                continue

            sdk_aliases = self._sdk_declares_symbols(all_aliases)
            if not sdk_aliases:
                continue

            removed = 0

            def _replace(match: re.Match) -> str:
                nonlocal removed
                idx = matches.index(match)
                aliases = aliases_by_match.get(idx, set())
                if aliases & sdk_aliases:
                    removed += 1
                    return ""
                return match.group("block")

            # Avoid list.index() surprises on duplicated match objects by
            # replacing from the end with recorded spans.
            new_content = content
            for idx, match in reversed(list(enumerate(matches))):
                if idx in protected_match_indexes:
                    continue
                aliases = aliases_by_match.get(idx, set())
                if not (aliases & sdk_aliases):
                    continue
                new_content = new_content[:match.start()] + "" + new_content[match.end():]
                removed += 1

            if removed == 0 or new_content == content:
                continue
            new_content = re.sub(r'\n{3,}', '\n\n', new_content)
            try:
                path.write_text(new_content, encoding="utf-8")
                patched += 1
                log.info(
                    "sdk_typedef_redefinitions_normalized",
                    file=path.name,
                    removed_blocks=removed,
                    sdk_aliases=sorted(sdk_aliases)[:20],
                )
            except OSError as exc:
                log.warning("sdk_typedef_redefinition_write_failed", file=str(path), error=str(exc))

        return patched

    @staticmethod
    def _sdk_declares_symbols(symbols: set[str]) -> set[str]:
        """Return the subset of names declared by local Windows SDK headers."""
        if not symbols:
            return set()
        try:
            from automation.win32_header_index import _find_sdk_version_roots  # type: ignore
        except Exception:  # noqa: BLE001
            return set()

        wanted = {s for s in symbols if re.fullmatch(r"[A-Za-z_]\w*", s)}
        if not wanted:
            return set()
        found: set[str] = set()
        # Look for typedef aliases, struct/union/enum tags, and defines.  This
        # deliberately includes big umbrella headers such as winnt.h because
        # typedef redefinition diagnostics usually point there.
        patterns = {
            name: re.compile(
                rf'(\btypedef\b[^;{{}}]*(?:\{{[^}}]*\}}[^;]*)?\b{re.escape(name)}\b\s*(?:[,;])|'
                rf'\b(?:struct|union|enum)\s+{re.escape(name)}\b|'
                rf'^\s*#\s*define\s+{re.escape(name)}\b)',
                re.DOTALL | re.MULTILINE,
            )
            for name in wanted
        }
        priority_headers = {
            "windows.h", "winnt.h", "windef.h", "minwindef.h", "basetsd.h",
            "ntdef.h", "winbase.h", "processthreadsapi.h", "securitybaseapi.h",
            "winternl.h",
        }
        for root in _find_sdk_version_roots():
            try:
                headers = [p for p in Path(root).glob("*.h") if p.name.lower() in priority_headers]
            except OSError:
                continue
            for hdr in headers:
                if found >= wanted:
                    return found
                try:
                    text = hdr.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for name, pat in patterns.items():
                    if name not in found and pat.search(text):
                        found.add(name)
        return found

    @staticmethod
    def _remove_duplicate_sdk_local_declarations(content: str, sdk_aliases: set[str]) -> tuple[str, int]:
        if not sdk_aliases:
            return content, 0

        aliases = "|".join(re.escape(alias) for alias in sorted(sdk_aliases, key=len, reverse=True))
        decl_re = re.compile(rf'^(?P<indent>\s*)(?P<type>{aliases})\s+(?P<name>[A-Za-z_]\w*)\s*;\s*$')
        lines = content.splitlines()
        out: list[str] = []
        brace_depth = 0
        seen_by_depth: dict[int, set[tuple[str, str]]] = {}
        removed = 0

        for line in lines:
            current_depth = brace_depth
            for depth in list(seen_by_depth):
                if depth > current_depth:
                    seen_by_depth.pop(depth, None)

            match = decl_re.match(line)
            if match:
                key = (match.group("type"), match.group("name"))
                seen_here = seen_by_depth.setdefault(current_depth, set())
                if key in seen_here:
                    removed += 1
                    brace_depth += line.count('{') - line.count('}')
                    continue
                seen_here.add(key)

            out.append(line)
            brace_depth += line.count('{') - line.count('}')

        new_content = "\n".join(out)
        if content.endswith("\n"):
            new_content += "\n"
        return new_content, removed

    def _apply_deterministic_build_normalizers(self, project, log) -> int:
        """Run build-tree deterministic normalizers and return patched file count."""
        total = 0
        normalizers = (
            self._normalize_parent_local_includes,
            self._neutralize_mingw_sdk_shadow_headers,
            self._normalize_missing_corecrt_headers,
            self._normalize_sdk_typedef_redefinitions,
            self._normalize_conflicting_local_redeclarations,
            self._normalize_extra_file_scope_closing_braces,
            self._normalize_bsd_queue_foreach_cursor_types,
            self._normalize_generated_string_scope_blocks,
            self._normalize_legacy_windows_version_macros,
            self._normalize_nt_peb_fallback_types,
            self._localize_duplicate_global_symbols,
        )
        for normalizer in normalizers:
            try:
                total += int(normalizer(project, log) or 0)
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "deterministic_build_normalizer_failed",
                    normalizer=getattr(normalizer, "__name__", str(normalizer)),
                    error=str(exc),
                )
        return total

    def _normalize_conflicting_local_redeclarations(self, project, log) -> int:
        """Remove unused generated locals that are redeclared with a real type later.

        LLM fixes sometimes inject a placeholder such as ``HANDLE String;`` at
        the top of a function, then the original code later declares
        ``PSTRING String = NULL;`` in the same scope.  MSVC reports C2371.  This
        removes only the earlier declaration when the name is not used between
        the two declarations.
        """
        decl_re = re.compile(
            r'^(?P<indent>\s*)'
            r'(?P<type>(?:const\s+)?(?:struct\s+)?[A-Za-z_]\w*(?:\s*\*)?)'
            r'\s+(?P<name>[A-Za-z_]\w*)\s*(?:=\s*[^;]*)?;\s*$'
        )
        patched = 0

        for src_path in getattr(project, "source_files", []) or []:
            path = Path(src_path)
            if path.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.splitlines()
            remove_indexes: set[int] = set()
            seen_by_depth: dict[int, dict[str, tuple[int, str]]] = {}
            brace_depth = 0

            for idx, line in enumerate(lines):
                current_depth = brace_depth
                for depth in list(seen_by_depth):
                    if depth > current_depth:
                        seen_by_depth.pop(depth, None)

                match = decl_re.match(line)
                if match and current_depth > 0:
                    name = match.group("name")
                    typ = re.sub(r'\s+', ' ', match.group("type").replace("*", " *")).strip()
                    seen_here = seen_by_depth.setdefault(current_depth, {})
                    previous = seen_here.get(name)
                    if previous and previous[1] != typ:
                        prev_idx, _prev_type = previous
                        between = "\n".join(lines[prev_idx + 1:idx])
                        if not re.search(rf'\b{re.escape(name)}\b', between):
                            remove_indexes.add(prev_idx)
                    seen_here[name] = (idx, typ)

                brace_depth += line.count('{') - line.count('}')

            if not remove_indexes:
                continue

            new_lines = [line for idx, line in enumerate(lines) if idx not in remove_indexes]
            new_content = "\n".join(new_lines)
            if content.endswith("\n"):
                new_content += "\n"
            if new_content == content:
                continue
            try:
                path.write_text(new_content, encoding="utf-8")
                patched += 1
                log.info(
                    "conflicting_local_redeclarations_removed",
                    file=path.name,
                    removed=len(remove_indexes),
                )
            except OSError as exc:
                log.warning("conflicting_local_redeclaration_write_failed", file=str(path), error=str(exc))

        return patched

    def _normalize_extra_file_scope_closing_braces(self, project, log) -> int:
        """Remove standalone closing braces that appear at file scope.

        A failed region fix can leave:

            }
            DWORD WINAPI NextThread(...)

        where the first brace already closed the previous function and the
        second one is a stray file-scope token.  That produces MSVC C2059/C2143
        on the brace and blocks later deterministic fixes.  This pass only
        removes a line containing a bare ``}`` when brace depth is already zero,
        so it avoids touching valid namespace/extern/function closures.
        """
        patched = 0

        for src_path in getattr(project, "source_files", []) or []:
            path = Path(src_path)
            if path.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.splitlines()
            remove_indexes: set[int] = set()
            brace_depth = 0
            in_block_comment = False

            for idx, line in enumerate(lines):
                stripped = line.strip()

                if in_block_comment:
                    if "*/" in stripped:
                        in_block_comment = False
                    continue
                if stripped.startswith("/*") and "*/" not in stripped:
                    in_block_comment = True
                    continue
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue

                if brace_depth <= 0 and stripped == "}":
                    remove_indexes.add(idx)
                    continue

                code = re.sub(r'"(?:[^"\\]|\\.)*"', '""', line)
                code = re.sub(r"'(?:[^'\\]|\\.)*'", "''", code)
                code = re.sub(r"//.*", "", code)
                code = re.sub(r"/\*.*?\*/", "", code)
                brace_depth += code.count("{") - code.count("}")
                if brace_depth < 0:
                    brace_depth = 0

            if not remove_indexes:
                continue

            new_lines = [line for idx, line in enumerate(lines) if idx not in remove_indexes]
            new_content = "\n".join(new_lines)
            if content.endswith("\n"):
                new_content += "\n"
            if new_content == content:
                continue
            try:
                path.write_text(new_content, encoding="utf-8")
                patched += 1
                log.info(
                    "extra_file_scope_closing_braces_removed",
                    file=path.name,
                    removed=len(remove_indexes),
                )
            except OSError as exc:
                log.warning("extra_file_scope_brace_write_failed", file=str(path), error=str(exc))

        return patched

    def _normalize_bsd_queue_foreach_cursor_types(self, project, log) -> int:
        """Correct BSD queue foreach cursors that were changed to list-head pointers.

        For BSD-style macros, ``TAILQ_FOREACH(var, &head, field)`` expects
        ``var`` to be an element pointer, not a pointer to the queue head.  LLM
        fixes sometimes replace ``PNODE var`` with ``PNODE_LIST var`` after an
        unrelated C2065, which then fails inside the macro expansion with
        errors like ``left of '.tqe_next' must have class/struct/union``.
        """
        foreach_re = re.compile(
            r'\b(?:TAILQ_FOREACH|STAILQ_FOREACH|LIST_FOREACH|SLIST_FOREACH)\s*\(\s*'
            r'(?P<var>[A-Za-z_]\w*)\s*,',
            re.MULTILINE,
        )
        decl_re_template = (
            r'(?m)^(?P<indent>\s*)(?P<type>P[A-Za-z_]\w*?_LIST)\s+'
            r'(?P<var>{var})\s*=\s*(?:NULL|nullptr|0)\s*;'
        )
        patched = 0

        for src_path in getattr(project, "source_files", []) or []:
            path = Path(src_path)
            if path.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            new_content = content
            fixed_vars: list[str] = []
            for match in foreach_re.finditer(content):
                var = match.group("var")
                decl_re = re.compile(decl_re_template.format(var=re.escape(var)))
                decl = decl_re.search(new_content)
                if not decl or decl.start() > match.start():
                    continue

                list_type = decl.group("type")
                elem_type = re.sub(r'_LIST$', '', list_type)
                # Only rewrite if the element pointer typedef is visible in this
                # file.  That avoids inventing project-specific type names.
                if not re.search(rf'\b{re.escape(elem_type)}\b', new_content):
                    continue

                replacement = f"{decl.group('indent')}{elem_type} {var} = NULL;"
                new_content = new_content[:decl.start()] + replacement + new_content[decl.end():]
                fixed_vars.append(f"{list_type}->{elem_type} {var}")

            if new_content == content:
                continue
            try:
                path.write_text(new_content, encoding="utf-8")
                patched += 1
                log.info(
                    "bsd_queue_foreach_cursor_types_normalized",
                    file=path.name,
                    cursors=fixed_vars[:20],
                )
            except OSError as exc:
                log.warning("bsd_queue_cursor_type_write_failed", file=str(path), error=str(exc))

        return patched

    def _normalize_generated_string_scope_blocks(self, project, log) -> int:
        """Remove accidental block scopes around generated _sN string buffers.

        LLM mutations sometimes emit:

            {
                char _s1[5]; ...
            }
            Use(_s1);

        The braces make the generated buffers go out of scope, producing C2065.
        We only unwrap simple blocks containing generated string buffer setup and
        harmless volatile/dead-code statements, and only when the generated names
        are referenced immediately after the block.
        """
        patched = 0
        generated_decl_re = re.compile(r'\b(?:char|wchar_t|WCHAR|unsigned\s+char)\s+(_s\d+|_w\d+|_b\d+)\s*\[')
        allowed_line_re = re.compile(
            r'^\s*(?:'
            r'(?:char|wchar_t|WCHAR|unsigned\s+char)\s+_[swb]\d+\s*\[[^\]]+\]\s*;.*|'
            r'_[swb]\d+\s*\[[^\]]+\]\s*=.*;|'
            r'for\s*\(.*_[swb]\d+.*\)\s*_[swb]\d+\s*\[[^\]]+\]\s*=.*;|'
            r'volatile\s+(?:int|DWORD|ULONG|LONG|size_t)\s+_[A-Za-z]\w*\s*=.*;|'
            r'int\s+_[A-Za-z]\w*\s*=.*;|'
            r'//.*|/\*.*\*/|\s*)$'
        )

        for src_path in getattr(project, "source_files", []) or []:
            path = Path(src_path)
            if path.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.splitlines()
            remove_indexes: set[int] = set()
            idx = 0
            while idx < len(lines):
                if not re.match(r'^\s*\{\s*$', lines[idx]):
                    idx += 1
                    continue

                depth = 1
                end = idx + 1
                while end < len(lines) and depth > 0:
                    depth += lines[end].count('{') - lines[end].count('}')
                    if depth == 0:
                        break
                    end += 1
                if depth != 0 or end <= idx + 1:
                    idx += 1
                    continue

                body = lines[idx + 1:end]
                if any(('{' in line or '}' in line) for line in body):
                    idx += 1
                    continue
                declared: set[str] = set()
                body_ok = True
                for line in body:
                    declared.update(generated_decl_re.findall(line))
                    if not allowed_line_re.match(line):
                        body_ok = False
                        break
                if not body_ok or not declared:
                    idx += 1
                    continue

                following = "\n".join(lines[end + 1:min(len(lines), end + 25)])
                if not any(re.search(rf'\b{re.escape(name)}\b', following) for name in declared):
                    idx += 1
                    continue

                remove_indexes.add(idx)
                remove_indexes.add(end)
                idx = end + 1

            if not remove_indexes:
                continue

            new_lines = [line for i, line in enumerate(lines) if i not in remove_indexes]
            new_content = "\n".join(new_lines)
            if content.endswith("\n"):
                new_content += "\n"
            if new_content == content:
                continue
            try:
                path.write_text(new_content, encoding="utf-8")
                patched += 1
                log.info(
                    "generated_string_scope_blocks_normalized",
                    file=path.name,
                    blocks=len(remove_indexes) // 2,
                )
            except OSError as exc:
                log.warning("generated_string_scope_block_write_failed", file=str(path), error=str(exc))

        return patched

    def _normalize_legacy_windows_version_macros(self, project, log) -> int:
        """Raise stale Windows target macros that break modern SDK headers."""
        patched = 0
        macro_re = re.compile(
            r'^(?P<prefix>\s*#\s*define\s+_WIN32_WINNT\s+)'
            r'(?P<value>0x[0-9A-Fa-f]+|\d+)(?P<suffix>[^\r\n]*)$',
            re.MULTILINE,
        )
        winver_re = re.compile(
            r'^(?P<prefix>\s*#\s*define\s+WINVER\s+)'
            r'(?P<value>0x[0-9A-Fa-f]+|\d+)(?P<suffix>[^\r\n]*)$',
            re.MULTILINE,
        )
        ie_re = re.compile(
            r'^(?P<prefix>\s*#\s*define\s+_WIN32_IE\s+)'
            r'(?P<value>0x[0-9A-Fa-f]+|\d+)(?P<suffix>[^\r\n]*)$',
            re.MULTILINE,
        )
        target = "0x0601"

        def _value_is_low(value: str) -> bool:
            try:
                return int(value, 0) < int(target, 0)
            except ValueError:
                return False

        files = list(getattr(project, "source_files", []) or []) + list(getattr(project, "header_files", []) or [])
        for file_path in files:
            path = Path(file_path)
            if path.suffix.lower() not in {".h", ".hpp", ".c", ".cc", ".cpp", ".cxx"}:
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "_WIN32_WINNT" not in content and "#include <windows.h>" not in content and "#include \"windows.h\"" not in content:
                continue

            changed = False

            def _replace_winnt(match: re.Match) -> str:
                nonlocal changed
                if _value_is_low(match.group("value")):
                    changed = True
                    return f"{match.group('prefix')}0x0601{match.group('suffix')}"
                return match.group(0)

            def _replace_winver(match: re.Match) -> str:
                nonlocal changed
                if _value_is_low(match.group("value")):
                    changed = True
                    return f"{match.group('prefix')}0x0601{match.group('suffix')}"
                return match.group(0)

            new_content = macro_re.sub(_replace_winnt, content)
            new_content = winver_re.sub(_replace_winver, new_content)
            if "_WIN32_WINNT" in new_content:
                ie_match = ie_re.search(new_content)
                if ie_match:
                    if _value_is_low(ie_match.group("value")):
                        new_content = ie_re.sub(
                            lambda m: f"{m.group('prefix')}0x0601{m.group('suffix')}",
                            new_content,
                            count=1,
                        )
                        changed = True
                elif changed:
                    new_content = macro_re.sub(
                        lambda m: f"{m.group(0)}\n#define WINVER 0x0601\n#define _WIN32_IE 0x0601",
                        new_content,
                        count=1,
                    )

            if not changed or new_content == content:
                continue
            try:
                path.write_text(new_content, encoding="utf-8")
                patched += 1
                log.info("legacy_windows_version_macros_normalized", file=path.name)
            except OSError as exc:
                log.warning("legacy_windows_macro_write_failed", file=str(path), error=str(exc))

        return patched

    def _normalize_parent_local_includes(self, project, log) -> int:
        """Rewrite ../header.h includes when the header exists beside the file."""
        include_re = re.compile(
            r'^(?P<indent>\s*#\s*include\s+")(?P<prefix>(?:\.\./)+)(?P<name>[^"/<>]+\.h)(?P<quote>"\s*)$',
            re.IGNORECASE | re.MULTILINE,
        )
        patched = 0
        files = list(getattr(project, "source_files", []) or []) + list(getattr(project, "header_files", []) or [])
        for file_path in files:
            path = Path(file_path)
            if path.suffix.lower() not in {".h", ".hpp", ".c", ".cc", ".cpp", ".cxx"}:
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            replacements = 0

            def _replace(match: re.Match) -> str:
                nonlocal replacements
                name = match.group("name")
                if (path.parent / name).exists():
                    replacements += 1
                    return f'{match.group("indent")}{name}{match.group("quote")}'
                return match.group(0)

            new_content = include_re.sub(_replace, content)
            if replacements == 0 or new_content == content:
                continue
            try:
                path.write_text(new_content, encoding="utf-8")
                patched += 1
                log.info("parent_local_includes_normalized", file=path.name, replacements=replacements)
            except OSError as exc:
                log.warning("parent_local_include_write_failed", file=str(path), error=str(exc))
        return patched

    def _normalize_nt_peb_fallback_types(self, project, log) -> int:
        """Add minimal nt::PEB typedefs for reflective loaders that use nt::PPEB."""
        fallback = """
typedef struct _PEB_LDR_DATA_FALLBACK
{
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB_FALLBACK
{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

""".lstrip()
        patched = 0
        for src_path in getattr(project, "source_files", []) or []:
            path = Path(src_path)
            if path.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "nt::PPEB" not in content or "PPEB_LDR_DATA" in re.sub(r'nt::PPEB_LDR_DATA', '', content):
                continue

            ns_match = re.search(r'namespace\s+nt\s*\{\s*', content)
            if not ns_match:
                continue
            insert_at = ns_match.end()
            new_content = content[:insert_at] + "\n" + fallback + content[insert_at:]
            try:
                path.write_text(new_content, encoding="utf-8")
                patched += 1
                log.info("nt_peb_fallback_types_added", file=path.name)
            except OSError as exc:
                log.warning("nt_peb_fallback_type_write_failed", file=str(path), error=str(exc))
        return patched

    def _localize_duplicate_global_symbols(self, project, log) -> int:
        """Make non-provider duplicate helper functions file-local.

        This fixes link errors such as LNK2005 where a nested module carries
        private copies of helpers also defined in the root library.  Excluding
        the whole nested file is risky because it may define unique exports, so
        only the duplicate helper definitions in non-provider files are made
        static.
        """
        from collections import defaultdict

        source_files = [
            str(p) for p in (getattr(project, "source_files", []) or [])
            if str(p).lower().endswith((".c", ".cc", ".cpp", ".cxx"))
        ]
        file_functions: dict[str, set[str]] = {}
        for src in source_files:
            try:
                content = Path(src).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            funcs = ProjectCompiler._extract_global_function_defs(content)
            if funcs:
                file_functions[src] = funcs

        func_to_files: dict[str, list[str]] = defaultdict(list)
        for src, funcs in file_functions.items():
            for fn in funcs:
                if fn not in {"main", "WinMain", "DllMain", "wWinMain"}:
                    func_to_files[fn].append(src)

        duplicates = {fn: files for fn, files in func_to_files.items() if len(files) >= 2}
        if not duplicates:
            return 0

        def _provider_score(path: str, fn: str) -> tuple[int, int, int]:
            try:
                size = os.path.getsize(path)
            except OSError:
                size = 0
            basename = os.path.basename(path).lower()
            entry_bonus = 1 if fn in getattr(ProjectCompiler, "_ENTRY_POINT_SYMBOLS", set()) else 0
            return (entry_bonus, size, -len(basename))

        provider_for = {fn: max(files, key=lambda p: _provider_score(p, fn)) for fn, files in duplicates.items()}
        funcs_by_file: dict[str, set[str]] = defaultdict(set)
        for fn, files in duplicates.items():
            for src in files:
                if provider_for.get(fn) != src:
                    funcs_by_file[src].add(fn)

        patched = 0
        for src, funcs in funcs_by_file.items():
            path = Path(src)
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            new_content = content
            localized: list[str] = []
            for fn in sorted(funcs, key=len, reverse=True):
                pattern = re.compile(
                    rf'(?m)^(?P<indent>\s*)(?!static\b|extern\b)'
                    rf'(?P<sig>[\w\s\*\(\),]+?[\s\*]+{re.escape(fn)}\s*\([^;{{}}]*\)\s*)'
                    rf'(?=\{{)'
                )
                new_content, count = pattern.subn(r'\g<indent>static \g<sig>', new_content, count=1)
                if count:
                    localized.append(fn)

            if not localized or new_content == content:
                continue
            try:
                path.write_text(new_content, encoding="utf-8")
                patched += 1
                log.info(
                    "duplicate_global_symbols_localized",
                    file=path.name,
                    symbols=localized[:20],
                )
            except OSError as exc:
                log.warning("duplicate_global_symbol_localize_write_failed", file=str(path), error=str(exc))

        return patched

    def _format_detailed_error(self, error_message: str, fix_stats: dict, error_category: str) -> str:
        """Format detailed error report with fix statistics."""
        total_attempts = fix_stats.get("total_attempts", 0)
        
        formatted = f"[{error_category.upper()}] Build failed after {total_attempts} fix attempts:\n"
        formatted += f"Original error: {error_message[:500]}\n"
        
        if fix_stats.get("standard_attempts", 0) > 0:
            formatted += f"• Standard fixes attempted: {fix_stats['standard_attempts']}\n"
        if fix_stats.get("permissive_attempts", 0) > 0:
            formatted += f"• Permissive mode attempts: {fix_stats['permissive_attempts']}\n"  
        if fix_stats.get("surgical_attempts", 0) > 0:
            formatted += f"• Surgical fix attempts: {fix_stats['surgical_attempts']}\n"
        
        if fix_stats.get("fix_loop_detected"):
            formatted += "• Fix loop detected - automatic rollback triggered\n"
        if fix_stats.get("rollback_triggered"):
            formatted += "• Code rollback was applied\n"
            
        error_categories = fix_stats.get("error_categories", [])
        if error_categories:
            formatted += f"• Error progression: {' → '.join(error_categories)}\n"
            
        return formatted

    async def _emit_build_failed(self, job_id: str, sample_id: str, correlation_id: str, error_message: str):
        """Helper to emit BuildFailedEvent properly."""
        event = BuildFailedEvent(
            job_id=job_id,
            sample_id=sample_id, 
            correlation_id=correlation_id,
            auto_fix_attempts=0,
            error_message=error_message[:1000],  # Truncate to prevent oversized messages
        )
        await self._ctx.broker.publish(Topic.EVENTS_ALL, event)

    async def _try_rollback_mutated_functions(
        self,
        job_id: str,
        source_payload: dict,
        build_source_path: str,
        log,
    ) -> int:
        """Restore original function bodies in build_source_path for all mutated functions.

        Called when all AutoFixer tiers fail. Replaces each mutated_body with
        original_body in the on-disk materialized source so a final compile
        attempt can succeed using the original (known-good) function code.

        Returns the number of functions successfully rolled back.
        """
        mutation_artifact_id = source_payload.get("mutation_artifact_id", "")
        if not mutation_artifact_id:
            log.debug("rollback_skipped_no_artifact_id")
            return 0
        if not build_source_path or not os.path.isdir(build_source_path):
            log.debug("rollback_skipped_no_build_dir", path=build_source_path)
            return 0

        try:
            mutation_payload = await self._load_artifact(job_id, mutation_artifact_id, log)
        except Exception as e:
            log.warning("rollback_artifact_load_failed", error=str(e))
            return 0

        if not mutation_payload:
            log.warning("rollback_mutation_payload_missing", artifact_id=mutation_artifact_id)
            return 0

        mutated_functions = mutation_payload.get("mutated_functions", [])
        if not mutated_functions:
            return 0

        original_source_path = (
            source_payload.get("_original_source_path")
            or source_payload.get("source_path", "")
        )
        _mut_source_files = [
            str(mf.get("source_file", "") or "")
            for mf in mutated_functions
            if mf.get("source_file")
        ]
        _mut_root = _infer_mutation_source_root(_mut_source_files, original_source_path)
        rolled_back = 0
        modified_files: dict = {}  # rel_path -> current content (str)

        for mf in mutated_functions:
            original_body = mf.get("original_body", "")
            mutated_body = mf.get("mutated_body", "")
            source_file = mf.get("source_file", "")
            func_name = mf.get("original_name", "unknown")

            if not original_body or not mutated_body or not source_file:
                continue
            if original_body == mutated_body:
                continue  # not actually mutated, skip

            # Compute relative path of the source file vs the original project root.
            rel_path = _relative_source_path(source_file, _mut_root)

            # Load file content from the materialized build directory (once per file)
            if rel_path not in modified_files:
                build_file = os.path.join(build_source_path, rel_path)
                if not os.path.exists(build_file):
                    log.warning("rollback_file_not_found", file=build_file, func=func_name)
                    continue
                try:
                    with open(build_file, "r", encoding="utf-8", errors="ignore") as fh:
                        modified_files[rel_path] = fh.read()
                except OSError as e:
                    log.warning("rollback_file_read_failed", file=build_file, error=str(e))
                    continue

            content = modified_files[rel_path]
            if mutated_body in content:
                modified_files[rel_path] = content.replace(mutated_body, original_body, 1)
                rolled_back += 1
                log.info("rollback_function_restored", func=func_name, file=rel_path)
            else:
                log.warning("rollback_body_not_found_in_file", func=func_name, file=rel_path)

        # Write modified files back to disk
        for rel_path, content in modified_files.items():
            build_file = os.path.join(build_source_path, rel_path)
            try:
                with open(build_file, "w", encoding="utf-8") as fh:
                    fh.write(content)
            except OSError as e:
                log.warning("rollback_file_write_failed", file=build_file, error=str(e))

        if rolled_back > 0:
            log.info("rollback_complete", total_rolled_back=rolled_back)
        return rolled_back


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _compile_result_to_payload(result) -> Optional[dict]:
    if result is None:
        return None
    payload = result.to_dict() if hasattr(result, "to_dict") else {}
    for attr in (
        "success",
        "executable_path",
        "output",
        "errors",
        "warnings",
        "compile_time",
        "executable_size",
        "auto_fix_attempts",
    ):
        payload[attr] = getattr(result, attr, payload.get(attr, None))
    # Keep IPC bounded if a compiler emits a very large transcript.
    for attr in ("output", "errors", "warnings"):
        value = payload.get(attr)
        if isinstance(value, str) and len(value) > 200_000:
            payload[attr] = value[:200_000] + "\n...[truncated by build worker IPC]..."
    return payload


def _payload_to_compile_result(payload: Optional[dict]):
    if payload is None:
        return None
    return SimpleNamespace(**payload)


def _kill_process_tree(pid: int) -> None:
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                timeout=15,
            )
            return
        except Exception as exc:  # noqa: BLE001 - best-effort cleanup
            logger.warning("taskkill_failed", pid=pid, error=str(exc))
    try:
        os.kill(pid, 9)
    except OSError:
        pass


def _run_build_worker_process(target, args: tuple, timeout_s: int) -> dict:
    import json as _json
    import tempfile

    ctx = multiprocessing.get_context("spawn")
    fd, result_path = tempfile.mkstemp(prefix="build_worker_", suffix=".json")
    try:
        os.close(fd)
        proc = ctx.Process(target=target, args=(result_path, *args), daemon=False)
        proc.start()
        proc.join(timeout_s)

        if proc.is_alive():
            _kill_process_tree(proc.pid)
            proc.join(2)
            raise TimeoutError(f"Build worker timed out after {timeout_s}s")

        if not os.path.exists(result_path) or os.path.getsize(result_path) == 0:
            raise RuntimeError(
                f"Build worker exited with code {proc.exitcode} without returning a result"
            )
        with open(result_path, "r", encoding="utf-8") as fh:
            payload = _json.load(fh)
    finally:
        try:
            os.unlink(result_path)
        except OSError:
            pass

    if not payload.get("ok"):
        error = payload.get("error", "unknown worker error")
        traceback_text = payload.get("traceback", "")
        if traceback_text:
            error = f"{error}\n{traceback_text}"
        raise RuntimeError(error)

    return payload


def _write_worker_payload(result_path: str, payload: dict) -> None:
    import json as _json

    with open(result_path, "w", encoding="utf-8") as fh:
        _json.dump(payload, fh)


# ── Final targeted rollback helpers ──────────────────────────────────────────

def _path_key(path: str) -> str:
    return os.path.normcase(os.path.abspath(os.path.normpath(path)))


def _relative_source_path(source_file: str, source_root: str = "") -> str:
    """Return a stable relative path for a mutation source file."""
    if not source_file:
        return ""
    try:
        if source_root:
            return os.path.normpath(os.path.relpath(source_file, source_root))
    except ValueError:
        pass
    return os.path.basename(source_file)


def _infer_mutation_source_root(source_files: list[str], preferred_root: str = "") -> str:
    """Infer the original source root for mutation artifacts."""
    preferred_root = str(preferred_root or "")
    if preferred_root and os.path.isdir(preferred_root):
        preferred_key = _path_key(preferred_root)
        if any(_path_key(sf).startswith(preferred_key + os.sep) for sf in source_files):
            return preferred_root

    dirs = [os.path.dirname(sf) for sf in source_files if sf]
    if not dirs:
        return preferred_root
    try:
        return os.path.commonpath(dirs)
    except ValueError:
        return preferred_root or dirs[0]


def _build_mutation_fix_context(
    build_source_path: str,
    mutation_data: list,
    max_chars: int = 6000,
) -> str:
    """Build compact, generic context so AutoFixer repairs generated edits in place."""
    if not mutation_data:
        return ""

    by_file: dict[str, list[str]] = {}
    for mf in mutation_data:
        rel = mf.get("source_relpath") or _relative_source_path(mf.get("source_file", ""))
        name = mf.get("original_name") or "unknown"
        by_file.setdefault(rel, []).append(str(name))

    lines = [
        "MUTATION REPAIR CONTEXT:",
        "- This source tree is a generated variant; repair compile errors with the smallest local edit that preserves generated changes.",
        "- Do not delete functions, includes, macros, typedefs, or unrelated code to make errors disappear.",
        "- Prefer fixing declarations, local variable types, call arguments, and missing prototypes around the reported line.",
        "- Preserve existing public function signatures unless the compiler error explicitly identifies that declaration as wrong.",
        "- Mutated functions by file:",
    ]
    for rel, names in sorted(by_file.items()):
        joined = ", ".join(names[:12])
        if len(names) > 12:
            joined += f", ... (+{len(names) - 12})"
        lines.append(f"  - {rel}: {joined}")

    context = "\n".join(lines)
    if len(context) > max_chars:
        context = context[:max_chars] + "\n...[mutation context truncated]..."
    return context


def _extract_error_files(compile_result) -> set:
    """Return a set of normalised absolute file paths that have compile errors."""
    files: set = set()
    errors = getattr(compile_result, "errors", "") or ""
    if isinstance(errors, list):
        errors = "\n".join(str(e) for e in errors)
    # GCC:  /abs/path/file.cpp:123:45: error:
    # MSVC: C:\path\file.cpp(123): error C2065:
    for pattern in [
        r'([A-Za-z]:[/\\][^\n:()"]+\.(?:c|cpp|cc|cxx|h|hpp))[:(]\d+',
        r'(/[^\n:()"]+\.(?:c|cpp|cc|cxx|h|hpp))[:(]\d+',
    ]:
        for m in re.finditer(pattern, errors, re.IGNORECASE):
            files.add(os.path.normpath(m.group(1)))
    return files


def _apply_targeted_rollback(
    build_source_path: str,
    original_source_path: str,
    mutation_data: list,
    error_files: set,
    log,
) -> int:
    """Replace mutated function bodies with originals for files that have compile errors.

    Modifies source files in-place.  Maps each mutation's *source_file* (which
    is the path inside the original samples dir) to its materialized build path
    using the same relpath logic as ``_try_rollback_mutated_functions``.  Only
    touches functions whose materialized build file is found in *error_files*.
    Returns the number of functions rolled back.
    """
    if not mutation_data or not error_files:
        return 0

    rolled_back = 0
    error_file_keys = {_path_key(path) for path in error_files}
    # Buffer per build file so we do a single read + write per file
    file_contents: dict = {}  # normpath(build_file) -> content

    for mf in mutation_data:
        source_file = mf.get("source_file", "")
        original_body = mf.get("original_body", "")
        mutated_body = mf.get("mutated_body", "")
        func_name = mf.get("original_name", "?")

        if not (source_file and original_body and mutated_body):
            continue
        if original_body == mutated_body:
            continue

        # Map original samples path → materialized build path
        build_file = mf.get("build_file", "")
        if build_file:
            build_file = os.path.normpath(build_file)
        else:
            rel = mf.get("source_relpath") or _relative_source_path(
                source_file,
                original_source_path,
            )
            build_file = os.path.normpath(os.path.join(build_source_path, rel))

        if _path_key(build_file) not in error_file_keys:
            continue

        if build_file not in file_contents:
            try:
                with open(build_file, "r", encoding="utf-8", errors="ignore") as fh:
                    file_contents[build_file] = fh.read()
            except OSError as exc:
                log.warning("targeted_rollback_read_failed", file=build_file, error=str(exc))
                continue

        content = file_contents[build_file]
        if mutated_body in content:
            file_contents[build_file] = content.replace(mutated_body, original_body, 1)
            rolled_back += 1
            log.info(
                "targeted_rollback_applied",
                func=func_name,
                file=os.path.basename(build_file),
            )
        else:
            log.debug("targeted_rollback_body_not_found", func=func_name)

    for path, content in file_contents.items():
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
        except OSError as exc:
            log.warning("targeted_rollback_write_failed", file=path, error=str(exc))

    return rolled_back


def _advanced_compile_worker_main(
    result_path: str,
    project,
    compiler_name: str,
    output_dir: str,
    output_name: str,
    job_id: str,
    sample_id: str,
    fixer_model: str = "",
    mutation_data: list = None,
    original_source_path: str = "",
) -> None:
    try:
        worker_log = logger.bind(job_id=job_id, worker="advanced_compile_process")
        compiler = ProjectCompiler(compiler=compiler_name, msvc_arch="x86")
        helper = object.__new__(BuildValidationAgent)
        result, fix_stats = BuildValidationAgent._compile_with_advanced_retry(
            helper,
            compiler=compiler,
            project=project,
            output_dir=output_dir,
            output_name=output_name,
            job_id=job_id,
            sample_id=sample_id,
            log=worker_log,
            fixer_model=fixer_model,
            mutation_data=mutation_data,
            original_source_path=original_source_path,
        )
        _write_worker_payload(
            result_path,
            {
                "ok": True,
                "result": _compile_result_to_payload(result),
                "fix_stats": fix_stats,
            }
        )
    except Exception as exc:  # noqa: BLE001 - process boundary must report all failures
        import traceback

        _write_worker_payload(
            result_path,
            {
                "ok": False,
                "error": str(exc),
                "traceback": traceback.format_exc(),
            }
        )


def _compile_project_worker_main(
    result_path: str,
    project,
    compiler_name: str,
    output_dir: str,
    output_name: str,
    compile_kwargs: dict,
) -> None:
    try:
        compiler = ProjectCompiler(compiler=compiler_name, msvc_arch="x86")
        result = compiler.compile_project(
            project=project,
            output_dir=output_dir,
            output_name=output_name,
            **compile_kwargs,
        )
        _write_worker_payload(
            result_path,
            {"ok": True, "result": _compile_result_to_payload(result)},
        )
    except Exception as exc:  # noqa: BLE001 - process boundary must report all failures
        import traceback

        _write_worker_payload(
            result_path,
            {
                "ok": False,
                "error": str(exc),
                "traceback": traceback.format_exc(),
            }
        )


def _run_advanced_compile_in_process(
    project,
    compiler_name: str,
    output_dir: str,
    output_name: str,
    job_id: str,
    sample_id: str,
    fixer_model: str,
    timeout_s: int,
    mutation_data: list = None,
    original_source_path: str = "",
):
    payload = _run_build_worker_process(
        _advanced_compile_worker_main,
        (project, compiler_name, output_dir, output_name, job_id, sample_id, fixer_model,
         mutation_data or [], original_source_path),
        timeout_s,
    )
    return _payload_to_compile_result(payload.get("result")), payload.get("fix_stats", {})


def _run_compile_project_in_process(
    project,
    compiler_name: str,
    output_dir: str,
    output_name: str,
    timeout_s: int,
    compile_kwargs: dict,
):
    payload = _run_build_worker_process(
        _compile_project_worker_main,
        (project, compiler_name, output_dir, output_name, compile_kwargs),
        timeout_s,
    )
    return _payload_to_compile_result(payload.get("result"))
