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
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

import structlog

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from project_compiler import ProjectCompiler  # type: ignore
from project_detector import ProjectDetector  # type: ignore

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

    Prefers CLOUD_URL model (e.g. qwen2.5:32b on RunPod) over deepseek-chat.
    Returns a model name suitable for get_llm_provider().
    """
    cloud_url = os.environ.get("CLOUD_URL", "")
    if cloud_url:
        # CLOUD_URL is set -> use a generic model name so get_llm_provider
        # routes through OpenAICompatibleProvider instead of DeepSeek.
        return os.environ.get("FIXER_MODEL", "qwen2.5:32b")
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

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        # Stores BuildValidatedEvent keyed by job_id until state transitions to BUILD_READY.
        # Deferred so SandboxSubmitAgent sees BUILD_READY before consuming the event.
        self._pending_validated_events: dict = {}

    async def handle_event(self, data: dict, claimed_state) -> None:
        """Build command data from event + state."""
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
                    ),
                )
                compilation_time_s = loop.time() - t0
                fix_stats = {"total_attempts": 0}
                auto_fix_attempts = 0
            else:
                # Enhanced compilation with advanced retry logic (C/C++)
                t0 = loop.time()
                compile_result, fix_stats = await self._compile_with_advanced_retry(
                    compiler=compiler,
                    project=project_obj,
                    output_dir=output_dir,
                    output_name=output_name,
                    job_id=job_id,
                    sample_id=sample_id,
                    log=log,
                )
                compilation_time_s = loop.time() - t0
                auto_fix_attempts = fix_stats.get("total_attempts", 0)
                fix_stats["compilation_time_s"] = round(compilation_time_s, 3)

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

    async def _compile_with_advanced_retry(
        self,
        compiler: ProjectCompiler,
        project,
        output_dir: str,
        output_name: str,
        job_id: str,
        sample_id: str,
        log,
    ) -> tuple[Optional[object], dict]:
        """
        Advanced compilation with three-tier retry strategy:
        1. Standard compilation with auto-fix
        2. Permissive mode retry  
        3. Surgical fix for large files
        
        Returns (compile_result, fix_stats)
        """
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

        # Tier 1: Standard compilation with auto-fix
        log.info("compile_attempt_standard", attempt=1)
        _fixer_model = _resolve_fixer_model()
        try:
            result = compiler.compile_project(
                project=project,
                output_dir=output_dir,
                output_name=output_name,
                max_fix_attempts=_MAX_FIX_ATTEMPTS,
                auto_fix=True,
                llm_model=_fixer_model,
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

        # Final attempt: Return last result or None
        if last_result and last_result.errors:
            fix_stats["final_error_count"] = last_result.errors.count("error")
        log.warning("compile_failed_all_tiers", fix_stats=fix_stats)
        return None, fix_stats

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


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
