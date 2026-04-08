"""
MutationAgent — LLM-powered function mutation.

Wraps Stage 3 logic from the old pipeline:
  - Loads parsed source artifact (functions list)
  - Selects functions for mutation
  - Calls LLM to mutate each function using the configured strategy
  - Validates / cleans LLM output (brace balance, stub detection, SDK sanitization)
  - Stores mutation results as artifact

Input command:  MutateCommand
Output event:   MutationCompletedEvent
Error event:    ErrorEvent (code MUTATION_FAILED)
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path

import structlog

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from utility_prompt_library import strategy_prompt_dict, get_strategy_prompt  # type: ignore

from broker.topics import Topic
from contracts.job import JobStatus
from contracts.messages import MutationCompletedEvent
from llm.provider import LLMRequest

from .base_agent import BaseAgent

logger = structlog.get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# SDK types/macros that LLM mutations must NOT redefine (from old pipeline)
# ──────────────────────────────────────────────────────────────────────────────

_SDK_TYPES_NO_REDEFINE = {
    'DWORD', 'WORD', 'BYTE', 'BOOL', 'HANDLE', 'HWND', 'HDC', 'HINSTANCE',
    'HMODULE', 'HKEY', 'HRESULT', 'LPVOID', 'LPSTR', 'LPCSTR', 'LPWSTR',
    'LPCWSTR', 'LPARAM', 'WPARAM', 'LRESULT', 'UINT', 'INT', 'LONG',
    'ULONG', 'SHORT', 'USHORT', 'CHAR', 'WCHAR', 'TCHAR', 'SIZE_T',
    'PVOID', 'PDWORD', 'PWORD', 'PBYTE', 'PBOOL', 'VOID',
    'DATA_BLOB', 'PDATA_BLOB', 'HCRYPTPROV', 'HCRYPTHASH', 'HCRYPTKEY',
    'SOCKET', 'sockaddr', 'sockaddr_in', 'in_addr', 'hostent', 'WSADATA',
    'STARTUPINFO', 'PROCESS_INFORMATION', 'SECURITY_ATTRIBUTES',
}

_SDK_MACROS_NO_REDEFINE = {
    'PROV_RSA_FULL', 'CRYPT_VERIFYCONTEXT', 'CRYPT_NEWKEYSET',
    'TRUE', 'FALSE', 'NULL', 'INVALID_HANDLE_VALUE', 'MAX_PATH', 'INFINITE',
    'GENERIC_READ', 'GENERIC_WRITE', 'FILE_SHARE_READ',
    'OPEN_EXISTING', 'CREATE_ALWAYS',
}

_SDK_DANGEROUS_DEFINES = {
    'string', 'bool', 'true', 'false', 'wstring',
    'vector', 'map', 'list', 'set', 'pair',
}

# Regex to detect inline assembly in function bodies
_HAS_INLINE_ASM = re.compile(
    r'\b__asm\b|\b__asm__\b|\b_asm\b|\basm\s*\(|\basm\s*volatile\b',
    re.IGNORECASE,
)

# Event signature for self-activation: SamplePreparedEvent
_SIG_SAMPLE_PREPARED = frozenset({"source_artifact_id", "num_source_files", "num_functions_selected"})

# DecisionIssuedEvent with retry_with_mutation action
_SIG_DECISION_RETRY = frozenset({"decision_id", "action", "next_mutation_strategy"})


class MutationAgent(BaseAgent):
    """
    Mutate selected functions using LLM following configured strategies.

    Self-activates on:
      - SamplePreparedEvent (SAMPLE_READY → MUTATING) — first-time mutation after prep
      - DecisionIssuedEvent with action=retry_with_mutation (DECISION_ISSUED → MUTATING)
    """

    agent_name = "MutationAgent"
    command_stream = Topic.CMD_MUTATE
    consumer_group = Topic.CG_MUTATE
    event_consumer_group = Topic.CG_EVENTS_MUTATE

    activates_on = {
        _SIG_SAMPLE_PREPARED: (JobStatus.SAMPLE_READY, JobStatus.MUTATING),
        _SIG_DECISION_RETRY: (
            JobStatus.DECISION_ISSUED,
            JobStatus.MUTATING,
            lambda d: d.get("action") == "retry_with_mutation",
        ),
    }

    capabilities = {"stage": "mutation", "uses_llm": True}

    # ──────────────────────────────────────────────────────────────────────
    # Adaptive sizing helpers
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _adaptive_max_tokens(func_body: str, strategy: str, language: str) -> int:
        """Compute LLM token budget based on function size and strategy.

        Larger functions need more tokens.  strat_all (stack-strings +
        GetProcAddress boilerplate) expands code ~4x, while simpler strategies
        expand ~2x.  We estimate output size then clamp to a safe range.
        """
        CHARS_PER_TOKEN = 3.5
        SAFETY_FACTOR = 1.25  # headroom for LLM variation

        if language in ("python", "javascript"):
            multiplier, lo, hi = 2.0, 2048, 8192
        elif strategy == "strat_all":
            multiplier, lo, hi = 4.0, 4096, 16384
        elif strategy == "strat_2":
            multiplier, lo, hi = 2.5, 3072, 12288
        elif strategy in ("strat_3", "strat_5"):
            multiplier, lo, hi = 2.5, 4096, 10240
        elif strategy == "strat_4":
            multiplier, lo, hi = 3.5, 4096, 12288
        else:
            multiplier, lo, hi = 2.0, 2048, 10240

        estimated = int(len(func_body) * multiplier * SAFETY_FACTOR / CHARS_PER_TOKEN)
        result = max(lo, min(hi, estimated))
        return result

    @staticmethod
    def _adaptive_max_select(functions: list[dict], strategy: str) -> int:
        """Decide how many functions the LLM should select for mutation.

        Considers: strategy cost, total available functions, and average
        complexity (line count).  Returns a sensible cap for max_select.
        """
        n = len(functions)
        if n <= 2:
            return n  # tiny project — mutate everything available

        # Strategy-based base cap
        if strategy == "strat_all":
            strategy_cap = 5      # expensive, higher compile-failure risk
        elif strategy in ("strat_2", "strat_4"):
            strategy_cap = 5      # structural transforms — fewer to avoid cross-file conflicts
        else:
            strategy_cap = 8      # string-only obfuscation is lighter

        # Don't try to mutate more than ~60% of available functions
        availability_cap = max(2, int(n * 0.6))

        # Complex (large) functions → fewer selections
        avg_lines = sum(
            f.get("body", "").count("\n") + 1 for f in functions
        ) / max(1, n)
        if avg_lines > 150:
            complexity_factor = 0.6
        elif avg_lines > 80:
            complexity_factor = 0.8
        else:
            complexity_factor = 1.0

        result = min(strategy_cap, int(availability_cap * complexity_factor))
        return max(2, result)

    async def handle_event(self, data: dict, claimed_state) -> None:
        """Handle self-activated event — extract data from event and state."""
        # Build command-like data from event + claimed state
        cmd_data = {
            "job_id": data["job_id"],
            "sample_id": data.get("sample_id", ""),
            "correlation_id": data.get("correlation_id", ""),
            "source_artifact_id": data.get("source_artifact_id", "")
                                  or (claimed_state.source_artifact_id if claimed_state else ""),
            "language": data.get("language", "")
                        or (claimed_state.language if claimed_state else "c"),
            "mutation_strategy": data.get("next_mutation_strategy", "")
                                 or self._pick_strategy(claimed_state),
            "requested_strategies": data.get("requested_strategies", [])
                                    or (claimed_state.requested_strategies if claimed_state else []),
            "num_functions": (claimed_state.num_functions if claimed_state and claimed_state.num_functions else None)
                             or 3,
            "target_functions": (claimed_state.target_functions if claimed_state and hasattr(claimed_state, 'target_functions') else []),
            "project_name": data.get("project_name", "")
                            or (claimed_state.project_name if claimed_state else ""),
        }
        await self.handle(cmd_data)
        # Transition to MUTATION_READY after successful processing
        if self._ctx.state_store:
            state = await self._ctx.state_store.get(data["job_id"])
            if state and state.current_status == JobStatus.MUTATING:
                await self.transition_and_save(state, JobStatus.MUTATION_READY,
                                               reason="mutation completed")

    def _pick_strategy(self, state) -> str:
        if state and state.requested_strategies:
            idx = state.mutation_cycle_count % len(state.requested_strategies)
            return str(state.requested_strategies[idx]).strip() or "strat_1"
        return "strat_1"

    async def handle(self, data: dict) -> None:
        job_id = data["job_id"]
        source_artifact_id = data["source_artifact_id"]
        language = data.get("language", "c")
        strategy = data.get("mutation_strategy", "strat_1")
        requested_strategies = data.get("requested_strategies", [])
        retry_attempts = data.get("retry_attempts", 5)

        log = logger.bind(job_id=job_id, strategy=strategy)

        # ── 1. Load parsed source artifact ─────────────────────────────────
        source_payload = await self._load_artifact(source_artifact_id, job_id)
        if source_payload is None:
            raise ValueError(f"Source artifact not found: {source_artifact_id}")

        functions = source_payload.get("functions", [])
        if not functions:
            raise ValueError("No functions found in source artifact")

        # ── 1.pre Build per-file context for cross-function awareness ──────
        # Group functions by file so each mutation knows its siblings
        _structs = source_payload.get("structs", [])
        _globals_list = source_payload.get("globals", [])
        _file_funcs: dict[str, list[str]] = {}
        for fn in functions:
            fpath = fn.get("file", "")
            _file_funcs.setdefault(fpath, []).append(fn.get("name", ""))
        _file_structs: dict[str, list[str]] = {}
        for s in _structs:
            fpath = s.get("file", "")
            body = s.get("body", "")
            if body:
                _file_structs.setdefault(fpath, []).append(body)
        self._file_context_cache = {
            "file_funcs": _file_funcs,
            "file_structs": _file_structs,
            "globals": _globals_list,
        }

        # ── 1a. Filter out functions containing inline assembly ────────────
        # LLM cannot safely mutate inline assembly (register/opcode sensitivity)
        safe_functions = []
        skipped_asm = []
        for func in functions:
            body = func.get("body", "")
            if _HAS_INLINE_ASM.search(body):
                skipped_asm.append(func.get("name", "unknown"))
            else:
                safe_functions.append(func)
        if skipped_asm:
            log.info("skipped_inline_assembly", count=len(skipped_asm), names=skipped_asm)
        if not safe_functions:
            log.warning("all_functions_contain_assembly", total=len(functions))
            raise ValueError("All functions contain inline assembly — nothing safe to mutate")
        functions = safe_functions

        # ── 1a.5  Filter out functions too large for LLM context ───────────
        # strat_all expands code ~4x.  If the expanded output would exceed
        # the LLM's max_tokens ceiling we'll always get truncated / validation-
        # failed results, so skip them upfront and save API calls.
        _MAX_BODY_CHARS = {
            "strat_all": 12000,   # 12K chars → ~14K tokens output, fits 16384
            "strat_2":   20000,   # state-machine is less verbose
        }
        _limit = _MAX_BODY_CHARS.get(strategy, 25000)
        oversized = [f for f in functions if len(f.get("body", "")) > _limit]
        if oversized:
            log.info("skipped_oversized_functions",
                     count=len(oversized), limit=_limit,
                     names=[f.get("name", "?") for f in oversized])
            functions = [f for f in functions if len(f.get("body", "")) <= _limit]
        if not functions:
            log.warning("all_functions_oversized", total=len(safe_functions))
            # Fall back to the N smallest functions
            functions = sorted(safe_functions, key=lambda f: len(f.get("body", "")))[:5]
            log.info("fallback_smallest_functions",
                     names=[f.get("name", "?") for f in functions])

        # ── 1b. LLM-based function selection ───────────────────────────────
        # Let the LLM decide which functions to mutate for maximum AV evasion
        effective_strategy = strategy
        if not effective_strategy or effective_strategy not in strategy_prompt_dict:
            effective_strategy = (requested_strategies or ["strat_1"])[0]
        strategy_prompt = get_strategy_prompt(effective_strategy, language)

        # Check for forced target functions (bypass LLM selection)
        target_functions = data.get("target_functions", [])
        if target_functions:
            target_set = {n.strip() for n in target_functions}
            selected = [f for f in functions if f.get("name", "") in target_set]
            missing = target_set - {f.get("name", "") for f in selected}
            if missing:
                log.warning("target_functions_not_found", missing=list(missing))
            log.info("forced_function_selection",
                     target_functions=list(target_set),
                     matched=len(selected),
                     strategy=effective_strategy)
        else:
            # Adaptive max_select: use config value if explicitly set (>0), else compute
            config_num_functions = int(source_payload.get("num_functions", 0))
            if config_num_functions > 0:
                max_select = config_num_functions
            else:
                max_select = self._adaptive_max_select(functions, effective_strategy)
            log.info("adaptive_max_select",
                     config_num_functions=config_num_functions,
                     computed_max_select=max_select,
                     total_available=len(functions),
                     strategy=effective_strategy)

            selected = await self._llm_select_functions(
                functions=functions,
                language=language,
                strategy=effective_strategy,
                strategy_prompt=strategy_prompt,
                log=log,
                max_select=max_select,
            )
            if not selected:
                # Fallback: take all functions if LLM selection fails
                selected = functions
                log.warning("llm_selection_fallback", reason="LLM selection returned empty, using all functions")

        log.info("mutation_start", num_selected=len(selected),
                 num_total=len(functions),
                 strategy=effective_strategy, language=language,
                 selected_names=[f.get("name", "?") for f in selected])

        # ── 3. Mutate each function via LLM ────────────────────────────────
        mutated_functions = []
        failed_count = 0

        for i, func in enumerate(selected):
            func_name = func.get("name", "unknown")
            func_body = func.get("body", "")
            if not func_body.strip():
                log.warning("skipping_empty_function", name=func_name)
                failed_count += 1
                continue

            log.info("mutating_function", index=i + 1, total=len(selected), name=func_name)

            # Build file context: other function names + struct definitions in same file
            func_file = func.get("file", "")
            _sibling_names = [
                n for n in self._file_context_cache["file_funcs"].get(func_file, [])
                if n != func_name
            ]
            _file_struct_bodies = self._file_context_cache["file_structs"].get(func_file, [])
            file_context = ""
            if _sibling_names or _file_struct_bodies:
                parts = []
                if _sibling_names:
                    parts.append(f"Other functions in same file: {', '.join(_sibling_names)}")
                if _file_struct_bodies:
                    parts.append("Existing struct/type definitions in this file:\n" +
                                 "\n".join(_file_struct_bodies[:10]))
                file_context = "\n".join(parts)

            mutated_body = await self._mutate_function(
                func_name=func_name,
                func_body=func_body,
                language=language,
                strategy_prompt=strategy_prompt,
                retry_attempts=retry_attempts,
                file_context=file_context,
                strategy=effective_strategy,
            )

            if mutated_body is not None:
                mutated_functions.append({
                    "original_name": func_name,
                    "original_body": func_body,
                    "mutated_body": mutated_body,
                    "strategy": effective_strategy,
                    "source_file": func.get("file", ""),
                    "start_line": func.get("start_line", 0),
                    "end_line": func.get("end_line", 0),
                })
                log.info("mutation_success", name=func_name)
            else:
                failed_count += 1
                log.warning("mutation_failed", name=func_name)

        # ── 4. Store mutation artifact ──────────────────────────────────────
        mutation_payload = {
            "project_name": source_payload.get("project_name", ""),
            "language": language,
            "strategy": effective_strategy,
            "source_artifact_id": source_artifact_id,
            "mutated_functions": mutated_functions,
            "selected_functions": [
                {"name": f.get("name", ""), "file": f.get("file", "")}
                for f in selected
            ],
            "statistics": {
                "total_selected": len(selected),
                "total_mutated": len(mutated_functions),
                "total_failed": failed_count,
                "success_rate": len(mutated_functions) / len(selected) * 100 if selected else 0,
            },
        }

        if self._ctx.artifact_store:
            mutation_artifact_id = await self._ctx.artifact_store.store_json(
                job_id=job_id,
                artifact_type="mutation_result",
                data=mutation_payload,
            )
        else:
            mutation_artifact_id = f"mutation_{job_id[:8]}"

        # ── 5. Emit event ──────────────────────────────────────────────────
        event = MutationCompletedEvent(
            job_id=job_id,
            sample_id=data["sample_id"],
            correlation_id=data["correlation_id"],
            mutation_artifact_id=mutation_artifact_id,
            source_artifact_id=source_artifact_id,
            project_name=source_payload.get("project_name", ""),
            language=language,
            strategy_used=effective_strategy,
            num_functions_mutated=len(mutated_functions),
            num_functions_failed=failed_count,
        )
        await self._ctx.broker.publish(Topic.EVENTS_ALL, event)
        log.info("mutation_completed",
                 mutated=len(mutated_functions), failed=failed_count,
                 artifact_id=mutation_artifact_id)

    # ──────────────────────────────────────────────────────────────────────
    # LLM-based function selection
    # ──────────────────────────────────────────────────────────────────────

    async def _llm_select_functions(
        self,
        functions: list[dict],
        language: str,
        strategy: str,
        strategy_prompt: str,
        log,
        max_select: int = 7,
    ) -> list[dict]:
        """Ask the LLM which functions to mutate for maximum AV evasion effectiveness."""
        if self._ctx.llm_provider is None:
            log.warning("no_llm_for_selection, using all functions")
            return functions

        # Build a compact summary of all available functions
        func_summaries = []
        for i, func in enumerate(functions):
            name = func.get("name", "unknown")
            body = func.get("body", "")
            line_count = body.count("\n") + 1
            # Extract key indicators: API calls, string literals, imports
            has_strings = bool(re.findall(r'"[^"]{3,}"', body))
            has_api_calls = bool(re.findall(
                r'\b(CreateFile|WriteFile|ReadFile|RegSetValue|VirtualAlloc|LoadLibrary|'
                r'GetProcAddress|CreateProcess|URLDownload|InternetOpen|WSAStartup|'
                r'socket|connect|send|recv|ShellExecute|WinExec|CreateThread|'
                r'WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|'
                r'NtCreateFile|NtWriteFile|HttpSendRequest|WinHttpOpen|'
                r'CryptEncrypt|CryptDecrypt|RegCreateKey|RegOpenKey|'
                r'import |require\(|__import__|from\s+\w+\s+import)\b', body))
            has_network = bool(re.findall(
                r'\b(socket|connect|send|recv|WSA|Internet|Http|URL|http|https|'
                r'requests\.|urllib|fetch|net\.)\b', body))
            has_file_ops = bool(re.findall(
                r'\b(CreateFile|WriteFile|ReadFile|fopen|fwrite|fread|'
                r'open\(|write\(|read\(|fs\.)\b', body))
            has_registry = bool(re.findall(
                r'\b(RegSetValue|RegCreateKey|RegOpenKey|RegDeleteKey|winreg)\b', body))
            has_crypto = bool(re.findall(
                r'\b(Crypt|AES|DES|RSA|XOR|encrypt|decrypt|hash|SHA|MD5|base64)\b', body, re.IGNORECASE))

            indicators = []
            if has_strings: indicators.append("strings")
            if has_api_calls: indicators.append("API_calls")
            if has_network: indicators.append("network")
            if has_file_ops: indicators.append("file_ops")
            if has_registry: indicators.append("registry")
            if has_crypto: indicators.append("crypto")

            func_summaries.append(
                f"  [{i}] {name} ({line_count} lines, {len(body)} chars) — "
                f"{', '.join(indicators) if indicators else 'basic_logic'}"
            )

        functions_list = "\n".join(func_summaries)

        system_prompt = (
            "You are a malware analysis and AV evasion expert. Your task is to select "
            "which functions in a malware project should be mutated to maximize evasion "
            "from antivirus detection. You understand how AV engines work: static signatures, "
            "import table analysis, heuristic patterns, and ML-based detection."
        )

        user_prompt = (
            f"Given a {language.upper()} malware project with the following functions, select which ones "
            f"should be mutated using strategy '{strategy}' to MAXIMIZE reduction in AV detection.\n\n"
            f"STRATEGY DESCRIPTION:\n{strategy_prompt[:500]}\n\n"
            f"AVAILABLE FUNCTIONS:\n{functions_list}\n\n"
            f"SELECTION CRITERIA:\n"
            f"- Select AT MOST {max_select} functions (fewer is better — focus on highest-impact targets)\n"
            f"- Prioritize functions with the MOST detectable signatures (API calls, strings, network ops)\n"
            f"- Functions with hardcoded strings, URLs, file paths, registry keys are HIGH priority\n"
            f"- Functions calling suspicious Windows APIs (VirtualAlloc, CreateRemoteThread, etc.) are HIGH priority\n"
            f"- Functions with network operations (socket, HTTP, DNS) are HIGH priority\n"
            f"- Small utility functions with no suspicious indicators MUST be SKIPPED\n"
            f"- Entry points (main, WinMain, DllMain) should usually be included\n"
            f"- Consider the strategy: e.g. strat_1 (string obfuscation) needs functions WITH strings\n"
            f"- Mutating too many functions increases compile failure risk — be selective!\n"
            f"- Very large functions (>200 lines) are HARDER to mutate successfully — prefer medium-sized targets (30-150 lines)\n"
            f"- Very small functions (<10 lines) with no indicators are NOT worth mutating\n\n"
            f"Respond with ONLY a JSON array of the selected function indices (max {max_select}). Example: [0, 2, 5]\n"
            f"Do NOT include any explanation, just the JSON array."
        )

        # Disable thinking mode for qwen3 models
        if "qwen3" in os.environ.get("FIXER_MODEL", "").lower():
            user_prompt += "\n/nothink"

        try:
            request = LLMRequest(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=0.1,
                max_tokens=2048,
                response_format="text",
                timeout_s=120,
            )
            response = await self._ctx.llm_provider.generate(request)
            raw = re.sub(r'<think>.*?</think>', '', response.content, flags=re.DOTALL).strip()

            # Extract JSON array from response
            match = re.search(r'\[[\d\s,]*\]', raw)
            if not match:
                log.warning("llm_selection_parse_failed", raw_response=raw[:200])
                return functions

            indices = json.loads(match.group())
            # Validate indices
            valid_indices = [i for i in indices if isinstance(i, int) and 0 <= i < len(functions)]
            if not valid_indices:
                log.warning("llm_selection_no_valid_indices", parsed=indices)
                return functions

            # Hard cap: take only the first max_select indices
            if len(valid_indices) > max_select:
                log.info("llm_selection_capped",
                         original_count=len(valid_indices), max_select=max_select)
                valid_indices = valid_indices[:max_select]

            selected = [functions[i] for i in valid_indices]
            log.info("llm_function_selection",
                     total_available=len(functions),
                     selected_count=len(selected),
                     selected_indices=valid_indices,
                     selected_names=[f.get("name", "?") for f in selected],
                     provider=response.provider,
                     latency_s=round(response.latency_s, 1))
            return selected

        except Exception as e:
            log.warning("llm_selection_error", error=str(e), error_type=type(e).__name__)
            return functions

    # ──────────────────────────────────────────────────────────────────────
    # Core mutation logic
    # ──────────────────────────────────────────────────────────────────────

    async def _mutate_function(
        self,
        func_name: str,
        func_body: str,
        language: str,
        strategy_prompt: str,
        retry_attempts: int = 5,
        file_context: str = "",
        strategy: str = "strat_1",
    ) -> str | None:
        """Call LLM to mutate a single function. Returns mutated body or None."""
        if self._ctx.llm_provider is None:
            logger.warning("no_llm_provider_available")
            return None

        # Build mutation prompt (optimized)
        if language == "python":
            # Detect indentation level from original body
            indent_hint = ""
            first_code_line = next(
                (l for l in func_body.split("\n") if l.strip()), ""
            )
            leading_spaces = len(first_code_line) - len(first_code_line.lstrip())
            if leading_spaces > 0:
                indent_hint = (
                    f"\nCRITICAL INDENTATION RULE: The original code uses {leading_spaces}-space "
                    f"indentation for the function body. Your output MUST preserve EXACTLY the same "
                    f"indentation level. Every line of the function body must start with at least "
                    f"{leading_spaces} spaces. Do NOT strip or reduce indentation.\n"
                )

            mutation_prompt = (
                f"Transform this Python function using the given strategy. "
                f"Keep the same functionality but apply the modifications described below.\n\n"
                f"STRATEGY INSTRUCTIONS:\n{strategy_prompt}\n\n"
                f"REQUIREMENTS:\n"
                f"- Keep function signature (def line) EXACTLY unchanged\n"
                f"- Maintain identical behavior and outputs\n"
                f"- Use valid Python syntax only\n"
                f"- Preserve ALL import references to other modules\n"
                f"{indent_hint}\n"
                f"Output the complete modified function without explanations:\n"
            )
            system_prompt = ("You are a Python code transformation expert. Apply the requested "
                             "changes while preserving functionality and indentation. "
                             "Return only the modified function code, nothing else.")
        elif language == "javascript":
            mutation_prompt = (
                f"Transform this JavaScript function using the given strategy. "
                f"Keep the same functionality but apply the modifications described below.\n\n"
                f"STRATEGY INSTRUCTIONS:\n{strategy_prompt}\n\n"
                f"REQUIREMENTS:\n"
                f"- Keep function signature unchanged\n"
                f"- Maintain identical behavior and outputs\n"
                f"- Use valid JavaScript/Node.js syntax only\n"
                f"- Preserve require()/import statements references\n"
                f"- Maintain proper brace matching and semicolons\n\n"
                f"Output the complete modified function without explanations:\n"
            )
            system_prompt = ("You are a JavaScript/Node.js code transformation specialist. "
                             "Apply the requested changes while preserving functionality. "
                             "Return only valid JavaScript code, nothing else.")
        else:
            lang_label = "C" if language == "c" else "C++" if language == "cpp" else "C/C++"
            # NOTE: Language-specific prohibitions (C-only rules, C++ ban, etc.) are already
            # included in strategy_prompt via get_strategy_prompt() → _get_language_specific_prohibitions().
            # Do NOT duplicate them here to reduce prompt cognitive load.
            # Derive a short unique suffix from the function name for naming helpers/structs
            _fn_suffix = func_name.replace(' ', '_')[:32] if func_name and func_name != 'unknown' else ''
            _unique_hint = (
                f"\nNAMING RULE: This function is named '{func_name}'. "
                f"ALL NEW helper items you CREATE (structs, typedefs, static helper functions, new local variables) "
                f"MUST include the suffix '_{_fn_suffix}' to avoid collisions with other "
                f"mutated functions in the same file. "
                f"Example: _OP_CTX_{_fn_suffix}, _init_{_fn_suffix}, _enc_dll_{_fn_suffix}.\n"
                f"NAMING RULE EXCEPTIONS — do NOT add the suffix to:\n"
                f"  - The function being mutated itself (keep its name IDENTICAL)\n"
                f"  - The function's existing parameters (keep their names IDENTICAL)\n"
                f"  - Existing global variables from the original codebase (e.g. hHeap, pHttpData)\n"
                f"  - XOR encode/decode arrays and buffers (use _e0/_s0 naming from strat_1 rules)\n"
            ) if _fn_suffix else ''
            _file_ctx_section = ""
            if file_context:
                _file_ctx_section = (
                    f"\nFILE CONTEXT (read-only — do NOT redefine these, use them as-is):\n"
                    f"{file_context}\n"
                )
            mutation_prompt = (
                f"Transform this {lang_label} function by applying EVERY technique described in the strategy. "
                f"You MUST heavily modify the function body code — changing #include lines alone is NOT acceptable.\n\n"
                f"STRATEGY:\n{strategy_prompt}\n\n"
                f"{_unique_hint}\n"
                f"{_file_ctx_section}\n"
                f"CONSTRAINTS:\n"
                f"1. Keep function signature IDENTICAL (return type, name, parameters).\n"
                f"2. ALL original function calls must remain, called directly or via function pointer.\n"
                f"3. Use only REAL Windows/CRT APIs — never invent fake API names.\n"
                f"4. Output the complete code: any helpers first, then the transformed main function.\n\n"
                f"SAFETY VALVE: If a transformation would break semantics or produce code you are unsure about, "
                f"SKIP it and leave that code section unchanged. Partially-transformed CORRECT code > fully-transformed BROKEN code.\n\n"
                f"YOUR OUTPUT MUST show major visible changes inside the function body. "
                f"If your output looks similar to the input, you have FAILED the task.\n\n"
                f"Here is the code to transform:\n"
            )
            _is_strat_all = strategy == "strat_all"
            _is_strat_2 = strategy == "strat_2"
            if _is_strat_all:
                _role_desc = (
                    f"You transform function bodies by: (1) building ALL strings on the stack "
                    f"via per-character assignment, (2) resolving Win32 API calls dynamically "
                    f"via GetProcAddress with local function pointer variables (reusing DLL handles), "
                    f"and (3) applying semantic substitutions where safe. "
                    f"Use short generic variable names like _s0, _pf0 to keep the code clean."
                )
            elif _is_strat_2:
                _role_desc = (
                    f"You transform function control flow into state-machine dispatch loops. "
                    f"You define a context struct and static state handler functions OUTSIDE the main function, "
                    f"then replace the function body with a dispatch loop."
                )
            else:
                _role_desc = (
                    f"You transform function bodies to protect string literals: "
                    f"building strings at runtime via stack character assignment or arithmetic expressions."
                )
            # strat_2 needs typedef/struct/extern for context struct and state functions
            if _is_strat_2:
                _struct_rule = (
                    "You MUST define a context struct and static state functions OUTSIDE (before) the main function. "
                    "Use unique names with the function name suffix to avoid collisions. "
                )
            else:
                _struct_rule = (
                    "NEVER add #include directives, extern declarations, forward function declarations, "
                    "global variable declarations, or typedef/struct definitions — these already exist in scope. "
                    "ALL variable declarations must be LOCAL inside the function body. "
                )
            system_prompt = (f"You are a {lang_label} software protection specialist. "
                             f"{_role_desc} "
                             f"You output valid MSVC-compilable {lang_label} code only."
                             + (" This is C code — do NOT use any C++ syntax." if language == "c" else "")
                             + " IMPORTANT: Output ONLY the transformed code. "
                               "NEVER rename the function itself, its parameters, or any Win32 API calls. "
                             + _struct_rule
                             + "No prose, no markdown, no explanations outside code comments.")

        if language not in ("python", "javascript"):
            user_prompt = mutation_prompt + func_body
        else:
            user_prompt = mutation_prompt + "\nHere is the code:\n" + func_body

        # Disable thinking mode for qwen3 models (produces 10-18x bloated output)
        _model_name = os.environ.get("FIXER_MODEL", "")
        if "qwen3" in _model_name.lower():
            user_prompt += "\n/nothink"

        # Adaptive token budget based on function size + strategy
        _temperature = 0.4 if language not in ("python", "javascript") else 0.2
        _max_tokens = self._adaptive_max_tokens(func_body, strategy, language)
        logger.info("adaptive_token_budget",
                    name=func_name, body_chars=len(func_body),
                    strategy=strategy, max_tokens=_max_tokens)

        # Retry loop
        for attempt in range(retry_attempts):
            try:
                request = LLMRequest(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    temperature=_temperature,
                    max_tokens=_max_tokens,
                    response_format="text",
                    timeout_s=300,
                )
                response = await self._ctx.llm_provider.generate(request)
                raw_output = response.content

                # Strip reasoning model <think>...</think> blocks
                had_think = '<think>' in raw_output
                raw_output = re.sub(r'<think>.*?</think>', '', raw_output, flags=re.DOTALL).strip()
                # Also handle unclosed <think> (model ran out of tokens mid-reasoning)
                if '<think>' in raw_output:
                    raw_output = re.sub(r'<think>.*', '', raw_output, flags=re.DOTALL).strip()
                if had_think:
                    logger.info("think_stripped", name=func_name, remaining_len=len(raw_output),
                                first_100=raw_output[:100] if raw_output else "(empty)")

                # Extract code from response
                extracted = self._extract_code(raw_output, language)
                if not extracted:
                    logger.warning("llm_no_code_extracted", attempt=attempt + 1,
                                   raw_len=len(raw_output), raw_start=raw_output[:200] if raw_output else "(empty)")
                    continue

                # Clean LLM artifacts
                cleaned = self._clean_llm_artifacts(extracted)

                # Sanitize SDK patterns (C/C++ only) — skip struct stripping for strat_2
                if language not in ("python", "javascript"):
                    cleaned = self._sanitize_mutation_output(cleaned, allow_structs=_is_strat_2)

                # Fix LLM renaming APIs/functions with _funcname suffix (e.g. RegOpenKeyEx_getActivationKey -> RegOpenKeyEx)
                # Skip for strat_2: state functions intentionally use _funcname suffix (_s0_getActivationKey)
                if language not in ("python", "javascript") and func_name and not _is_strat_2:
                    _suffix = f"_{func_name}"
                    if _suffix in cleaned:
                        cleaned = cleaned.replace(_suffix, "")
                        logger.info("suffix_rename_fix", name=func_name, suffix=_suffix)

                # Brace autorepair for C/C++: trim trailing partial token, then close
                if language not in ("python", "javascript"):
                    _open_b = cleaned.count('{')
                    _close_b = cleaned.count('}')
                    _b_diff = _open_b - _close_b
                    if 1 <= _b_diff <= 8:
                        # Trim trailing partial token BEFORE re-counting braces
                        _last_term = max(cleaned.rfind(';'), cleaned.rfind('}'))
                        if _last_term != -1 and _last_term < len(cleaned) - 1:
                            cleaned = cleaned[:_last_term + 1]
                        # Recount after trim; only add what's still needed
                        _diff_after = cleaned.count('{') - cleaned.count('}')
                        if _diff_after > 0:
                            cleaned += "\n}" * _diff_after
                        logger.info("brace_autorepair", name=func_name,
                                    open=_open_b, close=_close_b, added=max(0, _diff_after))

                # Force-suffix generic helper names to avoid cross-file C2011/C2084
                if language not in ("python", "javascript") and func_name and func_name != 'unknown':
                    cleaned = self._suffix_generic_helpers(cleaned, func_body, func_name)

                # Validation gates
                if not self._validate_mutation(func_body, cleaned, func_name, language):
                    logger.warning("mutation_validation_failed", attempt=attempt + 1, name=func_name)
                    continue

                return cleaned

            except Exception as e:
                logger.warning("llm_mutation_error", error=str(e), attempt=attempt + 1)

        return None

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────

    async def _load_artifact(self, artifact_id: str, job_id: str) -> dict | None:
        if self._ctx.artifact_store:
            return await self._ctx.artifact_store.get_json(artifact_id)
        return None

    @staticmethod
    def _extract_code(response: str, language: str) -> str | None:
        """Extract code from LLM response (handles markdown fences)."""
        # Try markdown code blocks first
        blocks = re.findall(r'```(?:\w*)\n(.*?)```', response, re.DOTALL)
        if blocks:
            return "\n".join(blocks).strip()

        # Fallback: unclosed code fence (model ran out of tokens before closing ```)
        unclosed = re.match(r'```(?:\w*)\n(.*)', response, re.DOTALL)
        if unclosed:
            code = unclosed.group(1).strip()
            if code and '{' in code:
                return code

        # Fallback: if response looks like raw code
        stripped = response.strip()
        if language == "python":
            if "def " in stripped:
                return stripped
        elif language == "javascript":
            if "function " in stripped or "=>" in stripped or "{" in stripped:
                return stripped
        else:
            # C/C++: strip LLM preamble/postamble text that isn't code
            if "{" in stripped:
                if "}" in stripped:
                    cleaned = MutationAgent._strip_llm_prose(stripped)
                    if cleaned:
                        return cleaned
                    return stripped
                # Truncated code (missing }) — return raw so brace autorepair can handle
                return stripped

        return None

    @staticmethod
    def _strip_llm_prose(text: str) -> str | None:
        """Strip non-code prose from LLM output for C/C++.

        Removes leading explanation text before the first C declaration
        and trailing explanation text after the last closing brace.
        """
        lines = text.split("\n")

        # C/C++ code indicators: type keywords, preprocessor directives, function signatures
        _CODE_START = re.compile(
            r'^\s*('
            r'(static\s+|const\s+|unsigned\s+|signed\s+|extern\s+|inline\s+|volatile\s+)*'
            r'(void|int|char|short|long|float|double|BOOL|DWORD|HANDLE|HMODULE|'
            r'ULONG_PTR|ULONG|LONG|LPSTR|LPCSTR|LPVOID|PVOID|SIZE_T|HRESULT|'
            r'BYTE|WORD|UINT|LPCTSTR|LPTSTR|TCHAR|WCHAR|SOCKET|HINTERNET|'
            r'FARPROC|HKEY|LPBYTE|LPDWORD|NTSTATUS|LPWSTR|LPCWSTR|PCHAR|'
            r'struct\s+\w+|enum\s+\w+|typedef\s+|#define\s+|#include\s+|#if|#pragma)'
            r')',
            re.IGNORECASE,
        )

        # Find the first line that looks like C code
        start_idx = 0
        for i, line in enumerate(lines):
            ls = line.strip()
            if not ls:
                continue
            if _CODE_START.match(ls) or ls.startswith("{") or ls.startswith("//") and i > 0:
                start_idx = i
                break
            # Also match bare language labels like "c++" or "c" left from stripped backticks
            if ls.lower() in ("c", "c++", "cpp"):
                start_idx = i + 1  # skip the language label
                continue

        # Find the last closing brace
        end_idx = len(lines) - 1
        for i in range(len(lines) - 1, -1, -1):
            if "}" in lines[i]:
                end_idx = i
                break

        result = "\n".join(lines[start_idx:end_idx + 1]).strip()
        if "{" in result and "}" in result:
            return result
        return None

    @staticmethod
    def _clean_llm_artifacts(code: str) -> str:
        """Clean common LLM artifacts from generated code."""
        # Remove remaining markdown markers
        code = re.sub(r'```[\w]*\n', '', code)
        code = re.sub(r'```\s*$', '', code, flags=re.MULTILINE)

        # Remove stray backticks
        code = code.replace('`', '')

        # Remove LLM instruction remnants
        code = re.sub(r'^\s*Add\s+include\s+', '#include ', code, flags=re.MULTILINE)
        code = re.sub(r'^\s*Add\s+define\s+', '#define ', code, flags=re.MULTILINE)
        code = re.sub(r'^\s*Remove\s+include\s+.*$', '', code, flags=re.MULTILINE)

        # Remove explanation comments
        code = re.sub(r'^\s*//\s*(Here|This|Note|Important|Warning):.*$', '', code, flags=re.MULTILINE)

        # Collapse excessive blank lines
        code = re.sub(r'\n\n\n+', '\n\n', code)

        return code

    @staticmethod
    def _sanitize_mutation_output(code: str, allow_structs: bool = False) -> str:
        """Remove dangerous SDK redefinitions from mutated code."""
        lines = code.split('\n')
        cleaned = []
        _in_typedef_struct = False  # track multi-line typedef struct blocks

        for line in lines:
            stripped = line.strip()

            # Skip all lines inside a typedef struct block (only when not allowing structs)
            if _in_typedef_struct:
                if allow_structs:
                    cleaned.append(line)
                if re.match(r'^\}\s*\w+\s*;', stripped):  # closing } TypeName;
                    _in_typedef_struct = False
                continue

            # Remove #include inside function bodies
            if stripped.startswith('#include'):
                continue

            # Remove extern declarations (globals already declared elsewhere)
            if re.match(r'^extern\b', stripped):
                continue

            # Start skipping a typedef struct block (skip only SDK types, allow custom _Ctx structs)
            if re.match(r'^typedef\s+struct\b', stripped):
                if allow_structs:
                    cleaned.append(line)
                    _in_typedef_struct = True  # still track to find closing brace
                else:
                    _in_typedef_struct = True
                continue

            # Remove dangerous #define
            m = re.match(r'#define\s+(\w+)', stripped)
            if m and m.group(1) in (_SDK_DANGEROUS_DEFINES | _SDK_MACROS_NO_REDEFINE):
                continue

            # Remove typedef of SDK types
            m = re.match(r'typedef\s+.*\b(\w+)\s*;', stripped)
            if m and m.group(1) in _SDK_TYPES_NO_REDEFINE:
                continue

            # Remove struct redefinitions of SDK types
            m = re.match(r'(?:typedef\s+)?struct\s+(\w+)', stripped)
            if m and m.group(1) in _SDK_TYPES_NO_REDEFINE:
                continue

            cleaned.append(line)

        return '\n'.join(cleaned)

    @staticmethod
    def _suffix_generic_helpers(code: str, original: str, func_name: str) -> str:
        """Add _<funcname> suffix to generic LLM helper names (_Ctx, _step0 …)
        to prevent C2011/C2084 redefinition errors across header files.

        Only renames identifiers that appear in the mutated code but NOT in the
        original function body, so existing identifiers are never touched.
        """
        sfx = f"_{func_name}"
        renames: list[tuple[str, str]] = []

        # Generic struct/typedef names
        for name in ('_Ctx', '_OP_CTX'):
            if re.search(rf'\b{name}\b', code) and not re.search(rf'\b{name}\b', original):
                renames.append((name, f'{name}{sfx}'))

        # Generic helper function names: _step0, _step1, _proc0, _helper0 …
        seen: set[str] = set()
        for m in re.finditer(r'\b(_(?:step|proc|helper)\d+)\b', code):
            n = m.group(1)
            if n not in seen and not re.search(rf'\b{re.escape(n)}\b', original):
                renames.append((n, f'{n}{sfx}'))
                seen.add(n)

        # Standalone _init as a helper name
        if re.search(r'\b_init\b', code) and not re.search(r'\b_init\b', original):
            renames.append(('_init', f'_init{sfx}'))

        if not renames:
            return code

        for old, new in renames:
            code = re.sub(rf'\b{re.escape(old)}\b', new, code)

        logger.info("suffix_generic_helpers", func=func_name,
                     renames={o: n for o, n in renames})
        return code

    @staticmethod
    def _validate_mutation(
        original_body: str, mutated_body: str, func_name: str, language: str
    ) -> bool:
        """Run validation gates on mutated code."""
        if not mutated_body or not mutated_body.strip():
            logger.warning("validation_gate_empty", name=func_name)
            return False

        orig_len = len(original_body)
        mut_len = len(mutated_body)

        # Gate 1: Size ratio (relaxed)
        if orig_len > 50:  # Lower threshold
            ratio = mut_len / orig_len
            # strat_2 (state-machine dispatch) naturally produces 10-30x expansion for small functions
            max_ratio = 30.0 if ratio > 10.0 and mut_len < 3000 else 10.0
            if ratio < 0.20 or ratio > max_ratio:
                logger.warning("validation_gate1_size_ratio", name=func_name,
                               orig_len=orig_len, mut_len=mut_len, ratio=round(ratio, 2))
                return False

        # Gate 2: Stub detection (more specific)
        lower = mutated_body.lower()
        stubs = ['// implementation goes here', '// todo: implement',
                 '/* implementation */', '// placeholder code',
                 '# todo: implement', '# placeholder code',
                 'pass  # todo', 'raise notimplementederror']
        if any(s in lower for s in stubs):
            logger.warning("validation_gate2_stub", name=func_name)
            return False

        # Gate 3: Basic completeness check
        if language == "python":
            # Python: must contain def keyword
            if 'def ' not in mutated_body:
                logger.warning("validation_gate3_no_def", name=func_name)
                return False
        elif language == "javascript":
            # JavaScript: brace balance check
            open_braces = mutated_body.count('{')
            close_braces = mutated_body.count('}')
            if abs(open_braces - close_braces) > 1:
                logger.warning("validation_gate3_brace_js", name=func_name,
                               open=open_braces, close=close_braces)
                return False
        elif language != "python":
            # C/C++: More flexible brace validation
            open_braces = mutated_body.count('{')
            close_braces = mutated_body.count('}')
            if abs(open_braces - close_braces) > 1:  # Allow 1 brace diff
                logger.warning("validation_gate3_brace_c", name=func_name,
                               open=open_braces, close=close_braces)
                return False
            
            # Must contain some basic C constructs
            if not any(pattern in mutated_body for pattern in ['{', 'return', ';']):
                logger.warning("validation_gate3_no_constructs", name=func_name)
                return False

            # Gate 3b: Detect function self-renaming (e.g. getActivationKey -> getActivationKey_getActivationKey)
            _doubled = f"{func_name}_{func_name}"
            if _doubled in mutated_body:
                logger.warning("validation_gate3b_func_renamed", name=func_name, doubled=_doubled)
                return False

        return True
