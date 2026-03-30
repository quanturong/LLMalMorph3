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

from utility_prompt_library import strategy_prompt_dict  # type: ignore

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
        num_functions = data.get("num_functions", 3)
        retry_attempts = data.get("retry_attempts", 5)

        log = logger.bind(job_id=job_id, strategy=strategy)

        # ── 1. Load parsed source artifact ─────────────────────────────────
        source_payload = await self._load_artifact(source_artifact_id, job_id)
        if source_payload is None:
            raise ValueError(f"Source artifact not found: {source_artifact_id}")

        functions = source_payload.get("functions", [])
        if not functions:
            raise ValueError("No functions found in source artifact")

        # Select top N functions (already ranked by SamplePrepAgent)
        selected = functions[:num_functions]
        log.info("mutation_start", num_selected=len(selected),
                 strategy=strategy, language=language)

        # ── 2. Determine effective strategy ─────────────────────────────────
        effective_strategy = strategy
        if not effective_strategy or effective_strategy not in strategy_prompt_dict:
            effective_strategy = (requested_strategies or ["strat_1"])[0]
        strategy_prompt = strategy_prompt_dict.get(effective_strategy, strategy_prompt_dict["strat_1"])

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

            mutated_body = await self._mutate_function(
                func_name=func_name,
                func_body=func_body,
                language=language,
                strategy_prompt=strategy_prompt,
                retry_attempts=retry_attempts,
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
    # Core mutation logic
    # ──────────────────────────────────────────────────────────────────────

    async def _mutate_function(
        self,
        func_name: str,
        func_body: str,
        language: str,
        strategy_prompt: str,
        retry_attempts: int = 5,
    ) -> str | None:
        """Call LLM to mutate a single function. Returns mutated body or None."""
        if self._ctx.llm_provider is None:
            logger.warning("no_llm_provider_available")
            return None

        # Build mutation prompt (optimized)
        if language == "python":
            mutation_prompt = (
                f"Transform this Python function using the given strategy. "
                f"Keep the same functionality but apply the modifications described below.\n\n"
                f"STRATEGY INSTRUCTIONS:\n{strategy_prompt}\n\n"
                f"REQUIREMENTS:\n"
                f"- Keep function signature unchanged\n"
                f"- Maintain identical behavior and outputs\n"
                f"- Use valid Python syntax only\n\n"
                f"Output the complete modified function without explanations:\n"
            )
            system_prompt = ("You are a code transformation expert. Apply the requested "
                             "changes while preserving functionality. Return only the modified function.")
        elif language == "javascript":
            mutation_prompt = (
                f"Transform this JavaScript function using the given strategy. "
                f"Keep the same functionality but apply the modifications described below.\n\n"
                f"STRATEGY INSTRUCTIONS:\n{strategy_prompt}\n\n"
                f"REQUIREMENTS:\n"
                f"- Keep function signature unchanged\n"
                f"- Maintain identical behavior and outputs\n"
                f"- Use valid JavaScript syntax only\n"
                f"- Preserve require/import statements\n\n"
                f"Output the complete modified function without explanations:\n"
            )
            system_prompt = ("You are a JavaScript/Node.js code transformation specialist. "
                             "Apply the requested changes while preserving functionality. "
                             "Return only valid JavaScript code.")
        else:
            mutation_prompt = (
                f"Transform this C/C++ function using the strategy below. "
                f"Preserve all functionality while applying the requested changes.\n\n"
                f"STRATEGY:\n{strategy_prompt}\n\n"
                f"CONSTRAINTS:\n"
                f"- Keep function signature identical\n"
                f"- Preserve all variable declarations\n"
                f"- Maintain original logic flow\n"
                f"- Use only valid C/C++ syntax\n\n"
                f"Return the complete transformed function:\n"
            )
            system_prompt = ("You are a C/C++ code transformation specialist. "
                             "Apply optimizations while maintaining identical functionality. "
                             "Output only valid, compilable C/C++ code.")

        user_prompt = mutation_prompt + "\nHere is the code:\n" + func_body

        # Retry loop
        for attempt in range(retry_attempts):
            try:
                request = LLMRequest(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    temperature=0.2,
                    max_tokens=4096,
                    response_format="text",
                    timeout_s=120,
                )
                response = await self._ctx.llm_provider.generate(request)
                raw_output = response.content

                # Extract code from response
                extracted = self._extract_code(raw_output, language)
                if not extracted:
                    logger.warning("llm_no_code_extracted", attempt=attempt + 1)
                    continue

                # Clean LLM artifacts
                cleaned = self._clean_llm_artifacts(extracted)

                # Sanitize SDK patterns (C/C++ only)
                if language not in ("python", "javascript"):
                    cleaned = self._sanitize_mutation_output(cleaned)

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

        # Fallback: if response looks like raw code
        stripped = response.strip()
        if language == "python":
            if "def " in stripped:
                return stripped
        elif language == "javascript":
            if "function " in stripped or "=>" in stripped or "{" in stripped:
                return stripped
        else:
            if "{" in stripped and "}" in stripped:
                return stripped

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
    def _sanitize_mutation_output(code: str) -> str:
        """Remove dangerous SDK redefinitions from mutated code."""
        lines = code.split('\n')
        cleaned = []

        for line in lines:
            stripped = line.strip()

            # Remove #include inside function bodies
            if stripped.startswith('#include'):
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
    def _validate_mutation(
        original_body: str, mutated_body: str, func_name: str, language: str
    ) -> bool:
        """Run validation gates on mutated code."""
        if not mutated_body or not mutated_body.strip():
            return False

        orig_len = len(original_body)
        mut_len = len(mutated_body)

        # Gate 1: Size ratio (relaxed)
        if orig_len > 50:  # Lower threshold
            ratio = mut_len / orig_len
            if ratio < 0.20 or ratio > 10.0:  # More permissive range
                return False

        # Gate 2: Stub detection (more specific)
        lower = mutated_body.lower()
        stubs = ['// implementation goes here', '// todo: implement',
                 '/* implementation */', '// placeholder code',
                 '# todo: implement', '# placeholder code',
                 'pass  # todo', 'raise notimplementederror']
        if any(s in lower for s in stubs):
            return False

        # Gate 3: Basic completeness check
        if language == "python":
            # Python: must contain def keyword
            if 'def ' not in mutated_body:
                return False
        elif language == "javascript":
            # JavaScript: brace balance check
            open_braces = mutated_body.count('{')
            close_braces = mutated_body.count('}')
            if abs(open_braces - close_braces) > 1:
                return False
        elif language != "python":
            # C/C++: More flexible brace validation
            open_braces = mutated_body.count('{')
            close_braces = mutated_body.count('}')
            if abs(open_braces - close_braces) > 1:  # Allow 1 brace diff
                return False
            
            # Must contain some basic C constructs
            if not any(pattern in mutated_body for pattern in ['{', 'return', ';']):
                return False

        return True
