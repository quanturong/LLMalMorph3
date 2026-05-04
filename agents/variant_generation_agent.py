"""
VariantGenerationAgent — assemble mutated functions into variant source files.

Wraps Stage 4 logic from the old pipeline:
  - Loads original parsed source artifact
  - Loads mutation results artifact
  - For each source file, replaces original function bodies with mutated versions
  - Copies headers / resource files as-is
  - Stores assembled variant source tree as artifact

Input command:  GenerateVariantCommand
Output event:   VariantGeneratedEvent
Error event:    ErrorEvent (code VARIANT_GENERATION_FAILED)
"""

from __future__ import annotations

import json
import os
import random
import re
import shutil
from pathlib import Path

import structlog

from broker.topics import Topic
from contracts.job import JobStatus
from contracts.messages import VariantGeneratedEvent

from .base_agent import BaseAgent

logger = structlog.get_logger(__name__)

# Event signature: MutationCompletedEvent
_SIG_MUTATION_COMPLETED = frozenset({"mutation_artifact_id", "num_functions_mutated", "strategy_used"})


class VariantGenerationAgent(BaseAgent):
    """
    Stitch mutated function bodies into original source to produce variant.

    Self-activates on: MutationCompletedEvent (MUTATION_READY → VARIANT_GENERATING)
    """

    agent_name = "VariantGenerationAgent"
    command_stream = Topic.CMD_GENERATE_VARIANT
    consumer_group = Topic.CG_GENERATE_VARIANT
    event_consumer_group = Topic.CG_EVENTS_GENERATE_VARIANT

    activates_on = {
        _SIG_MUTATION_COMPLETED: (JobStatus.MUTATION_READY, JobStatus.VARIANT_GENERATING),
    }

    capabilities = {"stage": "variant_generation"}

    async def handle_event(self, data: dict, claimed_state) -> None:
        """Build command data from event + state, delegate to handle()."""
        cmd_data = {
            "job_id": data["job_id"],
            "sample_id": data.get("sample_id", ""),
            "correlation_id": data.get("correlation_id", ""),
            "source_artifact_id": data.get("source_artifact_id", "")
                                  or (claimed_state.source_artifact_id if claimed_state else ""),
            "mutation_artifact_id": data.get("mutation_artifact_id", ""),
            "project_name": data.get("project_name", "")
                            or (claimed_state.project_name if claimed_state else ""),
            "language": data.get("language", "")
                        or (claimed_state.language if claimed_state else "c"),
        }
        await self.handle(cmd_data)
        # Transition to VARIANT_READY
        if self._ctx.state_store:
            state = await self._ctx.state_store.get(data["job_id"])
            if state and state.current_status == JobStatus.VARIANT_GENERATING:
                await self.transition_and_save(state, JobStatus.VARIANT_READY,
                                               reason="variant generated")

    async def handle(self, data: dict) -> None:
        job_id = data["job_id"]
        source_artifact_id = data["source_artifact_id"]
        mutation_artifact_id = data["mutation_artifact_id"]
        project_name = data.get("project_name", "")
        language = data.get("language", "c")

        log = logger.bind(job_id=job_id, project=project_name)

        # ── 1. Load artifacts ─────────────────────────────────────────────
        source_payload = await self._load_artifact(source_artifact_id)
        if source_payload is None:
            raise ValueError(f"Source artifact not found: {source_artifact_id}")

        mutation_payload = await self._load_artifact(mutation_artifact_id)
        if mutation_payload is None:
            raise ValueError(f"Mutation artifact not found: {mutation_artifact_id}")

        mutated_functions = mutation_payload.get("mutated_functions", [])
        source_path = source_payload.get("source_path", "")
        source_files = source_payload.get("source_files", [])
        header_files = source_payload.get("header_files", [])

        log.info("variant_generation_start",
                 source_files=len(source_files),
                 mutated_functions=len(mutated_functions))

        # Build lookup: source_file -> list of mutations
        mutations_by_file: dict[str, list[dict]] = {}
        for mf in mutated_functions:
            sf = mf.get("source_file", "")
            if sf:
                mutations_by_file.setdefault(sf, []).append(mf)

        # ── 2. Generate variant source files ──────────────────────────────
        # Determine project root from source_path or first source file
        project_root = source_path
        if not project_root and source_files:
            project_root = os.path.dirname(source_files[0])

        variant_files: dict[str, str] = {}  # relative_path -> content
        files_generated = 0

        for sf in source_files:
            try:
                with open(sf, 'r', encoding='utf-8', errors='ignore') as f:
                    original_code = f.read()
            except (FileNotFoundError, OSError) as e:
                log.warning("source_file_read_error", file=sf, error=str(e))
                continue

            file_mutations = mutations_by_file.get(sf, [])

            if file_mutations:
                modified_code = self._apply_mutations(original_code, file_mutations, language)
                modified_code = self._ensure_includes_preserved(original_code, modified_code)
                if language in ("c", "cpp", "c++"):
                    modified_code = self._deduplicate_c_helpers(modified_code)
                    modified_code = self._reorder_functions(modified_code)
            else:
                modified_code = original_code

            rel_path = os.path.relpath(sf, project_root) if project_root else os.path.basename(sf)
            # Add include guards to .h files to prevent double-inclusion
            if language in ("c", "cpp", "c++") and rel_path.endswith('.h'):
                modified_code = self._add_include_guard(modified_code, rel_path)
            variant_files[rel_path] = modified_code
            files_generated += 1

        # Include headers verbatim
        for hf in header_files:
            try:
                with open(hf, 'r', encoding='utf-8', errors='ignore') as f:
                    header_content = f.read()
                rel_path = os.path.relpath(hf, project_root) if project_root else os.path.basename(hf)
                # Add include guards to .h files to prevent double-inclusion
                if language in ("c", "cpp", "c++") and rel_path.endswith('.h'):
                    header_content = self._add_include_guard(header_content, rel_path)
                variant_files[rel_path] = header_content
                files_generated += 1
            except (FileNotFoundError, OSError) as e:
                log.warning("header_file_read_error", file=hf, error=str(e))

        # ── 3. Store variant artifact ─────────────────────────────────────
        variant_payload = {
            "project_name": project_name,
            "language": language,
            "source_path": source_path,
            "source_files": source_files,
            "source_artifact_id": source_artifact_id,
            "mutation_artifact_id": mutation_artifact_id,
            "variant_files": variant_files,
            "num_source_files": len(source_files),
            "num_mutations_applied": len(mutated_functions),
            "num_files_generated": files_generated,
        }

        if self._ctx.artifact_store:
            variant_artifact_id = await self._ctx.artifact_store.store_json(
                job_id=job_id,
                artifact_type="variant_source",
                data=variant_payload,
            )
        else:
            variant_artifact_id = f"variant_{job_id[:8]}"

        # ── 4. Emit event ────────────────────────────────────────────────
        event = VariantGeneratedEvent(
            job_id=job_id,
            sample_id=data["sample_id"],
            correlation_id=data["correlation_id"],
            variant_artifact_id=variant_artifact_id,
            source_artifact_id=source_artifact_id,
            mutation_artifact_id=mutation_artifact_id,
            project_name=project_name,
            language=language,
            num_files_generated=files_generated,
        )
        await self._ctx.broker.publish(Topic.EVENTS_ALL, event)
        log.info("variant_generated",
                 files=files_generated, artifact_id=variant_artifact_id)

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────

    async def _load_artifact(self, artifact_id: str) -> dict | None:
        if self._ctx.artifact_store:
            return await self._ctx.artifact_store.get_json(artifact_id)
        return None

    @staticmethod
    def _apply_mutations(
        original_code: str,
        file_mutations: list[dict],
        language: str,
    ) -> str:
        """Replace original function bodies with mutated versions."""
        modified = original_code

        for mutation in file_mutations:
            original_body = mutation.get("original_body", "")
            mutated_body = mutation.get("mutated_body", "")

            if not original_body or not mutated_body:
                continue

            # For Python/JS: fix indentation using two-tier delta
            # (handles LLMs that strip the def/function line indent but
            #  leave body lines at their original absolute indent)
            if language in ("python", "javascript"):
                orig_lines = original_body.split("\n")
                mut_lines = mutated_body.split("\n")

                def _indent(line: str) -> int:
                    return len(line) - len(line.lstrip())

                # Find first and second non-blank line indents
                orig_nonblank = [l for l in orig_lines if l.strip()]
                mut_nonblank = [l for l in mut_lines if l.strip()]

                if orig_nonblank and mut_nonblank:
                    orig_first = _indent(orig_nonblank[0])
                    mut_first = _indent(mut_nonblank[0])
                    def_delta = orig_first - mut_first

                    # Body delta from second non-blank line (if exists)
                    if len(orig_nonblank) > 1 and len(mut_nonblank) > 1:
                        body_delta = _indent(orig_nonblank[1]) - _indent(mut_nonblank[1])
                    else:
                        body_delta = def_delta

                    if def_delta != 0 or body_delta != 0:
                        reindented = []
                        first_seen = False
                        for line in mut_lines:
                            if not line.strip():
                                reindented.append(line)
                                continue
                            delta = def_delta if not first_seen else body_delta
                            first_seen = True
                            if delta > 0:
                                reindented.append(" " * delta + line)
                            elif delta < 0:
                                rm = min(-delta, _indent(line))
                                reindented.append(line[rm:])
                            else:
                                reindented.append(line)
                        mutated_body = "\n".join(reindented)

            # Replace the first occurrence of the original body
            if original_body in modified:
                modified = modified.replace(original_body, mutated_body, 1)

        return modified

    @staticmethod
    def _ensure_includes_preserved(original_code: str, modified_code: str) -> str:
        """Restore any #include / import / require directives that were accidentally lost."""
        orig_includes = set()
        for line in original_code.split('\n'):
            stripped = line.strip()
            if (stripped.startswith('#include') or
                stripped.startswith('import ') or stripped.startswith('from ') or
                'require(' in stripped):
                normalized = re.sub(r'\s+', ' ', stripped)
                orig_includes.add(normalized)

        mod_includes = set()
        for line in modified_code.split('\n'):
            stripped = line.strip()
            if (stripped.startswith('#include') or
                stripped.startswith('import ') or stripped.startswith('from ') or
                'require(' in stripped):
                normalized = re.sub(r'\s+', ' ', stripped)
                mod_includes.add(normalized)

        missing = orig_includes - mod_includes
        if missing:
            inject_block = '\n'.join(sorted(missing)) + '\n'
            # Insert at top of file
            modified_code = inject_block + modified_code

        return modified_code

    @staticmethod
    def _add_include_guard(code: str, rel_path: str) -> str:
        """Wrap a .h file with an include guard if one is not already present."""
        stripped = code.lstrip()
        if stripped.startswith('#ifndef ') or stripped.startswith('#pragma once'):
            return code  # already has a guard
        guard = re.sub(r'[^A-Za-z0-9]', '_', rel_path).upper() + '_'
        return f"#ifndef {guard}\n#define {guard}\n\n{code}\n\n#endif /* {guard} */\n"

    @staticmethod
    def _deduplicate_c_helpers(code: str) -> str:
        """Remove duplicate static helper function definitions and typedef structs in C files.

        When multiple functions in the same file are mutated, each mutation
        independently adds its own helpers/structs.  This causes C2084/C2371.
        Keep only the first definition of each name.
        """
        lines = code.split('\n')
        seen_helpers: set[str] = set()
        seen_typedefs: set[str] = set()
        result: list[str] = []
        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            # Detect duplicate typedef struct: 'typedef struct { ... } _NAME;'
            # Can be single-line or multi-line
            td_match = re.match(r'typedef\s+struct\s*\{?', stripped)
            if td_match:
                # Collect the full typedef (may span multiple lines)
                typedef_lines = [line]
                td_text = stripped
                if '{' in td_text:
                    brace_depth = td_text.count('{') - td_text.count('}')
                    while brace_depth > 0 and i + 1 < len(lines):
                        i += 1
                        typedef_lines.append(lines[i])
                        td_text += ' ' + lines[i].strip()
                        brace_depth += lines[i].count('{') - lines[i].count('}')
                # Now look for the name after the closing brace: } _NAME;
                name_match = re.search(r'\}\s*(\w+)\s*;', td_text)
                if name_match:
                    tname = name_match.group(1)
                    if tname in seen_typedefs:
                        # Skip this duplicate typedef
                        i += 1
                        continue
                    seen_typedefs.add(tname)
                result.extend(typedef_lines)
                i += 1
                continue

            # Detect 'static void _xd(' or similar helper definition
            if stripped.startswith('static ') and '(' in stripped:
                # Extract function name
                m = re.match(r'static\s+\w+\s+(\w+)\s*\(', stripped)
                if m:
                    fname = m.group(1)
                    if fname in seen_helpers:
                        # Skip this duplicate definition (until closing brace)
                        brace_depth = 0
                        started = False
                        while i < len(lines):
                            for ch in lines[i]:
                                if ch == '{':
                                    brace_depth += 1
                                    started = True
                                elif ch == '}':
                                    brace_depth -= 1
                            i += 1
                            if started and brace_depth <= 0:
                                break
                        continue
                    else:
                        seen_helpers.add(fname)

            # Detect duplicate typedef for function pointers: 'typedef int (*_NAME)(...);'
            fp_match = re.match(r'typedef\s+\w[\w\s*]*\(\s*\*\s*(\w+)\s*\)', stripped)
            if fp_match:
                fpname = fp_match.group(1)
                if fpname in seen_typedefs:
                    i += 1
                    continue
                seen_typedefs.add(fpname)

            result.append(line)
            i += 1
        return '\n'.join(result)

    @staticmethod
    def _reorder_functions(code: str) -> str:
        """Shuffle the order of top-level function definitions in C/C++ source.

        Keeps #include / #define / typedef / struct / global-variable blocks in
        place at the top.  Only reorders function definitions (detected by
        brace-balanced blocks starting with a return-type + name pattern).
        Forward declarations are added for reordered functions so the file
        still compiles.

        Entry-point functions (main, WinMain, DllMain, wmain, _tmain,
        wWinMain, WinMainCRTStartup) are always placed LAST.
        """
        # Split code into "preamble" (includes, globals, typedefs, structs)
        # and "function blocks"
        lines = code.split('\n')
        preamble_lines: list[str] = []
        func_blocks: list[tuple[str, list[str]]] = []   # (func_name, lines)
        current_func_lines: list[str] = []
        current_func_name = ""
        brace_depth = 0
        in_function = False

        _ENTRY_POINTS = frozenset({
            "main", "wmain", "_tmain", "WinMain", "wWinMain",
            "DllMain", "WinMainCRTStartup", "DllEntryPoint",
        })

        # Regex for function definition start (simplified, C/C++ only)
        _FUNC_DEF_RE = re.compile(
            r'^(?:static\s+|inline\s+|extern\s+|__declspec\([^)]*\)\s+)*'
            r'(?:(?:unsigned|signed|long|short|const|volatile|struct|enum)\s+)*'
            r'\w[\w*\s]*\s+(\w+)\s*\([^;]*$'
        )

        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            if not in_function:
                # Check if this line starts a function definition
                m = _FUNC_DEF_RE.match(stripped)
                if m and '{' not in stripped[:stripped.find('(')] if '(' in stripped else False:
                    # Could be function def – look for opening brace
                    pass  # fall through to brace check below

                if m and not stripped.endswith(';'):
                    # Potential function definition
                    current_func_name = m.group(1)
                    current_func_lines = [line]
                    brace_depth = line.count('{') - line.count('}')
                    if brace_depth > 0:
                        in_function = True
                    elif '{' not in line:
                        # Signature spans multiple lines — look ahead for brace
                        in_function = False
                        j = i + 1
                        while j < len(lines) and '{' not in lines[j]:
                            current_func_lines.append(lines[j])
                            if lines[j].strip().endswith(';'):
                                # This was a declaration, not definition
                                break
                            j += 1
                        if j < len(lines) and '{' in lines[j]:
                            current_func_lines.append(lines[j])
                            brace_depth = sum(l.count('{') - l.count('}') for l in current_func_lines)
                            in_function = brace_depth > 0
                            i = j
                    if not in_function and brace_depth == 0 and current_func_lines:
                        # Complete single-line or declaration
                        if any('{' in l for l in current_func_lines):
                            func_blocks.append((current_func_name, current_func_lines))
                        else:
                            preamble_lines.extend(current_func_lines)
                        current_func_lines = []
                        current_func_name = ""
                else:
                    preamble_lines.append(line)
            else:
                current_func_lines.append(line)
                brace_depth += line.count('{') - line.count('}')
                if brace_depth <= 0:
                    func_blocks.append((current_func_name, current_func_lines))
                    current_func_lines = []
                    current_func_name = ""
                    in_function = False

            i += 1

        # Flush any remaining function block
        if current_func_lines:
            if current_func_name:
                func_blocks.append((current_func_name, current_func_lines))
            else:
                preamble_lines.extend(current_func_lines)

        # Only reorder if there are 3+ functions (otherwise not worth it)
        if len(func_blocks) < 3:
            return code

        # Separate entry points from regular functions
        entry_funcs = [(n, ls) for n, ls in func_blocks if n in _ENTRY_POINTS]
        regular_funcs = [(n, ls) for n, ls in func_blocks if n not in _ENTRY_POINTS]

        # Shuffle regular functions
        random.shuffle(regular_funcs)

        # Build forward declarations for all reordered functions
        forward_decls: list[str] = []
        for func_name, func_lines in regular_funcs + entry_funcs:
            # Extract signature from first line(s)
            sig_lines = []
            for fl in func_lines:
                # Strip inline // comments before joining — otherwise they cut off
                # remaining parameters when the signature is squished to one line.
                stripped_line = fl.strip()
                comment_pos = stripped_line.find('//')
                if comment_pos >= 0:
                    stripped_line = stripped_line[:comment_pos].strip()
                if stripped_line:
                    sig_lines.append(stripped_line)
                if '{' in fl:
                    break
            sig = ' '.join(sig_lines)
            # Remove everything from { onwards
            brace_pos = sig.find('{')
            if brace_pos >= 0:
                sig = sig[:brace_pos].strip()
            if sig and not sig.endswith(';'):
                forward_decls.append(sig + ';')

        # Reassemble: preamble + forward declarations + shuffled functions + entry points
        result_parts = ['\n'.join(preamble_lines)]
        if forward_decls:
            result_parts.append('\n/* Forward declarations (auto-generated for function reordering) */')
            result_parts.append('\n'.join(forward_decls))
            result_parts.append('')
        for _, func_lines in regular_funcs:
            result_parts.append('\n'.join(func_lines))
        for _, func_lines in entry_funcs:
            result_parts.append('\n'.join(func_lines))

        return '\n'.join(result_parts)
