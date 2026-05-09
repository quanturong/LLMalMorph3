"""Dynamic mutation policy.

This module scores functions and strategies from code features instead of
sample-specific rules.  It is intentionally conservative: the goal is to
avoid broken transformations and preserve compile/semantic stability across
different projects.
"""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class StrategyCapabilities:
    """Transformation capabilities implied by a strategy."""

    touches_strings: bool = False
    touches_control_flow: bool = False
    touches_api_abi: bool = False
    creates_helpers: bool = False
    rewrites_operations: bool = False
    adds_runtime_noise: bool = False
    multi_layer: bool = False

    @property
    def risk_weight(self) -> float:
        weight = 0.0
        if self.touches_strings:
            weight += 0.10
        if self.touches_control_flow:
            weight += 0.25
        if self.touches_api_abi:
            weight += 0.30
        if self.creates_helpers:
            weight += 0.30
        if self.rewrites_operations:
            weight += 0.22
        if self.adds_runtime_noise:
            weight += 0.12
        if self.multi_layer:
            weight += 0.25
        return min(1.0, weight)

    def gate_names(self) -> list[str]:
        gates: list[str] = ["size_ratio", "stub", "brace_comment_balance"]
        if self.touches_strings:
            gates.extend(["string_buffer_bounds", "char_width"])
        if self.touches_control_flow:
            gates.extend(["call_preservation", "cfg_hazard"])
        if self.touches_api_abi:
            gates.extend(["api_signature", "call_arg_width"])
        if self.creates_helpers:
            gates.extend(["helper_scope", "duplicate_helper_symbol"])
        if self.rewrites_operations:
            gates.extend(["type_equivalence", "signedness_hazard"])
        if self.adds_runtime_noise:
            gates.extend(["void_api_assignment", "header_requirement"])
        return sorted(set(gates))


@dataclass
class FunctionRiskProfile:
    """Risk features extracted from one function body."""

    name: str
    file: str = ""
    line_count: int = 0
    body_chars: int = 0
    string_literals: int = 0
    wide_literals: int = 0
    narrow_literals: int = 0
    api_calls: int = 0
    project_calls: int = 0
    returns: int = 0
    gotos: int = 0
    loops: int = 0
    switches: int = 0
    breaks_or_continues: int = 0
    pointer_ops: int = 0
    struct_accesses: int = 0
    macro_lines: int = 0
    cleanup_calls: int = 0
    has_naked: bool = False
    has_inline_asm: bool = False
    has_labels: bool = False
    has_wide_narrow_mix: bool = False
    has_pe_header_usage: bool = False
    has_seh: bool = False
    has_cpp_exception: bool = False
    has_template: bool = False
    has_crypto_pattern: bool = False
    blocker_reasons: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    hazards: list[str] = field(default_factory=list)
    recommended_max_strategy_risk: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MutationPolicyEngine:
    """Dynamic policy used by MutationAgent and validators."""

    _STRATEGY_CAPABILITIES: dict[str, StrategyCapabilities] = {
        "strat_1": StrategyCapabilities(touches_strings=True),
        "strat_2": StrategyCapabilities(
            touches_strings=True,
            touches_control_flow=True,
            adds_runtime_noise=True,
        ),
        "strat_3": StrategyCapabilities(
            touches_strings=True,
            touches_api_abi=True,
        ),
        "strat_4": StrategyCapabilities(
            touches_strings=True,
            creates_helpers=True,
        ),
        "strat_5": StrategyCapabilities(
            touches_strings=True,
            rewrites_operations=True,
        ),
        "strat_6": StrategyCapabilities(
            touches_strings=True,
            adds_runtime_noise=True,
        ),
        "strat_all": StrategyCapabilities(
            touches_strings=True,
            touches_api_abi=True,
            rewrites_operations=True,
            adds_runtime_noise=True,
            multi_layer=True,
        ),
    }

    _STRING_RE = re.compile(r'L?"(?:\\.|[^"\\])*"')
    _API_RE = re.compile(
        r'\b[A-Z][A-Za-z0-9_]*(?:A|W)?\s*\('
    )
    _CALL_RE = re.compile(r'\b([A-Za-z_]\w*)\s*\(')
    _CONTROL_RE = {
        "returns": re.compile(r'\breturn\b'),
        "gotos": re.compile(r'\bgoto\b'),
        "loops": re.compile(r'\b(for|while|do)\b'),
        "switches": re.compile(r'\bswitch\b'),
        "breaks_or_continues": re.compile(r'\b(break|continue)\b'),
    }
    _CLEANUP_RE = re.compile(
        r'\b(CloseHandle|closesocket|RegCloseKey|InternetCloseHandle|'
        r'free|_free|delete|Release|Unlock|LeaveCriticalSection)\s*\('
    )
    _INLINE_ASM_RE = re.compile(
        r'\b__asm\b|\b__asm__\b|\b_asm\b|\basm\s*\(|\basm\s+volatile\b',
        re.IGNORECASE,
    )
    _NAKED_RE = re.compile(
        r'\b__declspec\s*\(\s*naked\s*\)|\b__attribute__\s*\(\s*\(\s*naked\s*\)\s*\)',
        re.IGNORECASE,
    )
    _PE_HEADER_RE = re.compile(
        r'\b(IMAGE_DOS_HEADER|IMAGE_NT_HEADERS(?:32|64)?|IMAGE_FILE_HEADER|'
        r'IMAGE_OPTIONAL_HEADER(?:32|64)?|IMAGE_SECTION_HEADER|IMAGE_IMPORT_DESCRIPTOR|'
        r'IMAGE_EXPORT_DIRECTORY|IMAGE_BASE_RELOCATION|PIMAGE_[A-Z0-9_]+)\b'
    )
    _SEH_RE = re.compile(r'\b__(try|except|finally|leave)\b')
    _CPP_EXCEPTION_RE = re.compile(r'\btry\s*\{|\bcatch\s*\(|\bthrow\b')
    _TEMPLATE_RE = re.compile(
        r'\btemplate\s*<|typename\s+\w+|std::(?:vector|string|map|list|set|unique_ptr|shared_ptr)'
    )
    _CRYPTO_RE = re.compile(
        r'\b(AES|RSA|RC4|DES|SHA(?:1|256|512)?|MD5|HMAC|BCRYPT|CRYPT|'
        r'Crypt(?:AcquireContext|CreateHash|HashData|DeriveKey|Encrypt|Decrypt)|'
        r'BCrypt\w+|key(?:schedule|_schedule)?|SBOX|round_key|MixColumns|SubBytes)\b',
        re.IGNORECASE,
    )

    @classmethod
    def capabilities_for(cls, strategy: str) -> StrategyCapabilities:
        return cls._STRATEGY_CAPABILITIES.get(
            strategy,
            StrategyCapabilities(touches_strings=True),
        )

    @classmethod
    def profile_function(cls, func: dict, language: str = "c") -> FunctionRiskProfile:
        body = func.get("body", "") or ""
        name = func.get("name", "unknown") or "unknown"
        file = func.get("file", "") or ""
        lines = body.splitlines()
        strings = cls._STRING_RE.findall(body)
        wide_literals = sum(1 for s in strings if s.startswith('L"'))
        narrow_literals = len(strings) - wide_literals
        calls = cls._CALL_RE.findall(body)
        api_calls = len(cls._API_RE.findall(body))

        profile = FunctionRiskProfile(
            name=name,
            file=file,
            line_count=max(1, len(lines)),
            body_chars=len(body),
            string_literals=len(strings),
            wide_literals=wide_literals,
            narrow_literals=narrow_literals,
            api_calls=api_calls,
            project_calls=max(0, len(calls) - api_calls),
            returns=len(cls._CONTROL_RE["returns"].findall(body)),
            gotos=len(cls._CONTROL_RE["gotos"].findall(body)),
            loops=len(cls._CONTROL_RE["loops"].findall(body)),
            switches=len(cls._CONTROL_RE["switches"].findall(body)),
            breaks_or_continues=len(cls._CONTROL_RE["breaks_or_continues"].findall(body)),
            pointer_ops=body.count('*') + body.count('&'),
            struct_accesses=body.count('->') + len(re.findall(r'\w+\.\w+', body)),
            macro_lines=sum(1 for line in lines if line.lstrip().startswith('#')),
            cleanup_calls=len(cls._CLEANUP_RE.findall(body)),
            has_naked=bool(cls._NAKED_RE.search(body)),
            has_inline_asm=bool(cls._INLINE_ASM_RE.search(body)),
            has_labels=bool(re.search(
                r'^\s*(?!case\b|default\b|public\b|private\b|protected\b)'
                r'[A-Za-z_]\w*\s*:\s*(?:$|//|/\*)',
                body,
                re.MULTILINE,
            )),
            has_wide_narrow_mix=wide_literals > 0 and narrow_literals > 0,
            has_pe_header_usage=bool(cls._PE_HEADER_RE.search(body)),
            has_seh=bool(cls._SEH_RE.search(body)),
            has_cpp_exception=bool(cls._CPP_EXCEPTION_RE.search(body)),
            has_template=bool(cls._TEMPLATE_RE.search(body)),
            has_crypto_pattern=bool(cls._CRYPTO_RE.search(body)),
        )
        cls._score_profile(profile, language)
        return profile

    @classmethod
    def profile_functions(cls, functions: list[dict], language: str = "c") -> list[FunctionRiskProfile]:
        return [cls.profile_function(func, language) for func in functions]

    @classmethod
    def profile_key(cls, profile_or_func: FunctionRiskProfile | dict) -> tuple[str, str]:
        if isinstance(profile_or_func, FunctionRiskProfile):
            return (profile_or_func.file, profile_or_func.name)
        return (
            str(profile_or_func.get("file", "") or ""),
            str(profile_or_func.get("name", "") or ""),
        )

    @classmethod
    def filter_candidates(
        cls,
        functions: list[dict],
        profiles: list[FunctionRiskProfile],
        strategy: str,
    ) -> tuple[list[dict], list[dict]]:
        """Filter functions whose risk is above what the strategy can tolerate."""
        cap = cls.capabilities_for(strategy)
        strategy_risk = cap.risk_weight
        profile_by_key = {cls.profile_key(p): p for p in profiles}
        kept: list[dict] = []
        skipped: list[dict] = []

        for func in functions:
            profile = profile_by_key.get(cls.profile_key(func))
            if not profile:
                kept.append(func)
                continue
            blockers = cls.blocker_reasons(profile, cap)
            if blockers:
                skipped.append({
                    "name": profile.name,
                    "file": profile.file,
                    "risk_score": round(profile.risk_score, 3),
                    "strategy_risk": round(strategy_risk, 3),
                    "threshold": round(profile.recommended_max_strategy_risk, 3),
                    "hazards": profile.hazards[:8],
                    "blockers": blockers,
                })
                continue
            threshold = profile.recommended_max_strategy_risk
            if strategy_risk > threshold:
                skipped.append({
                    "name": profile.name,
                    "file": profile.file,
                    "risk_score": round(profile.risk_score, 3),
                    "strategy_risk": round(strategy_risk, 3),
                    "threshold": round(threshold, 3),
                    "hazards": profile.hazards[:8],
                })
            else:
                kept.append(func)

        return kept, skipped

    @classmethod
    def blocker_reasons(
        cls,
        profile: FunctionRiskProfile,
        cap: StrategyCapabilities,
    ) -> list[str]:
        """Return hard blockers for this function/strategy capability pair."""
        reasons: list[str] = []
        if profile.has_naked:
            reasons.append("naked_function_blocks_all_mutation")
        if profile.has_inline_asm and (cap.creates_helpers or cap.rewrites_operations):
            reasons.append("inline_asm_blocks_helper_or_operation_rewrite")
        if profile.has_pe_header_usage and cap.rewrites_operations:
            reasons.append("pe_header_arithmetic_blocks_operation_rewrite")
        if profile.has_seh and (cap.touches_control_flow or cap.creates_helpers):
            reasons.append("seh_blocks_cfg_or_helper_rewrite")
        if profile.has_template and (cap.touches_api_abi or cap.creates_helpers):
            reasons.append("template_code_blocks_api_resolution_or_helper_split")
        if profile.has_cpp_exception and (cap.touches_control_flow or cap.creates_helpers):
            reasons.append("cpp_exception_blocks_cfg_or_helper_rewrite")
        if profile.has_crypto_pattern and cap.rewrites_operations:
            reasons.append("crypto_code_blocks_operation_rewrite")
        if (profile.gotos or profile.has_labels) and (cap.touches_control_flow or cap.creates_helpers):
            reasons.append("goto_or_label_blocks_cfg_or_helper_rewrite")
        profile.blocker_reasons = reasons
        return reasons

    @classmethod
    def recommend_max_select(
        cls,
        functions: list[dict],
        profiles: list[FunctionRiskProfile],
        strategy: str,
        base_cap: int,
    ) -> int:
        """Dynamic mutation budget from strategy risk and candidate risk."""
        if not functions:
            return 0
        cap = cls.capabilities_for(strategy)
        avg_risk = sum(p.risk_score for p in profiles) / max(1, len(profiles))
        confidence = max(0.25, 1.0 - avg_risk)
        strategy_penalty = max(0.35, 1.0 - cap.risk_weight * 0.55)
        availability = max(1, int(math.ceil(len(functions) * 0.6)))
        recommended = int(max(1, min(base_cap, availability) * confidence * strategy_penalty))
        return max(1, min(base_cap, availability, recommended))

    @classmethod
    def prompt_guidance(
        cls,
        profile: FunctionRiskProfile | None,
        strategy: str,
    ) -> str:
        if profile is None:
            return ""
        cap = cls.capabilities_for(strategy)
        gates = ", ".join(cap.gate_names())
        hazards = ", ".join(profile.hazards[:6]) if profile.hazards else "none"
        notes = [
            "DYNAMIC RISK CONTEXT (read-only):",
            f"- Function risk score: {profile.risk_score:.2f}; hazards: {hazards}.",
            f"- Strategy gates expected after generation: {gates}.",
        ]
        if profile.has_wide_narrow_mix and cap.touches_strings:
            notes.append("- Preserve each callee's char width exactly; do not convert wide data to narrow data or vice versa.")
        if profile.cleanup_calls:
            notes.append("- Preserve every cleanup/resource-release call and keep it on the same reachable path.")
        if (profile.gotos or profile.has_labels) and cap.touches_control_flow:
            notes.append("- This function uses labels/goto-like flow; avoid restructuring those paths.")
        if profile.struct_accesses and cap.creates_helpers:
            notes.append("- If creating helpers, pass every required struct/pointer dependency explicitly.")
        blockers = cls.blocker_reasons(profile, cap)
        if blockers:
            notes.append(f"- Policy blockers for risky sub-transforms: {', '.join(blockers)}.")
        return "\n".join(notes) + "\n"

    @classmethod
    def _score_profile(cls, profile: FunctionRiskProfile, language: str) -> None:
        score = 0.0
        hazards: list[str] = []

        def add(amount: float, hazard: str) -> None:
            nonlocal score
            score += amount
            hazards.append(hazard)

        if profile.line_count > 180:
            add(0.22, "very_large_function")
        elif profile.line_count > 90:
            add(0.12, "large_function")
        if profile.returns > 3:
            add(0.12, "many_returns")
        if profile.gotos:
            add(0.20, "goto_present")
        if profile.has_labels:
            add(0.12, "labels_present")
        if profile.loops + profile.switches > 4:
            add(0.12, "complex_control_flow")
        if profile.breaks_or_continues > 3:
            add(0.08, "loop_exit_flow")
        if profile.pointer_ops > 30:
            add(0.12, "pointer_heavy")
        if profile.struct_accesses > 15:
            add(0.12, "struct_heavy")
        if profile.macro_lines:
            add(0.10, "preprocessor_in_function")
        if profile.cleanup_calls:
            add(0.10, "resource_cleanup")
        if profile.has_naked:
            add(0.60, "naked_function")
        if profile.has_inline_asm:
            add(0.45, "inline_assembly")
        if profile.has_wide_narrow_mix:
            add(0.14, "mixed_char_width")
        if profile.has_pe_header_usage:
            add(0.18, "pe_header_manipulation")
        if profile.has_seh:
            add(0.22, "seh_scope")
        if profile.has_cpp_exception:
            add(0.16, "cpp_exception_flow")
        if profile.has_template:
            add(0.18, "template_code")
        if profile.has_crypto_pattern:
            add(0.16, "crypto_sensitive_logic")
        if language in ("cpp", "cplusplus", "cxx") and "::" in profile.name:
            add(0.08, "qualified_cpp_method")

        profile.risk_score = min(1.0, score)
        profile.hazards = hazards
        profile.recommended_max_strategy_risk = max(0.18, 1.0 - profile.risk_score * 0.85)
