"""
Mahoraga Adaptive Auto-Fixer
============================
Inspired by Mahoraga (魔虚羅) from Jujutsu Kaisen — the Shikigami that adapts
after every attack it receives.

This fixer wraps the existing AutoFixer and adds an **adaptation memory**:
  1. Every time the LLM successfully fixes an error, the error pattern and the
     corresponding code transformation are recorded.
  2. On subsequent encounters with a matching error pattern the cached fix is
     replayed *instantly* — no LLM call required.
  3. Confidence scores track how reliable each cached fix is; fixes that later
     fail are down-ranked automatically.

Adaptation levels (like Mahoraga's wheel turning):
  Level 1  –  Pattern-based fixes  (FixStrategies — already exists)
  Level 2  –  Adaptation Memory    (this module — NEW)
  Level 3  –  LLM fix             (AutoFixer cloud/local)
  Level 4  –  Aggressive LLM fix  (allow commenting-out / stubs)
"""

import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime
from difflib import unified_diff
from typing import Any, Dict, List, Optional, Tuple

try:
    from .auto_fixer import AutoFixer
except ImportError:
    from auto_fixer import AutoFixer

try:
    from .error_analyzer import ErrorAnalyzer, ErrorType
except ImportError:
    try:
        from error_analyzer import ErrorAnalyzer, ErrorType
    except ImportError:
        ErrorAnalyzer = None
        ErrorType = None

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_DEFAULT_MEMORY_FILE = "mahoraga_fix_memory.json"
_MIN_CONFIDENCE = 0.3          # Below this the cached fix is skipped
_CONFIDENCE_BOOST = 0.15       # On each success
_CONFIDENCE_PENALTY = 0.25     # On each failure
_MAX_MEMORY_ENTRIES = 2000     # Prune when exceeded


# ---------------------------------------------------------------------------
# Helper — canonical error signature
# ---------------------------------------------------------------------------
def _canonicalize_error(error_msg: str) -> str:
    """
    Strip file paths, line numbers and column numbers so that the same
    *type* of error in different files produces the same signature.

    Example:
        "src/foo.c:42:10: error: implicit declaration of function '_halloc'"
        → "error: implicit declaration of function '_halloc'"
    """
    # Remove leading file:line:col:
    msg = re.sub(r'^[^:]+:\d+:\d+:\s*', '', error_msg.strip())
    # Remove leading file:line:
    msg = re.sub(r'^[^:]+:\d+:\s*', '', msg.strip())
    # Collapse whitespace
    msg = re.sub(r'\s+', ' ', msg).strip()
    return msg


def _error_signature(canonical_error: str) -> str:
    """SHA-256 hex digest of the canonical error string (first 16 chars)."""
    return hashlib.sha256(canonical_error.encode('utf-8')).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Diff helpers — learn regex-replacement rules from before/after code
# ---------------------------------------------------------------------------
def _learn_replacements(
    original: str, fixed: str
) -> List[Dict[str, str]]:
    """
    Compare *original* and *fixed* code and try to extract simple
    search→replace rules (literal string or small regex).

    Returns a list of {"search": ..., "replace": ...} dicts.
    """
    rules: List[Dict[str, str]] = []
    orig_lines = original.splitlines(keepends=True)
    fix_lines = fixed.splitlines(keepends=True)

    diff = list(unified_diff(orig_lines, fix_lines, n=0))

    removed: List[str] = []
    added: List[str] = []

    for line in diff:
        if line.startswith('---') or line.startswith('+++') or line.startswith('@@'):
            # Flush previous hunk
            if removed and added and len(removed) == len(added):
                for r, a in zip(removed, added):
                    r_s = r.strip()
                    a_s = a.strip()
                    if r_s and a_s and r_s != a_s:
                        rules.append({"search": r_s, "replace": a_s})
            removed, added = [], []
            continue
        if line.startswith('-'):
            removed.append(line[1:])
        elif line.startswith('+'):
            added.append(line[1:])

    # Flush last hunk
    if removed and added and len(removed) == len(added):
        for r, a in zip(removed, added):
            r_s = r.strip()
            a_s = a.strip()
            if r_s and a_s and r_s != a_s:
                rules.append({"search": r_s, "replace": a_s})

    return rules


# ---------------------------------------------------------------------------
# FixMemoryEntry
# ---------------------------------------------------------------------------
class FixMemoryEntry:
    """One remembered fix."""

    def __init__(
        self,
        error_signature: str,
        error_canonical: str,
        fix_type: str = "llm_learned",
        replacements: Optional[List[Dict[str, str]]] = None,
        full_fix_code: Optional[str] = None,
        confidence: float = 0.6,
        success_count: int = 1,
        fail_count: int = 0,
        first_seen: Optional[str] = None,
        last_used: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ):
        self.error_signature = error_signature
        self.error_canonical = error_canonical
        self.fix_type = fix_type                    # "regex_replace" | "llm_learned" | "include_add"
        self.replacements = replacements or []       # [{"search": ..., "replace": ...}]
        self.full_fix_code = full_fix_code           # Full fixed code (for complex fixes)
        self.confidence = confidence
        self.success_count = success_count
        self.fail_count = fail_count
        self.first_seen = first_seen or datetime.now().isoformat()
        self.last_used = last_used or datetime.now().isoformat()
        self.tags = tags or []

    # -- serialization -------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_signature": self.error_signature,
            "error_canonical": self.error_canonical,
            "fix_type": self.fix_type,
            "replacements": self.replacements,
            "confidence": round(self.confidence, 4),
            "success_count": self.success_count,
            "fail_count": self.fail_count,
            "first_seen": self.first_seen,
            "last_used": self.last_used,
            "tags": self.tags,
            # NOTE: full_fix_code intentionally NOT persisted (too large)
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FixMemoryEntry":
        return cls(
            error_signature=d["error_signature"],
            error_canonical=d["error_canonical"],
            fix_type=d.get("fix_type", "llm_learned"),
            replacements=d.get("replacements", []),
            confidence=d.get("confidence", 0.6),
            success_count=d.get("success_count", 1),
            fail_count=d.get("fail_count", 0),
            first_seen=d.get("first_seen"),
            last_used=d.get("last_used"),
            tags=d.get("tags", []),
        )

    # -- confidence helpers --------------------------------------------------
    def boost(self):
        self.success_count += 1
        self.confidence = min(1.0, self.confidence + _CONFIDENCE_BOOST)
        self.last_used = datetime.now().isoformat()

    def penalize(self):
        self.fail_count += 1
        self.confidence = max(0.0, self.confidence - _CONFIDENCE_PENALTY)
        self.last_used = datetime.now().isoformat()

    @property
    def is_reliable(self) -> bool:
        return self.confidence >= _MIN_CONFIDENCE

    def __repr__(self):
        return (
            f"FixMemoryEntry(sig={self.error_signature}, "
            f"conf={self.confidence:.2f}, "
            f"ok={self.success_count}, fail={self.fail_count})"
        )


# ---------------------------------------------------------------------------
# FixMemory — the persistence layer
# ---------------------------------------------------------------------------
class FixMemory:
    """
    In-memory + JSON-file database of learned fixes.
    Think of it as Mahoraga's wheel: each successful adaptation turns it once.
    """

    def __init__(self, memory_file: Optional[str] = None):
        self.memory_file = memory_file or _DEFAULT_MEMORY_FILE
        self._entries: Dict[str, FixMemoryEntry] = {}  # sig → entry
        self._load()

    # -- persistence ---------------------------------------------------------
    def _load(self):
        if os.path.exists(self.memory_file):
            try:
                with open(self.memory_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for d in data.get("entries", []):
                    entry = FixMemoryEntry.from_dict(d)
                    self._entries[entry.error_signature] = entry
                logger.info(
                    f"🔄 Mahoraga memory loaded: {len(self._entries)} entries "
                    f"from {self.memory_file}"
                )
            except Exception as e:
                logger.warning(f"Failed to load Mahoraga memory: {e}")

    def save(self):
        # Prune if too big
        if len(self._entries) > _MAX_MEMORY_ENTRIES:
            self._prune()
        try:
            data = {
                "version": "1.0",
                "updated": datetime.now().isoformat(),
                "total_entries": len(self._entries),
                "entries": [e.to_dict() for e in self._entries.values()],
            }
            os.makedirs(os.path.dirname(self.memory_file) or ".", exist_ok=True)
            with open(self.memory_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.debug(f"Mahoraga memory saved ({len(self._entries)} entries)")
        except Exception as e:
            logger.warning(f"Failed to save Mahoraga memory: {e}")

    def _prune(self):
        """Remove low-confidence and old entries to stay within limits."""
        sorted_entries = sorted(
            self._entries.values(),
            key=lambda e: (e.confidence, e.success_count),
        )
        to_remove = len(self._entries) - _MAX_MEMORY_ENTRIES
        for entry in sorted_entries[:to_remove]:
            del self._entries[entry.error_signature]
        logger.info(f"Pruned {to_remove} low-confidence entries from Mahoraga memory")

    # -- lookup & mutation ---------------------------------------------------
    def lookup(self, canonical_error: str) -> Optional[FixMemoryEntry]:
        sig = _error_signature(canonical_error)
        entry = self._entries.get(sig)
        if entry and entry.is_reliable:
            return entry
        return None

    def record(
        self,
        canonical_error: str,
        replacements: List[Dict[str, str]],
        fix_type: str = "llm_learned",
        tags: Optional[List[str]] = None,
    ) -> FixMemoryEntry:
        sig = _error_signature(canonical_error)
        if sig in self._entries:
            # Already known — boost confidence
            self._entries[sig].boost()
            # Merge new replacements if any
            existing_searches = {r["search"] for r in self._entries[sig].replacements}
            for r in replacements:
                if r["search"] not in existing_searches:
                    self._entries[sig].replacements.append(r)
            return self._entries[sig]

        entry = FixMemoryEntry(
            error_signature=sig,
            error_canonical=canonical_error,
            fix_type=fix_type,
            replacements=replacements,
            tags=tags,
        )
        self._entries[sig] = entry
        logger.info(f"⚙️  Mahoraga adapted to new error: {canonical_error[:80]}…")
        return entry

    def boost(self, canonical_error: str):
        sig = _error_signature(canonical_error)
        if sig in self._entries:
            self._entries[sig].boost()

    def penalize(self, canonical_error: str):
        sig = _error_signature(canonical_error)
        if sig in self._entries:
            self._entries[sig].penalize()

    # -- stats ---------------------------------------------------------------
    def stats(self) -> Dict[str, Any]:
        total = len(self._entries)
        reliable = sum(1 for e in self._entries.values() if e.is_reliable)
        total_successes = sum(e.success_count for e in self._entries.values())
        total_failures = sum(e.fail_count for e in self._entries.values())
        return {
            "total_entries": total,
            "reliable_entries": reliable,
            "total_successes": total_successes,
            "total_failures": total_failures,
            "adaptation_rate": round(total_successes / max(total_successes + total_failures, 1), 4),
        }


# ---------------------------------------------------------------------------
# MahoragaAdaptiveFixer — the main class
# ---------------------------------------------------------------------------
class MahoragaAdaptiveFixer:
    """
    Drop-in replacement (superset) for AutoFixer.

    Adaptation levels:
        1. Pattern fixes      (FixStrategies — instant)
        2. Adaptation Memory  (this class — instant, learned from past LLM fixes)
        3. LLM fix            (AutoFixer — slow, costs API)
        4. Aggressive LLM     (allow comment-out / stub generation)
    """

    def __init__(
        self,
        llm_model: str = "codestral-2508",
        api_key: Optional[str] = None,
        use_hybrid: bool = False,
        local_model: str = "qwen2.5-coder:7b-instruct-q4_K_M",
        cloud_file_size_limit: int = 15000,
        mode: str = "hybrid",
        memory_file: Optional[str] = None,
        enable_learning: bool = True,
    ):
        # Underlying LLM fixer
        self.auto_fixer = AutoFixer(
            llm_model=llm_model,
            api_key=api_key,
            use_hybrid=use_hybrid,
            local_model=local_model,
            cloud_file_size_limit=cloud_file_size_limit,
            mode=mode,
        )

        # Adaptation memory
        self.memory = FixMemory(memory_file=memory_file)
        self.enable_learning = enable_learning

        # Stats for current session
        self._session_stats = {
            "memory_hits": 0,
            "memory_misses": 0,
            "llm_calls": 0,
            "llm_successes": 0,
            "adaptations_learned": 0,
        }

        # Expose llm_provider from inner fixer so callers work unchanged
        self.llm_provider = self.auto_fixer.llm_provider
        self.llm_model = self.auto_fixer.llm_model
        self.use_hybrid = self.auto_fixer.use_hybrid

        wheel_icon = "☸"  # Mahoraga's wheel
        logger.info(
            f"{wheel_icon} Mahoraga Adaptive Fixer initialized "
            f"(memory: {self.memory.stats()['total_entries']} entries, "
            f"learning={'ON' if enable_learning else 'OFF'})"
        )

    # -----------------------------------------------------------------------
    # Public API — same signature as AutoFixer.fix_compilation_errors
    # -----------------------------------------------------------------------
    def fix_compilation_errors(
        self,
        source_code: str,
        errors: List[str],
        language: str = "c",
        max_attempts: int = 3,
        use_pattern_fixes: bool = True,
        max_code_length: int = 50000,
        project_context: Optional[str] = None,
        file_context: Optional[str] = None,
        is_header_file: bool = False,
    ) -> Tuple[str, bool, List[str]]:
        """
        Fix compilation errors using a 4-level adaptive strategy.

        Same return type as AutoFixer.fix_compilation_errors:
            (fixed_code, success, remaining_errors)
        """
        if not errors:
            return source_code, True, []

        t0 = time.time()
        current_code = source_code
        remaining = list(errors)

        # ------------------------------------------------------------------
        # Level 1: Pattern-based fixes (FixStrategies)
        # ------------------------------------------------------------------
        if use_pattern_fixes:
            try:
                try:
                    from .fix_strategies import FixStrategies
                except ImportError:
                    from fix_strategies import FixStrategies
                pattern_fixed = FixStrategies.apply_pattern_fixes(current_code, remaining, language)
                if pattern_fixed != current_code:
                    logger.info("☸ Level-1 (Pattern): applied pattern-based fixes")
                    current_code = pattern_fixed
            except Exception as e:
                logger.debug(f"Pattern fixes skipped: {e}")

        # ------------------------------------------------------------------
        # Level 2: Adaptation Memory (instant replay of learned fixes)
        # ------------------------------------------------------------------
        memory_applied = 0
        for err in list(remaining):
            canonical = _canonicalize_error(err)
            entry = self.memory.lookup(canonical)
            if entry and entry.replacements:
                applied_any = False
                for rule in entry.replacements:
                    search = rule.get("search", "")
                    replace = rule.get("replace", "")
                    if search and search in current_code:
                        current_code = current_code.replace(search, replace, 1)
                        applied_any = True
                if applied_any:
                    memory_applied += 1
                    remaining.remove(err)
                    self.memory.boost(canonical)
                    self._session_stats["memory_hits"] += 1
            else:
                self._session_stats["memory_misses"] += 1

        if memory_applied:
            logger.info(
                f"☸ Level-2 (Adaptation Memory): replayed {memory_applied} "
                f"cached fix(es) — 0 LLM calls"
            )

        # If all errors handled by memory — done!
        if not remaining:
            elapsed = time.time() - t0
            logger.info(f"☸ All errors resolved by adaptation memory in {elapsed:.2f}s")
            return current_code, True, []

        # ------------------------------------------------------------------
        # Level 3: LLM fix (standard)
        # ------------------------------------------------------------------
        logger.info(
            f"☸ Level-3 (LLM): {len(remaining)} error(s) still unresolved, "
            f"calling LLM…"
        )
        self._session_stats["llm_calls"] += 1

        fixed_code, success, still_remaining = self.auto_fixer.fix_compilation_errors(
            source_code=current_code,
            errors=remaining,
            language=language,
            max_attempts=max_attempts,
            use_pattern_fixes=False,       # already done at Level 1
            max_code_length=max_code_length,
            project_context=project_context,
            file_context=file_context,
            is_header_file=is_header_file,
        )

        if success and fixed_code and isinstance(fixed_code, str):
            self._session_stats["llm_successes"] += 1

            # LEARN from this success — store in adaptation memory
            if self.enable_learning:
                self._learn_from_fix(current_code, fixed_code, remaining)

            elapsed = time.time() - t0
            logger.info(f"☸ Level-3 fix succeeded in {elapsed:.2f}s")
            return fixed_code, True, still_remaining

        # ------------------------------------------------------------------
        # Level 4: Aggressive LLM (comment-out / fallback)
        # ------------------------------------------------------------------
        logger.info("☸ Level-4 (Aggressive): attempting fallback strategy…")
        try:
            try:
                from .fix_strategies import FixStrategies
            except ImportError:
                from fix_strategies import FixStrategies

            fallback_code = FixStrategies.apply_fallback_strategy(
                fixed_code if (fixed_code and isinstance(fixed_code, str)) else current_code,
                still_remaining or remaining,
                language=language,
            )
            if fallback_code and fallback_code != current_code:
                elapsed = time.time() - t0
                logger.info(f"☸ Level-4 fallback applied in {elapsed:.2f}s")
                return fallback_code, False, still_remaining or remaining
        except Exception as e:
            logger.debug(f"Level-4 fallback failed: {e}")

        elapsed = time.time() - t0
        logger.warning(f"☸ All 4 levels exhausted in {elapsed:.2f}s — returning best effort")
        best = fixed_code if (fixed_code and isinstance(fixed_code, str)) else current_code
        return best, False, still_remaining or remaining

    # -----------------------------------------------------------------------
    # Delegate other AutoFixer methods so this is a true drop-in
    # -----------------------------------------------------------------------
    def fix_code_issues(self, *args, **kwargs):
        return self.auto_fixer.fix_code_issues(*args, **kwargs)

    def validate_fixed_code(self, *args, **kwargs):
        return self.auto_fixer.validate_fixed_code(*args, **kwargs)

    def safe_header_fix(self, *args, **kwargs):
        return self.auto_fixer.safe_header_fix(*args, **kwargs)

    # -----------------------------------------------------------------------
    # Internal: learning
    # -----------------------------------------------------------------------
    def _learn_from_fix(
        self,
        original_code: str,
        fixed_code: str,
        errors: List[str],
    ):
        """Extract replacement rules from a successful LLM fix and store them."""
        rules = _learn_replacements(original_code, fixed_code)
        if not rules:
            return

        learned = 0
        for err in errors:
            canonical = _canonicalize_error(err)
            # Only store rules that are relevant to this error
            relevant_rules = self._filter_relevant_rules(rules, canonical)
            if relevant_rules:
                self.memory.record(
                    canonical_error=canonical,
                    replacements=relevant_rules,
                    fix_type="llm_learned",
                    tags=[f"errors={len(errors)}"],
                )
                learned += 1

        if learned:
            self._session_stats["adaptations_learned"] += learned
            logger.info(f"☸ Mahoraga learned {learned} new adaptation(s) from LLM fix")
            self.memory.save()

    @staticmethod
    def _filter_relevant_rules(
        rules: List[Dict[str, str]], canonical_error: str
    ) -> List[Dict[str, str]]:
        """
        Heuristic: keep rules whose search string overlaps with keywords in
        the error message.  Falls back to returning all rules if none match
        (better to over-learn than not learn at all).
        """
        # Extract potential identifiers from the error
        tokens = set(re.findall(r"[A-Za-z_]\w+", canonical_error))
        relevant = []
        for rule in rules:
            search_tokens = set(re.findall(r"[A-Za-z_]\w+", rule["search"]))
            if tokens & search_tokens:
                relevant.append(rule)

        return relevant if relevant else rules[:5]  # cap at 5 generic rules

    # -----------------------------------------------------------------------
    # Stats & reporting
    # -----------------------------------------------------------------------
    def get_session_stats(self) -> Dict[str, Any]:
        memory_stats = self.memory.stats()
        return {
            **self._session_stats,
            "memory": memory_stats,
            "llm_call_savings_pct": round(
                self._session_stats["memory_hits"]
                / max(self._session_stats["memory_hits"] + self._session_stats["llm_calls"], 1)
                * 100,
                1,
            ),
        }

    def print_session_report(self):
        stats = self.get_session_stats()
        wheel = "☸"
        print(f"\n{'=' * 60}")
        print(f"{wheel}  MAHORAGA ADAPTIVE FIXER — SESSION REPORT  {wheel}")
        print(f"{'=' * 60}")
        print(f"  Memory hits  (instant fix) : {stats['memory_hits']}")
        print(f"  Memory misses              : {stats['memory_misses']}")
        print(f"  LLM calls                  : {stats['llm_calls']}")
        print(f"  LLM successes              : {stats['llm_successes']}")
        print(f"  New adaptations learned    : {stats['adaptations_learned']}")
        print(f"  LLM call savings           : {stats['llm_call_savings_pct']:.1f}%")
        print(f"  ---")
        print(f"  Total memory entries       : {stats['memory']['total_entries']}")
        print(f"  Reliable entries           : {stats['memory']['reliable_entries']}")
        print(f"  Overall adaptation rate    : {stats['memory']['adaptation_rate'] * 100:.1f}%")
        print(f"{'=' * 60}\n")

    def save_memory(self):
        """Persist adaptation memory to disk."""
        self.memory.save()
