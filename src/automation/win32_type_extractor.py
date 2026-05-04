"""
Win32 Type Extractor
====================
Dynamically discovers valid Win32/CRT type names by:

  1. Parsing Windows SDK header files (winnt.h, basetsd.h, WinBase.h, …)
     — ground truth, covers every typedef the SDK defines.

  2. Parsing the malware project's own .h/.c/.cpp files
     — picks up project-specific typedefs not in the SDK.

Results are cached in memory (per-process) and optionally on disk.
Falls back to a compact built-in seed set if the SDK is not found.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── In-process cache ────────────────────────────────────────────────────────
_CACHE_LOCK  = threading.Lock()
_SDK_TYPES:   Optional[frozenset[str]] = None      # from SDK headers
_SEED_TYPES:  Optional[frozenset[str]] = None      # built-in fallback

# On-disk cache next to this file
_DISK_CACHE = Path(__file__).parent / "_win32_type_cache.json"

# ── Well-known SDK header paths (relative to an "Include/<ver>/<sub>" root) ─
# Ordered by importance: parse fewer files to get the most useful types first.
_SDK_HEADERS_UM = [
    "winnt.h",       # HANDLE, BOOL, DWORD, LP*, ULONG_PTR, …
    "WinBase.h",     # CreateFile, WriteFile, … most LPSECURITY_ATTRIBUTES etc.
    "minwindef.h",   # BYTE, WORD, DWORD, UINT, LPVOID, LPCVOID, …
    "handleapi.h",
    "fileapi.h",
    "processthreadsapi.h",
    "synchapi.h",
    "memoryapi.h",
    "winsvc.h",      # SC_HANDLE, SERVICE_STATUS, …
    "wininet.h",     # HINTERNET, …
    "winreg.h",      # HKEY, REGSAM, PHKEY, …
    "winsock2.h",    # SOCKET, SOCKADDR, WSADATA, …
    "ws2tcpip.h",
    "shellapi.h",
    "shlobj.h",
    "commctrl.h",
]
_SDK_HEADERS_SHARED = [
    "ntdef.h",       # NT types: NTSTATUS, UNICODE_STRING, …
    "basetsd.h",     # ULONG_PTR, DWORD_PTR, INT_PTR, SIZE_T, …
    "guiddef.h",
    "minwindef.h",
]

# Regex: match typedef lines.  Captures the final identifier (the new type name).
# Handles:
#   typedef DWORD ULONG;                     → ULONG
#   typedef VOID *PVOID, *LPVOID;            → PVOID, LPVOID
#   typedef struct _FOO { ... } FOO, *PFOO;  → FOO, PFOO
#   typedef VOID (WINAPI *FARPROC)();        → FARPROC
_TYPEDEF_RE = re.compile(
    r"""
    \btypedef\b          # keyword
    (?:[^;{(]|           # simple typedef body (no brace / paren)
       \{[^}]*\}|        # struct / union body
       \([^)]*\)         # function pointer return parens
    )*?
    (                    # capture group: names before the semicolon
        (?:\*\s*)?       # optional pointer star
        [A-Za-z_]\w*     # first name
        (?:\s*,\s*(?:\*\s*)?[A-Za-z_]\w*)*  # optional comma-separated names
    )
    \s*;
    """,
    re.VERBOSE | re.DOTALL,
)

# Simpler fallback for common patterns that the above might miss
_SIMPLE_TYPEDEF_RE = re.compile(
    r'\btypedef\b[^;]+\b([A-Z_][A-Z0-9_]{1,})\s*;'
)

# Strip C/C++ line comments and block comments before parsing
_LINE_COMMENT_RE   = re.compile(r'//[^\n]*')
_BLOCK_COMMENT_RE  = re.compile(r'/\*.*?\*/', re.DOTALL)
_PREPROCESSOR_RE   = re.compile(r'^\s*#[^\n]*(\\\n[^\n]*)*', re.MULTILINE)


def _strip_comments(src: str) -> str:
    src = _BLOCK_COMMENT_RE.sub(' ', src)
    src = _LINE_COMMENT_RE.sub('', src)
    return src


def _extract_typedef_names(src: str) -> set[str]:
    """Return all type names introduced by typedef in *src*."""
    src = _strip_comments(src)
    names: set[str] = set()

    for m in _TYPEDEF_RE.finditer(src):
        raw = m.group(1)
        for part in raw.split(','):
            name = part.strip().lstrip('*').strip()
            if name and re.fullmatch(r'[A-Za-z_]\w*', name):
                names.add(name)

    # Second pass: simpler pattern for all-caps names (catches pointer typedefs
    # that the complex regex may miss due to nested parens)
    for m in _SIMPLE_TYPEDEF_RE.finditer(src):
        name = m.group(1).strip()
        if name and re.fullmatch(r'[A-Za-z_]\w*', name):
            names.add(name)

    return names


def _find_sdk_include_roots() -> list[Path]:
    """Return candidate Windows SDK Include/<version>/ directories."""
    roots: list[Path] = []

    # 1. From INCLUDE env var (set by vcvarsall.bat)
    env_include = os.environ.get('INCLUDE', '')
    for p in env_include.split(';'):
        pp = Path(p)
        if pp.exists():
            roots.append(pp)

    # 2. Standard install locations
    kit_bases = [
        Path(r'C:\Program Files (x86)\Windows Kits\10\Include'),
        Path(r'C:\Program Files\Windows Kits\10\Include'),
    ]
    for base in kit_bases:
        if base.exists():
            # Enumerate versioned sub-dirs, newest first
            versions = sorted(
                [d for d in base.iterdir() if d.is_dir() and d.name[0].isdigit()],
                reverse=True,
            )
            for ver in versions:
                roots.append(ver / 'um')
                roots.append(ver / 'shared')

    return roots


def _parse_sdk_headers() -> set[str]:
    """Parse key SDK headers and return all typedef names found."""
    roots = _find_sdk_include_roots()
    names: set[str] = set()
    parsed: list[str] = []
    failed: list[str] = []

    wanted = {h.lower() for h in _SDK_HEADERS_UM + _SDK_HEADERS_SHARED}

    for root in roots:
        if not root.exists():
            continue
        for hdr_path in root.iterdir():
            if not hdr_path.is_file():
                continue
            if hdr_path.name.lower() not in wanted:
                continue
            try:
                src = hdr_path.read_text(encoding='utf-8', errors='replace')
                new_names = _extract_typedef_names(src)
                names.update(new_names)
                parsed.append(hdr_path.name)
            except Exception as exc:
                failed.append(f"{hdr_path.name}: {exc}")

    if parsed:
        logger.debug("win32_type_extractor: parsed SDK headers %s → %d types",
                     parsed, len(names))
    if failed:
        logger.debug("win32_type_extractor: skipped %s", failed)

    return names


def extract_from_source_files(source_dirs: list[str | Path]) -> set[str]:
    """
    Extract typedef names from a malware project's own headers and source files.

    Call this with the project's source directory so project-specific types
    (e.g. custom struct typedefs, platform abstraction layer types) are also
    accepted by the validator without manual whitelisting.
    """
    names: set[str] = set()
    exts  = {'.h', '.hpp', '.c', '.cpp', '.hxx'}

    for src_dir in source_dirs:
        base = Path(src_dir)
        if not base.exists():
            continue
        for path in base.rglob('*'):
            if not path.is_file() or path.suffix.lower() not in exts:
                continue
            if path.stat().st_size > 2 * 1024 * 1024:  # skip files > 2 MB
                continue
            try:
                src = path.read_text(encoding='utf-8', errors='replace')
                names.update(_extract_typedef_names(src))
            except Exception:
                pass

    logger.debug("win32_type_extractor: source extraction → %d types", len(names))
    return names


# ── Built-in seed (compact, never changes) ──────────────────────────────────
# Only C primitives + types we know are always missing from win32_knowledge.json.
# The SDK parser fills in everything else.
_BUILTIN_SEED: frozenset[str] = frozenset({
    # C primitives
    "void", "char", "int", "long", "short", "unsigned", "signed",
    "float", "double", "size_t", "const", "struct",
    # Pointer-sized integers (basetsd.h — often missing from JSON)
    "ULONG_PTR", "DWORD_PTR", "LONG_PTR", "INT_PTR", "UINT_PTR",
    "SIZE_T", "SSIZE_T",
    # const-void pointer (winnt.h — most commonly hallucinated by LLM)
    "LPCVOID",
    # Pointer-to-pointer and rare handle types
    "LPHANDLE", "PHANDLE", "LPBOOL", "PBOOL",
    "PLONG", "PDWORD", "PULONG", "PUCHAR",
    # Internet / WinInet
    "HINTERNET", "INTERNET_PORT",
    # Service Control
    "SC_HANDLE", "LPSERVICE_STATUS", "SERVICE_STATUS",
    # Misc handles
    "HLOCAL", "HGLOBAL", "HFILE", "ATOM", "HWINSTA", "HDESK", "HTREEITEM",
    # Sync / mem objects
    "CONDITION_VARIABLE", "CRITICAL_SECTION",
    # Winsock extras
    "SOCKADDR", "LPSOCKADDR", "ADDRINFOA", "PADDRINFOA",
    # Common structs / pointers
    "LPOVERLAPPED", "OVERLAPPED", "PHKEY", "REGSAM",
    "LPSECURITY_ATTRIBUTES", "LPSTARTUPINFOA", "LPSTARTUPINFOW",
    "LPPROCESS_INFORMATION",
})


def _load_disk_cache() -> Optional[set[str]]:
    try:
        if _DISK_CACHE.exists():
            data = json.loads(_DISK_CACHE.read_text(encoding='utf-8'))
            return set(data.get('types', []))
    except Exception:
        pass
    return None


def _save_disk_cache(types: set[str]) -> None:
    try:
        _DISK_CACHE.write_text(
            json.dumps({'types': sorted(types)}, ensure_ascii=True, indent=None),
            encoding='utf-8',
        )
    except Exception:
        pass


def get_valid_win32_types(
    extra_source_dirs: Optional[list[str | Path]] = None,
    use_disk_cache: bool = True,
) -> frozenset[str]:
    """
    Return the full set of valid Win32/CRT type identifiers.

    Sources (combined):
      1. Windows SDK header typedefs (parsed once per process, then cached)
      2. Project source typedefs (if *extra_source_dirs* provided)
      3. Built-in seed (always included as fallback)

    The result is a frozenset of identifier strings (case-sensitive, as in C).
    """
    global _SDK_TYPES

    with _CACHE_LOCK:
        if _SDK_TYPES is None:
            # Try disk cache first
            disk = _load_disk_cache() if use_disk_cache else None
            if disk is not None and len(disk) > 200:
                _SDK_TYPES = frozenset(disk)
                logger.debug("win32_type_extractor: loaded %d types from disk cache",
                             len(_SDK_TYPES))
            else:
                sdk = _parse_sdk_headers()
                combined = sdk | set(_BUILTIN_SEED)
                _SDK_TYPES = frozenset(combined)
                if use_disk_cache and sdk:
                    _save_disk_cache(combined)
                logger.info("win32_type_extractor: discovered %d Win32 types "
                            "(SDK: %d, seed: %d)",
                            len(_SDK_TYPES), len(sdk), len(_BUILTIN_SEED))

        base = _SDK_TYPES

    # Project-level source files (not cached globally — caller may vary)
    if extra_source_dirs:
        project_types = extract_from_source_files(extra_source_dirs)
        if project_types:
            return base | frozenset(project_types)

    return base


def invalidate_cache() -> None:
    """Force re-parse on next call (useful after SDK installation)."""
    global _SDK_TYPES
    with _CACHE_LOCK:
        _SDK_TYPES = None
    if _DISK_CACHE.exists():
        try:
            _DISK_CACHE.unlink()
        except Exception:
            pass
