"""
Win32 Header Index
==================

Builds a best-effort symbol -> SDK header index from the local Windows SDK.

This is intentionally separate from ``win32_type_extractor``: that module
answers "is this a valid type?", while this one answers "which header declares
this identifier?".  The index is cached on disk so normal pipeline runs do not
re-scan the SDK every time.
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

_CACHE_LOCK = threading.Lock()
_HEADER_INDEX: Optional[dict[str, str]] = None
_DISK_CACHE = Path(__file__).parent / "_win32_header_index_cache.json"

_SDK_HEADER_DIRS = ("um", "shared", "ucrt")
_MAX_HEADER_SIZE = 2 * 1024 * 1024

_SKIP_HEADERS = {
    "windows.h",
    "winnt.h",
    "windef.h",
    "minwindef.h",
    "basetsd.h",
    "ntdef.h",
    "winbase.h",
}

_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', re.IGNORECASE | re.MULTILINE)
_DEFINE_RE = re.compile(r'^\s*#\s*define\s+([A-Za-z_]\w*)\b', re.MULTILINE)
_TYPEDEF_NAME_RE = re.compile(
    r'\btypedef\b[^;{}]*(?:\{[^}]*\}[^;]*)?\b([A-Za-z_]\w*)\s*(?:,\s*\*?[A-Za-z_]\w*)*\s*;',
    re.DOTALL,
)
_STRUCT_ALIAS_RE = re.compile(
    r'\btypedef\s+(?:struct|union|enum)\s+(?:[A-Za-z_]\w*)?\s*\{[^}]*\}\s*([^;]+);',
    re.DOTALL,
)
_DECL_RE = re.compile(
    r'^\s*(?:[A-Z_][A-Z0-9_]*\s+){0,4}[A-Za-z_][\w\s\*\&]*\s+([A-Za-z_]\w*)\s*\(',
    re.MULTILINE,
)


def _strip_comments(src: str) -> str:
    src = re.sub(r'/\*.*?\*/', ' ', src, flags=re.DOTALL)
    src = re.sub(r'//[^\n]*', '', src)
    return src


def _find_sdk_version_roots() -> list[Path]:
    roots: list[Path] = []

    include_env = os.environ.get("INCLUDE", "")
    for raw in include_env.split(";"):
        path = Path(raw)
        if path.exists() and path.is_dir():
            roots.append(path)

    for base in (
        Path(r"C:\Program Files (x86)\Windows Kits\10\Include"),
        Path(r"C:\Program Files\Windows Kits\10\Include"),
    ):
        if not base.exists():
            continue
        versions = sorted(
            [p for p in base.iterdir() if p.is_dir() and p.name[:1].isdigit()],
            reverse=True,
        )
        for ver in versions:
            for sub in _SDK_HEADER_DIRS:
                root = ver / sub
                if root.exists():
                    roots.append(root)

    deduped: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        key = str(root.resolve()).lower()
        if key not in seen:
            seen.add(key)
            deduped.append(root)
    return deduped


def _extract_symbols(src: str) -> set[str]:
    clean = _strip_comments(src)
    symbols: set[str] = set()

    symbols.update(m.group(1) for m in _DEFINE_RE.finditer(clean))

    for m in _STRUCT_ALIAS_RE.finditer(clean):
        for part in m.group(1).split(","):
            name = part.strip().lstrip("*").strip()
            if re.fullmatch(r"[A-Za-z_]\w*", name):
                symbols.add(name)

    symbols.update(m.group(1) for m in _TYPEDEF_NAME_RE.finditer(clean))

    for m in _DECL_RE.finditer(clean):
        name = m.group(1)
        if name not in {"if", "for", "while", "switch", "return", "sizeof"}:
            symbols.add(name)

    return symbols


def _build_index() -> dict[str, str]:
    index: dict[str, str] = {}
    parsed = 0

    for root in _find_sdk_version_roots():
        for hdr in root.glob("*.h"):
            header_name = hdr.name.lower()
            if header_name in _SKIP_HEADERS:
                continue
            try:
                if hdr.stat().st_size > _MAX_HEADER_SIZE:
                    continue
                src = hdr.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            parsed += 1
            include_name = f"<{hdr.name}>"
            for symbol in _extract_symbols(src):
                index.setdefault(symbol, include_name)

    logger.info("win32_header_index: parsed %d SDK headers, indexed %d symbols", parsed, len(index))
    return index


def get_win32_header_index(force_refresh: bool = False) -> dict[str, str]:
    global _HEADER_INDEX

    with _CACHE_LOCK:
        if _HEADER_INDEX is not None and not force_refresh:
            return _HEADER_INDEX

        if _DISK_CACHE.exists() and not force_refresh:
            try:
                _HEADER_INDEX = json.loads(_DISK_CACHE.read_text(encoding="utf-8"))
                return _HEADER_INDEX
            except Exception as exc:  # noqa: BLE001
                logger.debug("win32_header_index: cache load failed: %s", exc)

        _HEADER_INDEX = _build_index()
        try:
            _DISK_CACHE.write_text(json.dumps(_HEADER_INDEX, indent=2, sort_keys=True), encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            logger.debug("win32_header_index: cache write failed: %s", exc)
        return _HEADER_INDEX


def headers_for_symbols(symbols: set[str]) -> dict[str, str]:
    index = get_win32_header_index()
    resolved: dict[str, str] = {}
    for symbol in symbols:
        if symbol in index:
            resolved[symbol] = index[symbol]
            continue

        # Win32 APIs are often exposed through encoding-neutral macros:
        # ShellExecute -> ShellExecuteA/ShellExecuteW, CreateFile -> CreateFileA/W.
        # Compiler diagnostics report the macro name, while SDK headers index the
        # concrete A/W declarations. Resolve that relationship generically.
        ansi = f"{symbol}A"
        wide = f"{symbol}W"
        if ansi in index and wide in index and index[ansi] == index[wide]:
            resolved[symbol] = index[ansi]
        elif wide in index:
            resolved[symbol] = index[wide]
        elif ansi in index:
            resolved[symbol] = index[ansi]
    return resolved
