"""
Win32 / CRT function pointer signature validator.

Parses function pointer declarations of the form:
    TYPE (CALLCONV *_pfApiName)(PARAM, PARAM, ...) = NULL;

and validates them against the known signature database in
configs/win32_knowledge.json.

Reports:
  - Wrong return type   (e.g. BOOL *_pfstrtok → should be char*)
  - Unknown Win32 types (e.g. LPOOVERLAPPED → not a valid type)

Returns a formatted diagnostic block ready to inject into an LLM
fix prompt so the model can self-correct — no hardcoded API rules.
"""

import json
import logging
import os
import re
from typing import Dict, List, NamedTuple, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Load win32_knowledge.json ──────────────────────────────────────
_KNOWLEDGE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "configs", "win32_knowledge.json",
)
_knowledge_cache: Optional[dict] = None


def _load_knowledge() -> dict:
    global _knowledge_cache
    if _knowledge_cache is not None:
        return _knowledge_cache
    try:
        with open(_KNOWLEDGE_PATH, "r", encoding="utf-8") as f:
            _knowledge_cache = json.load(f)
    except Exception as e:
        logger.debug(f"win32_signature_validator: could not load knowledge: {e}")
        _knowledge_cache = {}
    return _knowledge_cache


# ── Extra CRT / Winsock return types not in win32_knowledge.json ───
# These are added here as a general supplement, NOT project-specific.
# The key is always lowercase for case-insensitive lookup.
_EXTRA_RETURN_TYPES: Dict[str, str] = {
    # CRT string functions
    "strtok": "char *",
    "strtok_s": "char *",
    "strtok_r": "char *",
    "strcpy": "char *",
    "strncpy": "char *",
    "strcat": "char *",
    "strncat": "char *",
    "strchr": "char *",
    "strrchr": "char *",
    "strstr": "char *",
    "strlwr": "char *",
    "strupr": "char *",
    "itoa": "char *",
    "_itoa": "char *",
    # CRT format functions
    "sprintf": "int",
    "snprintf": "int",
    "_snprintf": "int",
    "printf": "int",
    "sscanf": "int",
    # CRT memory
    "memcpy": "void *",
    "memmove": "void *",
    "memset": "void *",
    "memchr": "void *",
    # CRT misc
    "strlen": "size_t",
    "strcmp": "int",
    "strncmp": "int",
    "stricmp": "int",
    "_stricmp": "int",
    "atoi": "int",
    "atol": "long",
    "atof": "double",
    # Winsock
    "send": "int",
    "recv": "int",
    "connect": "int",
    "socket": "SOCKET",
    "closesocket": "int",
    "bind": "int",
    "listen": "int",
    "accept": "SOCKET",
    "gethostbyname": "struct hostent *",
    "inet_addr": "unsigned long",
    "htons": "u_short",
    "htonl": "u_long",
    "ntohs": "u_short",
    "ntohl": "u_long",
    "WSAStartup": "int",
    "WSACleanup": "int",
    "WSAGetLastError": "int",
}

# Calling convention tokens to recognise in declarations
_CALLCONVS = {"WINAPI", "CALLBACK", "APIENTRY", "__stdcall", "__cdecl", "__fastcall"}

# Regex: captures full function pointer declaration
# Group 1: return type (may contain spaces, *, WINAPI etc.)
# Group 2: calling convention (optional)
# Group 3: pointer variable name (e.g. _pfCreateFileA)
# Group 4: parameter list
_FPTR_RE = re.compile(
    r"""
    (?P<ret_type>[\w\s\*]+?)        # return type (greedy but bounded)
    \s*\(\s*
    (?P<callconv>WINAPI|CALLBACK|APIENTRY|__stdcall|__cdecl|__fastcall)?
    \s*\*\s*
    (?P<varname>\w+)                # variable name, e.g. _pfReadFile
    \s*\)\s*
    \((?P<params>[^)]*(?:\([^)]*\)[^)]*)*)\)  # param list (handle nested parens)
    \s*(?:=\s*NULL\s*)?;
    """,
    re.VERBOSE,
)

# Regex to normalise whitespace in a type string
_WS_RE = re.compile(r"\s+")


def _normalise_type(t: str) -> str:
    return _WS_RE.sub(" ", t.strip()).rstrip("*").strip()


def _api_name_from_var(varname: str) -> str:
    """
    Strip common prefixes (_pf, _fn, pf, fn) to recover the API name.
    e.g.  _pfCreateFileA -> CreateFileA
          _fn0           -> fn0  (opaque — skip)
    """
    for prefix in ("_pf", "_fn", "pf", "fn"):
        if varname.startswith(prefix):
            return varname[len(prefix):]
    return varname


class SignatureIssue(NamedTuple):
    varname: str       # e.g. _pfstrtok
    api_name: str      # recovered API name
    issue: str         # human-readable description
    suggestion: str    # what the correct declaration should look like


def validate_function_pointers(code: str) -> List[SignatureIssue]:
    """
    Scan `code` for Win32/CRT function pointer declarations and return
    a list of SignatureIssue objects for every problem found.

    Two checks are performed:
      1. Return type mismatch  — declared type vs known expected type
      2. Invalid Win32 type    — a param or return type token is not in the
                                 known-valid types set
    """
    knowledge = _load_knowledge()
    func_return_types: Dict[str, str] = dict(knowledge.get("func_return_types", {}))
    # Merge extra CRT/Winsock entries
    for k, v in _EXTRA_RETURN_TYPES.items():
        if k.lower() not in {k2.lower() for k2 in func_return_types}:
            func_return_types[k] = v

    # Build a case-insensitive lookup: api_lower -> canonical_return_type
    rt_lookup: Dict[str, str] = {k.lower(): v for k, v in func_return_types.items()}

    # Valid Win32 type tokens — dynamically discovered from SDK headers + built-in seed
    valid_types = set(knowledge.get("forbidden_defines", []))
    try:
        from win32_type_extractor import get_valid_win32_types
        valid_types |= get_valid_win32_types()
    except Exception as _e:
        logger.debug("win32_signature_validator: type extractor unavailable (%s), using seed", _e)
        # Compact fallback seed — the extractor's _BUILTIN_SEED covers these,
        # but keep them here so the validator stays self-contained if the
        # extractor module is missing entirely.
        valid_types.update({
            "void", "char", "int", "long", "short", "unsigned", "signed",
            "float", "double", "size_t", "const", "struct",
            "ULONG_PTR", "DWORD_PTR", "LONG_PTR", "INT_PTR", "UINT_PTR",
            "SIZE_T", "SSIZE_T", "LPCVOID",
            "LPHANDLE", "PHANDLE", "LPBOOL", "PBOOL",
            "PLONG", "PDWORD", "PULONG", "PUCHAR",
            "HINTERNET", "INTERNET_PORT", "INTERNET_BUFFERSA",
            "SC_HANDLE", "LPSERVICE_STATUS", "SERVICE_STATUS",
            "HLOCAL", "HGLOBAL", "HFILE", "ATOM",
            "HWINSTA", "HDESK", "HTREEITEM",
            "CONDITION_VARIABLE", "CRITICAL_SECTION",
            "SOCKET", "HANDLE", "HMODULE", "HKEY", "HINSTANCE", "HWND",
            "LPOVERLAPPED", "OVERLAPPED", "PHKEY", "REGSAM",
            "LPSECURITY_ATTRIBUTES", "SECURITY_ATTRIBUTES",
            "LPSTARTUPINFOA", "LPSTARTUPINFOW", "LPPROCESS_INFORMATION",
            "LPSTARTUPINFO", "STARTUPINFOA", "STARTUPINFOW", "PROCESS_INFORMATION",
            "SOCKADDR", "LPSOCKADDR", "ADDRINFOA", "PADDRINFOA",
        })

    issues: List[SignatureIssue] = []
    seen_varnames = set()

    for m in _FPTR_RE.finditer(code):
        ret_type_raw = m.group("ret_type").strip()
        varname = m.group("varname")
        params_raw = m.group("params")

        if varname in seen_varnames:
            continue
        seen_varnames.add(varname)

        api_name = _api_name_from_var(varname)
        # Skip short opaque names like _fn0, _fn1 — no way to validate
        if re.fullmatch(r"_?fn\d+|_?pf\d+", api_name, re.IGNORECASE):
            continue

        # ── Check 1: return type mismatch ──
        expected_ret = rt_lookup.get(api_name.lower())
        if expected_ret:
            declared_base = _normalise_type(ret_type_raw).upper()
            expected_base = _normalise_type(expected_ret).upper()
            # Strip pointer markers for base comparison
            declared_base_noptr = declared_base.replace("*", "").strip()
            expected_base_noptr = expected_base.replace("*", "").strip()

            if declared_base_noptr != expected_base_noptr:
                suggestion = (
                    f"{expected_ret} (WINAPI *{varname})({params_raw.strip()}) = NULL;"
                )
                issues.append(SignatureIssue(
                    varname=varname,
                    api_name=api_name,
                    issue=(
                        f"Return type mismatch: declared as '{ret_type_raw.strip()}' "
                        f"but {api_name} returns '{expected_ret}'"
                    ),
                    suggestion=suggestion,
                ))

        # ── Check 2: invalid type tokens in return + params ──
        all_type_tokens = re.findall(r"\b([A-Z_][A-Z0-9_]{2,})\b", ret_type_raw + " " + params_raw)
        for token in all_type_tokens:
            if token in _CALLCONVS:
                continue
            # If it looks like a Win32 type (all-caps or LP/lp prefix) but is
            # not in our known-valid set, flag it
            is_win32_like = (
                token.startswith("LP") or
                token.startswith("P") and len(token) > 2 and token[1].isupper() or
                token.isupper() and len(token) > 3
            )
            if is_win32_like and token not in valid_types:
                issues.append(SignatureIssue(
                    varname=varname,
                    api_name=api_name,
                    issue=(
                        f"Unknown Win32 type '{token}' in declaration of {varname}. "
                        f"This may be a typo."
                    ),
                    suggestion=f"Check the correct type spelling. e.g. LPOVERLAPPED (not LPOOVERLAPPED).",
                ))
                # Only flag once per unknown type per var
                break

    return issues


def format_issues_for_prompt(issues: List[SignatureIssue]) -> str:
    """
    Format a list of SignatureIssue objects into a prompt context block.
    Returns empty string if no issues.
    """
    if not issues:
        return ""

    lines = ["\nWIN32 SIGNATURE VALIDATION WARNINGS (fix these before compiling):\n"]
    for iss in issues:
        lines.append(f"  [{iss.varname}] {iss.issue}")
        if iss.suggestion:
            lines.append(f"    → Correct form: {iss.suggestion}")
    lines.append("")
    return "\n".join(lines)


def validate_and_format(code: str) -> str:
    """
    Convenience function: validate + format in one call.
    Returns empty string if no issues found.
    """
    try:
        issues = validate_function_pointers(code)
        return format_issues_for_prompt(issues)
    except Exception as e:
        logger.debug(f"win32_signature_validator: validation failed: {e}")
        return ""
