"""
MSVC compiler error documentation fetcher.

Fetches concise explanations for MSVC Cxxxx error codes from Microsoft Learn,
caches them locally, and returns short excerpts to inject into LLM fix prompts.

Usage:
    from .msvc_doc_fetcher import enrich_errors_with_msvc_docs
    extra_context = enrich_errors_with_msvc_docs(["C2086", "C2197"])
"""

import json
import logging
import os
import re
import time
import urllib.parse
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Local cache file path (lives next to this file)
_CACHE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "msvc_doc_cache.json")

# Base URL template for MSVC error docs on Microsoft Learn
_DOC_URL_TEMPLATE = (
    "https://learn.microsoft.com/en-us/cpp/error-messages/"
    "compiler-errors-{bucket}/compiler-error-c{code_lower}"
    "?view=msvc-170"
)

# Maximum characters to extract per doc page
_MAX_EXCERPT_LEN = 600

# How long to keep each cache entry (seconds) — 30 days
_CACHE_TTL = 30 * 24 * 3600

_cache: Optional[Dict[str, dict]] = None


def _load_cache() -> Dict[str, dict]:
    global _cache
    if _cache is not None:
        return _cache
    if os.path.exists(_CACHE_PATH):
        try:
            with open(_CACHE_PATH, "r", encoding="utf-8") as f:
                _cache = json.load(f)
        except Exception:
            _cache = {}
    else:
        _cache = {}
    return _cache


def _save_cache(cache: Dict[str, dict]) -> None:
    try:
        with open(_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.debug(f"msvc_doc_fetcher: cache save failed: {e}")


def _error_code_to_url(code: str) -> Optional[str]:
    """
    Map a code like 'C2086' to the correct Microsoft Learn URL.

    Microsoft organises pages by bucket:
      C2000-C2999 → compiler-errors-1
      C3000-C3999 → compiler-errors-2
    """
    m = re.match(r"[Cc](\d+)", code)
    if not m:
        return None
    num = int(m.group(1))
    if 2000 <= num <= 2999:
        bucket = "1"
    elif 3000 <= num <= 3999:
        bucket = "2"
    else:
        return None  # Other ranges (C4xxx warnings etc.) — skip
    return _DOC_URL_TEMPLATE.format(bucket=bucket, code_lower=str(num))


def _fetch_url(url: str, timeout: int = 8) -> Optional[str]:
    """Fetch URL content using urllib (no third-party deps needed)."""
    try:
        import urllib.request
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
                "Accept-Language": "en-US,en;q=0.9",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            charset = resp.headers.get_content_charset() or "utf-8"
            return raw.decode(charset, errors="replace")
    except Exception as e:
        logger.debug(f"msvc_doc_fetcher: fetch failed for {url}: {e}")
        return None


def _extract_text_from_html(html: str) -> str:
    """
    Strip HTML tags and extract readable text.
    Also removes script/style blocks and collapses whitespace.
    """
    # Remove script/style blocks
    html = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    # Remove all tags
    text = re.sub(r"<[^>]+>", " ", html)
    # Decode common HTML entities
    text = text.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
    text = text.replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " ")
    text = re.sub(r"&#\d+;", " ", text)
    text = re.sub(r"&\w+;", " ", text)
    # Collapse whitespace
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _extract_error_section(full_text: str, code: str) -> str:
    """
    Try to find and return the relevant 'Remarks / Possible cause' section
    from the full page text.
    """
    # Look for the section starting around the error code heading
    # Common patterns: "Compiler Error C2086", "Remarks", "Possible cause"
    patterns = [
        rf"Compiler Error {re.escape(code.upper())}(.{{200,1500}})",
        r"Remarks(.{100,800})",
        r"Possible cause(.{100,600})",
        r"This error occurs(.{100,500})",
        r"The compiler(.{100,500})",
    ]
    for pat in patterns:
        m = re.search(pat, full_text, re.IGNORECASE | re.DOTALL)
        if m:
            excerpt = m.group(0).strip()
            # Clean up and truncate
            excerpt = re.sub(r"\s+", " ", excerpt)
            return excerpt[:_MAX_EXCERPT_LEN]
    # Fallback: return first meaningful paragraph
    lines = [ln.strip() for ln in full_text.split("\n") if len(ln.strip()) > 40]
    return " ".join(lines[:3])[:_MAX_EXCERPT_LEN]


def _search_duckduckgo(code: str) -> Optional[str]:
    """
    Fallback: search DuckDuckGo HTML for the MSVC error code and return
    the snippet of the first relevant result.

    Uses the no-JS HTML endpoint which returns plain search-result markup.
    No API key required.
    """
    query = f"MSVC {code} compiler error C++ cause fix"
    encoded = urllib.parse.quote_plus(query)
    url = f"https://html.duckduckgo.com/html/?q={encoded}"

    html = _fetch_url(url, timeout=10)
    if not html:
        return None

    # DDG HTML result snippets are inside <a class="result__snippet">...
    # or within <div class="result__body"> — extract first few.
    snippets: List[str] = []
    for m in re.finditer(
        r'class="result__snippet"[^>]*>(.*?)</a>',
        html,
        re.IGNORECASE | re.DOTALL,
    ):
        text = _extract_text_from_html(m.group(1))
        text = re.sub(r"\s+", " ", text).strip()
        if len(text) > 30 and code.upper() in text.upper():
            snippets.append(text)
        if len(snippets) >= 3:
            break

    if not snippets:
        # Broader fallback: just grab first 3 snippets regardless of code mention
        for m in re.finditer(
            r'class="result__snippet"[^>]*>(.*?)</a>',
            html,
            re.IGNORECASE | re.DOTALL,
        ):
            text = _extract_text_from_html(m.group(1))
            text = re.sub(r"\s+", " ", text).strip()
            if len(text) > 30:
                snippets.append(text)
            if len(snippets) >= 2:
                break

    if not snippets:
        return None

    combined = " | ".join(snippets)
    return combined[:_MAX_EXCERPT_LEN]


def fetch_msvc_doc(code: str) -> Optional[str]:
    """
    Fetch and return a short excerpt for a single MSVC error code.

    Strategy:
      1. Check local cache (TTL 30 days)
      2. Fetch from Microsoft Learn (learn.microsoft.com)
      3. If that fails, fallback to DuckDuckGo web search snippets
      4. Cache whichever source succeeded

    Returns None if all sources fail or code is unsupported.
    """
    code = code.upper().lstrip("C").lstrip("0")  # normalise
    full_code = "C" + code.zfill(4)

    cache = _load_cache()
    entry = cache.get(full_code)
    now = time.time()

    if entry and (now - entry.get("ts", 0)) < _CACHE_TTL:
        return entry.get("excerpt")

    excerpt: Optional[str] = None
    source = "mslearn"

    # ── Primary: Microsoft Learn ──
    url = _error_code_to_url(full_code)
    if url:
        html = _fetch_url(url)
        if html:
            # Detect auth-wall responses — MS Learn sometimes requires login
            if "requires authorization" not in html and "sign in or changing directories" not in html:
                text = _extract_text_from_html(html)
                excerpt = _extract_error_section(text, full_code)

    # ── Fallback: DuckDuckGo ──
    if not excerpt:
        source = "duckduckgo"
        logger.debug(f"msvc_doc_fetcher: MS Learn failed for {full_code}, trying DuckDuckGo")
        excerpt = _search_duckduckgo(full_code)

    if not excerpt:
        return None

    cache[full_code] = {"ts": now, "excerpt": excerpt, "source": source}
    _save_cache(cache)
    logger.debug(f"msvc_doc_fetcher: cached doc for {full_code} (source={source})")
    return excerpt


def enrich_errors_with_msvc_docs(
    error_codes: List[str],
    max_codes: int = 5,
) -> str:
    """
    Given a list of MSVC error codes (e.g. ['C2086', 'C2197']),
    fetch docs for each unique code and return a formatted context block
    ready to inject into an LLM prompt.

    Returns an empty string if nothing useful was found.
    """
    seen = []
    for c in error_codes:
        cu = c.upper()
        if cu not in seen:
            seen.append(cu)
        if len(seen) >= max_codes:
            break

    sections: List[str] = []
    for code in seen:
        try:
            excerpt = fetch_msvc_doc(code)
            if excerpt:
                sections.append(f"[MSVC Docs — {code}] {excerpt}")
        except Exception as e:
            logger.debug(f"msvc_doc_fetcher: error for {code}: {e}")

    if not sections:
        return ""

    header = "\nMSVC OFFICIAL DOCUMENTATION FOR ERRORS IN THIS FILE:\n"
    body = "\n\n".join(sections)
    return header + body + "\n"


def extract_error_codes_from_errors(errors: List[str]) -> List[str]:
    """Parse MSVC 'Cxxxx' error codes out of raw compiler error strings."""
    codes = []
    for err in errors:
        for m in re.finditer(r"\b(C[2-3]\d{3})\b", err, re.IGNORECASE):
            code = m.group(1).upper()
            if code not in codes:
                codes.append(code)
    return codes
