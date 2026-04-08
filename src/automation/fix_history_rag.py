"""
Fix History RAG — Lightweight Retrieval-Augmented Generation for compilation fix history.

Stores successful fix patterns and retrieves similar ones as dynamic few-shot examples.
Zero external dependencies beyond numpy (already available).

Architecture:
  Storage: JSON file (one record per successful fix)
  Indexing: TF-IDF on error codes + error keywords (numpy vectors)
  Retrieval: Cosine similarity → top-k most similar past fixes
  Output: Formatted few-shot examples for injection into LLM prompts
"""

import json
import logging
import os
import re
import time
import hashlib
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# ── Error code patterns for MSVC and GCC ──
_MSVC_CODE_RE = re.compile(r'\b(C\d{4}|LNK\d{4})\b')
_GCC_CODE_RE = re.compile(r'\b(error|warning):\s')
_IDENT_RE = re.compile(r"'([^']{1,60})'")  # identifiers in quotes


class FixRecord:
    """A single stored fix record."""
    __slots__ = (
        'record_id', 'error_codes', 'error_keywords', 'error_text_sample',
        'fix_summary', 'language', 'timestamp', 'metadata', 'is_negative',
    )

    def __init__(
        self,
        record_id: str,
        error_codes: List[str],
        error_keywords: List[str],
        error_text_sample: str,
        fix_summary: str,
        language: str = "c",
        timestamp: float = 0.0,
        metadata: Optional[Dict] = None,
        is_negative: bool = False,
    ):
        self.record_id = record_id
        self.error_codes = error_codes
        self.error_keywords = error_keywords
        self.error_text_sample = error_text_sample
        self.fix_summary = fix_summary
        self.language = language
        self.timestamp = timestamp or time.time()
        self.metadata = metadata or {}
        self.is_negative = is_negative

    def to_dict(self) -> dict:
        return {
            'record_id': self.record_id,
            'error_codes': self.error_codes,
            'error_keywords': self.error_keywords,
            'error_text_sample': self.error_text_sample,
            'fix_summary': self.fix_summary,
            'language': self.language,
            'timestamp': self.timestamp,
            'metadata': self.metadata,
            'is_negative': self.is_negative,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'FixRecord':
        return cls(
            record_id=d['record_id'],
            error_codes=d.get('error_codes', []),
            error_keywords=d.get('error_keywords', []),
            error_text_sample=d.get('error_text_sample', ''),
            fix_summary=d.get('fix_summary', ''),
            language=d.get('language', 'c'),
            timestamp=d.get('timestamp', 0.0),
            metadata=d.get('metadata', {}),
            is_negative=d.get('is_negative', False),
        )


class FixHistoryRAG:
    """
    Lightweight RAG for compilation fix history.

    Usage:
        rag = FixHistoryRAG("path/to/fix_history.json")

        # After a successful fix:
        rag.store_fix(errors, original_code, fixed_code, language="c")

        # Before fixing:
        examples = rag.retrieve_similar_fixes(current_errors, top_k=2)
        prompt_section = rag.format_as_few_shot(examples)
    """

    # Maximum records to keep (FIFO eviction)
    MAX_RECORDS = 500

    def __init__(self, storage_path: str):
        self.storage_path = storage_path
        self.records: List[FixRecord] = []
        self._vocabulary: Dict[str, int] = {}  # term → index
        self._idf: Optional[np.ndarray] = None
        self._tfidf_matrix: Optional[np.ndarray] = None
        self._dirty = False  # True when index needs rebuild

        self._load()

    # ──────────────────────────── Storage ────────────────────────────

    def _load(self):
        """Load records from JSON file."""
        if not os.path.exists(self.storage_path):
            self.records = []
            return

        try:
            with open(self.storage_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self.records = [FixRecord.from_dict(r) for r in data.get('records', [])]
            self._dirty = True
            logger.info(f"[RAG] Loaded {len(self.records)} fix records from {self.storage_path}")
        except Exception as e:
            logger.warning(f"[RAG] Failed to load fix history: {e}")
            self.records = []

    def _save(self):
        """Persist records to JSON file."""
        os.makedirs(os.path.dirname(self.storage_path) or '.', exist_ok=True)
        data = {
            'version': 1,
            'record_count': len(self.records),
            'records': [r.to_dict() for r in self.records],
        }
        try:
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"[RAG] Failed to save fix history: {e}")

    # ──────────────────────────── Feature Extraction ────────────────────────────

    @staticmethod
    def _extract_error_codes(errors: List[str]) -> List[str]:
        """Extract MSVC/GCC error codes from error messages."""
        codes = []
        for err in errors:
            for m in _MSVC_CODE_RE.finditer(err):
                code = m.group(1)
                if code not in codes:
                    codes.append(code)
        return codes

    @staticmethod
    def _extract_error_keywords(errors: List[str]) -> List[str]:
        """Extract meaningful keywords from error messages."""
        keywords = []
        # Extract quoted identifiers
        for err in errors:
            for m in _IDENT_RE.finditer(err):
                ident = m.group(1).strip()
                if len(ident) > 1 and ident not in keywords:
                    keywords.append(ident)

        # Extract common error pattern words
        error_text = ' '.join(errors).lower()
        for pattern in [
            'undeclared', 'undefined', 'unresolved', 'redefinition',
            'missing', 'syntax error', 'expected', 'incompatible',
            'implicit', 'conflicting', 'unterminated', 'unbalanced',
            'no such file', 'cannot open', 'multiply defined',
        ]:
            if pattern in error_text:
                keywords.append(pattern)

        return keywords[:20]  # Cap at 20

    @staticmethod
    def _compute_fix_summary(original_code: str, fixed_code: str, max_length: int = 500) -> str:
        """Generate a concise summary of what the fix changed."""
        orig_lines = original_code.splitlines()
        fix_lines = fixed_code.splitlines()

        added = []
        removed = []

        # Simple line-level diff (not a full diff algorithm, but fast)
        orig_set = set(line.strip() for line in orig_lines if line.strip())
        fix_set = set(line.strip() for line in fix_lines if line.strip())

        for line in fix_set - orig_set:
            if line and not line.startswith('//'):
                added.append(line)
        for line in orig_set - fix_set:
            if line and not line.startswith('//'):
                removed.append(line)

        summary_parts = []
        if added:
            summary_parts.append("ADDED:\n" + "\n".join(f"  + {l}" for l in added[:8]))
        if removed:
            summary_parts.append("REMOVED:\n" + "\n".join(f"  - {l}" for l in removed[:8]))

        if not summary_parts:
            return "(no significant changes detected)"

        summary = "\n".join(summary_parts)
        if len(summary) > max_length:
            summary = summary[:max_length] + "\n  ... (truncated)"
        return summary

    # ──────────────────────────── TF-IDF Index ────────────────────────────

    def _build_document(self, record: FixRecord) -> List[str]:
        """Build term list for a record (used as TF-IDF document)."""
        terms = []
        # Error codes get high weight (repeated 3x)
        for code in record.error_codes:
            terms.extend([code] * 3)
        # Error keywords
        terms.extend(record.error_keywords)
        # Language tag
        terms.append(f"lang_{record.language}")
        return terms

    def _build_query_document(self, errors: List[str], language: str = "c") -> List[str]:
        """Build term list for a query."""
        terms = []
        codes = self._extract_error_codes(errors)
        keywords = self._extract_error_keywords(errors)
        for code in codes:
            terms.extend([code] * 3)
        terms.extend(keywords)
        terms.append(f"lang_{language}")
        return terms

    def _rebuild_index(self):
        """Rebuild TF-IDF index from all records."""
        if not self.records:
            self._tfidf_matrix = None
            self._idf = None
            self._vocabulary = {}
            self._dirty = False
            return

        # Build documents
        documents = [self._build_document(r) for r in self.records]

        # Build vocabulary
        vocab = {}
        for doc in documents:
            for term in set(doc):
                if term not in vocab:
                    vocab[term] = len(vocab)
        self._vocabulary = vocab
        vocab_size = len(vocab)

        if vocab_size == 0:
            self._tfidf_matrix = None
            self._idf = None
            self._dirty = False
            return

        n_docs = len(documents)

        # Compute document frequency
        df = np.zeros(vocab_size)
        for doc in documents:
            for term in set(doc):
                if term in vocab:
                    df[vocab[term]] += 1

        # IDF = log(N / (df + 1)) + 1
        self._idf = np.log(n_docs / (df + 1)) + 1.0

        # Build TF-IDF matrix (n_docs × vocab_size)
        self._tfidf_matrix = np.zeros((n_docs, vocab_size))
        for i, doc in enumerate(documents):
            tf = Counter(doc)
            for term, count in tf.items():
                if term in vocab:
                    j = vocab[term]
                    self._tfidf_matrix[i, j] = count * self._idf[j]

            # L2 normalize
            norm = np.linalg.norm(self._tfidf_matrix[i])
            if norm > 0:
                self._tfidf_matrix[i] /= norm

        self._dirty = False
        logger.debug(f"[RAG] TF-IDF index rebuilt: {n_docs} docs, {vocab_size} terms")

    # ──────────────────────────── Store ────────────────────────────

    def store_fix(
        self,
        errors: List[str],
        original_code: str,
        fixed_code: str,
        language: str = "c",
        metadata: Optional[Dict] = None,
    ) -> str:
        """
        Store a successful fix pattern.

        Returns:
            record_id of the stored fix
        """
        error_codes = self._extract_error_codes(errors)
        error_keywords = self._extract_error_keywords(errors)

        # Create a hash-based ID from error codes + first error line
        id_source = "|".join(error_codes) + "|" + (errors[0][:100] if errors else "")
        record_id = hashlib.md5(id_source.encode()).hexdigest()[:12]

        # Check for near-duplicate (>= 60% error code overlap, same polarity)
        for existing in self.records:
            if existing.language != language or existing.is_negative:
                continue
            if not existing.error_codes and not error_codes:
                continue
            # Jaccard-like overlap: |intersection| / |union|
            s_old = set(existing.error_codes)
            s_new = set(error_codes)
            union = s_old | s_new
            overlap = len(s_old & s_new) / len(union) if union else 0.0
            if overlap >= 0.60:
                # Update existing record with newer fix
                existing.fix_summary = self._compute_fix_summary(original_code, fixed_code)
                existing.error_keywords = error_keywords
                existing.error_text_sample = "\n".join(errors[:3])
                existing.timestamp = time.time()
                existing.metadata = metadata or existing.metadata
                self._dirty = True
                self._save()
                logger.info(f"[RAG] Updated existing fix record: {existing.record_id} ({error_codes})")
                return existing.record_id

        fix_summary = self._compute_fix_summary(original_code, fixed_code)

        record = FixRecord(
            record_id=record_id,
            error_codes=error_codes,
            error_keywords=error_keywords,
            error_text_sample="\n".join(errors[:3]),
            fix_summary=fix_summary,
            language=language,
            timestamp=time.time(),
            metadata=metadata or {},
        )

        self.records.append(record)

        # FIFO eviction
        if len(self.records) > self.MAX_RECORDS:
            self.records = self.records[-self.MAX_RECORDS:]

        self._dirty = True
        self._save()
        logger.info(
            f"[RAG] Stored fix record: {record_id} | "
            f"codes={error_codes} | keywords={error_keywords[:5]}"
        )
        return record_id

    def store_negative_fix(
        self,
        errors: List[str],
        original_code: str,
        failed_code: str,
        language: str = "c",
        failure_reason: str = "",
    ) -> str:
        """Store a FAILED fix pattern so it can be used as anti-example.

        Negative records are stored but excluded from positive retrieval;
        they are surfaced via ``retrieve_anti_examples()``.
        """
        error_codes = self._extract_error_codes(errors)
        error_keywords = self._extract_error_keywords(errors)
        id_source = "NEG|" + "|".join(error_codes) + "|" + (errors[0][:80] if errors else "")
        record_id = "neg_" + hashlib.md5(id_source.encode()).hexdigest()[:10]

        fix_summary = self._compute_fix_summary(original_code, failed_code)
        if failure_reason:
            fix_summary = f"❌ FAILED ({failure_reason}):\n{fix_summary}"

        record = FixRecord(
            record_id=record_id,
            error_codes=error_codes,
            error_keywords=error_keywords,
            error_text_sample="\n".join(errors[:3]),
            fix_summary=fix_summary,
            language=language,
            timestamp=time.time(),
            is_negative=True,
        )
        self.records.append(record)

        # FIFO eviction (keep ratio: max 20% negative)
        negatives = [r for r in self.records if r.is_negative]
        max_neg = max(self.MAX_RECORDS // 5, 20)
        if len(negatives) > max_neg:
            # Remove oldest negatives
            to_remove = set(id(r) for r in negatives[:-max_neg])
            self.records = [r for r in self.records if id(r) not in to_remove]

        if len(self.records) > self.MAX_RECORDS:
            self.records = self.records[-self.MAX_RECORDS:]

        self._dirty = True
        self._save()
        logger.info(f"[RAG] Stored NEGATIVE fix: {record_id} | codes={error_codes}")
        return record_id

    def retrieve_anti_examples(
        self,
        errors: List[str],
        language: str = "c",
        top_k: int = 1,
        min_similarity: float = 0.35,
    ) -> List[Tuple[FixRecord, float]]:
        """Retrieve similar FAILED fixes as anti-examples for the prompt."""
        negatives = [r for r in self.records if r.is_negative]
        if not negatives:
            return []

        # Quick TF-IDF similarity against negative records only
        query_terms = self._build_query_document(errors, language)
        results = []
        for rec in negatives:
            # Jaccard on error codes as fast proxy
            q_codes = set(self._extract_error_codes(errors))
            r_codes = set(rec.error_codes)
            union = q_codes | r_codes
            score = len(q_codes & r_codes) / len(union) if union else 0.0
            if score >= min_similarity:
                results.append((rec, score))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]

    def format_anti_examples(self, retrieved: List[Tuple[FixRecord, float]]) -> str:
        """Format anti-examples as a warning section for the prompt."""
        if not retrieved:
            return ""
        parts = [
            "\n⚠️ ANTI-EXAMPLES — these fix approaches FAILED before:",
            "─" * 50,
        ]
        for i, (rec, score) in enumerate(retrieved, 1):
            codes_str = ", ".join(rec.error_codes[:5]) if rec.error_codes else "unknown"
            parts.append(
                f"Failed attempt {i} (errors: {codes_str}):\n"
                f"  {rec.fix_summary[:300]}\n"
                f"  → Do NOT repeat this pattern.\n"
            )
        parts.append("─" * 50 + "\n")
        return "\n".join(parts)

    # ──────────────────────────── Retrieve ────────────────────────────

    def retrieve_similar_fixes(
        self,
        errors: List[str],
        language: str = "c",
        top_k: int = 2,
        min_similarity: float = 0.25,
    ) -> List[Tuple[FixRecord, float]]:
        """
        Retrieve the most similar past fixes for the given errors.

        Returns:
            List of (FixRecord, similarity_score) tuples, sorted by score desc.
        """
        if not self.records:
            return []

        if self._dirty:
            self._rebuild_index()

        if self._tfidf_matrix is None or self._idf is None:
            return []

        # Build query vector
        query_terms = self._build_query_document(errors, language)
        query_vector = np.zeros(len(self._vocabulary))
        tf = Counter(query_terms)
        for term, count in tf.items():
            if term in self._vocabulary:
                j = self._vocabulary[term]
                query_vector[j] = count * self._idf[j]

        # L2 normalize
        norm = np.linalg.norm(query_vector)
        if norm == 0:
            return []
        query_vector /= norm

        # Cosine similarity
        similarities = self._tfidf_matrix @ query_vector

        # Get top-k (skip negative records — they are anti-examples)
        top_indices = np.argsort(similarities)[::-1]
        results = []
        for idx in top_indices:
            if len(results) >= top_k:
                break
            rec = self.records[idx]
            if rec.is_negative:
                continue
            score = float(similarities[idx])
            if score >= min_similarity:
                results.append((rec, score))

        if results:
            logger.info(
                f"[RAG] Retrieved {len(results)} similar fixes "
                f"(top score: {results[0][1]:.3f})"
            )
        return results

    # ──────────────────────────── Format ────────────────────────────

    def format_as_few_shot(
        self,
        retrieved: List[Tuple[FixRecord, float]],
        max_tokens: int = 1500,
    ) -> str:
        """
        Format retrieved fixes as dynamic few-shot examples for injection into a prompt.

        Returns empty string if no relevant fixes were retrieved.
        """
        if not retrieved:
            return ""

        parts = [
            "\nDYNAMIC FEW-SHOT EXAMPLES (from past successful fixes):",
            "─" * 50,
        ]

        for i, (record, score) in enumerate(retrieved, 1):
            codes_str = ", ".join(record.error_codes[:5]) if record.error_codes else "unknown"
            example = (
                f"Example {i} (similarity: {score:.0%}, errors: {codes_str}):\n"
                f"  Errors encountered:\n"
                f"    {record.error_text_sample[:200]}\n"
                f"  Successful fix:\n"
                f"    {record.fix_summary}\n"
            )
            parts.append(example)

        parts.append("─" * 50)
        parts.append(
            "Apply similar fix patterns to the current errors. "
            "Do NOT copy verbatim — adapt to the current code.\n"
        )

        result = "\n".join(parts)
        # Rough token estimate: ~4 chars per token
        if len(result) > max_tokens * 4:
            result = result[:max_tokens * 4] + "\n  ... (truncated)\n"

        return result

    # ──────────────────────────── Stats ────────────────────────────

    def get_stats(self) -> Dict:
        """Return statistics about the fix history."""
        if not self.records:
            return {'total_records': 0}

        languages = Counter(r.language for r in self.records)
        all_codes = Counter()
        for r in self.records:
            all_codes.update(r.error_codes)

        return {
            'total_records': len(self.records),
            'languages': dict(languages),
            'top_error_codes': dict(all_codes.most_common(10)),
            'oldest_record': min(r.timestamp for r in self.records),
            'newest_record': max(r.timestamp for r in self.records),
        }
