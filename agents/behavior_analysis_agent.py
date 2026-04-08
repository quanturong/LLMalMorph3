"""
BehaviorAnalysisAgent — rule-based + LLM-assisted IOC extraction & categorization.

Two-layer analysis:
  Layer 1 (always): Rule-based extraction from sandbox report fields
  Layer 2 (LLM-optional): Structured LLM output with BehaviorLLMOutput schema,
                           validated by safety guardrails.

Input command:  AnalyzeBehaviorCommand
Output event:   BehaviorAnalyzedEvent
"""

from __future__ import annotations

import json
import re
import sys
import time
from difflib import SequenceMatcher
from pathlib import Path
from typing import Dict, List, Optional

import structlog

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from broker.topics import Topic
from contracts.analysis import (
    AnalysisMethod,
    BehaviorAnalysisResult,
    BehaviorCategory,
    BehaviorEquivalenceResult,
    BehaviorLLMOutput,
    EquivalenceVerdict,
    IOCEntry,
    IOCSource,
    IOCType,
)
from contracts.job import JobStatus
from contracts.messages import BehaviorAnalyzedEvent
from llm.provider import LLMRequest

from .base_agent import BaseAgent

logger = structlog.get_logger(__name__)

_BEHAVIOR_PROMPT_PATH = Path(__file__).resolve().parent.parent / "llm" / "prompts" / "behavior_analysis.txt"

# Event signature: ExecutionCompletedEvent
_SIG_EXECUTION_COMPLETED = frozenset({"raw_report_artifact_id", "analysis_duration_s", "sandbox_task_id"})


class BehaviorAnalysisAgent(BaseAgent):
    """
    Analyze sandbox report: extract IOCs, score behavior, summarize.

    Self-activates on: ExecutionCompletedEvent (EXECUTION_COMPLETE → BEHAVIOR_ANALYZING)
    """

    agent_name = "BehaviorAnalysisAgent"
    command_stream = Topic.CMD_ANALYZE_BEHAVIOR
    consumer_group = Topic.CG_ANALYZE_BEHAVIOR
    event_consumer_group = Topic.CG_EVENTS_ANALYZE_BEHAVIOR

    activates_on = {
        _SIG_EXECUTION_COMPLETED: (JobStatus.EXECUTION_COMPLETE, JobStatus.BEHAVIOR_ANALYZING),
    }

    capabilities = {"stage": "behavior_analysis", "uses_llm": True, "analysis_methods": ["rule_based", "llm"]}

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self._pending_analyzed_events: dict = {}

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self._pending_analyzed_events: dict = {}

    async def handle_event(self, data: dict, claimed_state) -> None:
        """Extract command data from event."""
        cmd_data = {
            "job_id": data["job_id"],
            "sample_id": data.get("sample_id", ""),
            "correlation_id": data.get("correlation_id", ""),
            "raw_report_artifact_id": data.get("raw_report_artifact_id", ""),
            "sandbox_backend": data.get("sandbox_backend", "cape"),
        }
        await self.handle(cmd_data)
        # Transition to BEHAVIOR_ANALYZED
        if self._ctx.state_store:
            state = await self._ctx.state_store.get(data["job_id"])
            if state and state.current_status == JobStatus.BEHAVIOR_ANALYZING:
                await self.transition_and_save(state, JobStatus.BEHAVIOR_ANALYZED,
                                               reason="behavior analysis completed")
                pending = self._pending_analyzed_events.pop(data["job_id"], None)
                if pending:
                    await self._ctx.broker.publish(Topic.EVENTS_ALL, pending)

    async def handle(self, data: dict) -> None:
        job_id = data["job_id"]
        sample_id = data["sample_id"]
        raw_report_artifact_id = data["raw_report_artifact_id"]
        sandbox_backend = data.get("sandbox_backend", "cape")

        log = logger.bind(job_id=job_id)

        raw_report: Dict = {}
        if self._ctx.artifact_store:
            stored = await self._ctx.artifact_store.get_json(job_id, raw_report_artifact_id)
            if stored:
                raw_report = stored

        # Normalize raw CAPE JSON → flat structure the helpers expect
        raw_report = _normalize_cape_report(raw_report)

        sandbox_task_id = raw_report.get("task_id", 0) or data.get("sandbox_task_id", 0)

        t0 = time.monotonic()
        rule_iocs = _extract_iocs_rule_based(raw_report)
        rule_score = _compute_threat_score_0_10(raw_report)
        rule_behaviors = _extract_key_behaviors(raw_report)
        rule_anomalies = _extract_anomalies(raw_report)

        detection_count = len(raw_report.get("detections", []))
        api_call_count = raw_report.get("api_call_count", 0)
        registry_ops = len(raw_report.get("registry_operations", []))
        file_ops = len(raw_report.get("file_operations", []))
        network_ops = len(raw_report.get("network_operations", []))
        process_ops = len(raw_report.get("process_operations", []))
        mutex_count = len(raw_report.get("mutex_operations", []))
        dll_count = len(raw_report.get("dll_loaded", []))
        ttp_ids = [
            t.get("ttp_id", "") for t in raw_report.get("ttps", []) if isinstance(t, dict)
        ]
        ttp_ids = [t for t in ttp_ids if t]

        log.info("rule_based_complete", ioc_count=len(rule_iocs), score=rule_score)

        llm_output: Optional[BehaviorLLMOutput] = None
        method = AnalysisMethod.RULE_ONLY
        analyst_narrative: Optional[str] = None

        if self._ctx.llm_provider:
            llm_output = await self._run_llm_analysis(raw_report, rule_iocs, log)
            if llm_output:
                method = AnalysisMethod.LLM_VALIDATED

        ioc_list = rule_iocs.copy()
        primary_category = BehaviorCategory.UNKNOWN
        category_confidence = 0.0

        if llm_output:
            existing_values = {ioc.value for ioc in ioc_list}
            for llm_ioc in (llm_output.ioc_extraction or []):
                if isinstance(llm_ioc, IOCEntry) and llm_ioc.value not in existing_values:
                    ioc_list.append(llm_ioc)
                    existing_values.add(llm_ioc.value)
            primary_category = llm_output.primary_behavior_category
            category_confidence = llm_output.confidence
            rule_behaviors = llm_output.key_behaviors or rule_behaviors
            rule_anomalies = llm_output.anomalies or rule_anomalies
            analyst_narrative = llm_output.analyst_summary
        else:
            cat_map = {
                "ransomware": BehaviorCategory.RANSOMWARE,
                "stealer": BehaviorCategory.STEALER,
                "loader": BehaviorCategory.LOADER,
                "backdoor": BehaviorCategory.BACKDOOR,
                "dropper": BehaviorCategory.DROPPER,
            }
            for cat in _infer_categories(raw_report):
                if cat in cat_map:
                    primary_category = cat_map[cat]
                    category_confidence = 0.6
                    break

        analysis_duration_s = time.monotonic() - t0

        analysis_result = BehaviorAnalysisResult(
            job_id=job_id,
            sample_id=sample_id,
            sandbox_task_id=sandbox_task_id,
            sandbox_backend=sandbox_backend,
            threat_score=rule_score,
            detection_count=detection_count,
            detection_names=raw_report.get("detections", []),
            iocs=ioc_list,
            ttp_ids=ttp_ids,
            api_call_count=api_call_count,
            registry_ops_count=registry_ops,
            file_ops_count=file_ops,
            network_ops_count=network_ops,
            process_ops_count=process_ops,
            mutex_count=mutex_count,
            dll_loaded_count=dll_count,
            primary_category=primary_category,
            category_confidence=category_confidence,
            key_behaviors=rule_behaviors[:5],
            anomalies=rule_anomalies,
            analyst_narrative=analyst_narrative,
            analysis_method=method,
            analysis_duration_s=analysis_duration_s,
        )

        # ── 5. Store analysis artifact ────────────────────────────────────
        result_dict = analysis_result.model_dump(mode="json")
        if self._ctx.artifact_store:
            analysis_id = await self._ctx.artifact_store.store_json(
                job_id=job_id,
                artifact_type="behavior_analysis_result",
                data=result_dict,
            )
        else:
            analysis_id = f"analysis_{job_id[:8]}"

        # ── 6. Persist analysis_id in state, then compute equivalence ────────
        if self._ctx.state_store:
            _state = await self._ctx.state_store.get(job_id)
            if _state:
                _state.analysis_result_id = analysis_id
                # Behavioral equivalence: diff mutated vs original raw reports
                if _state.original_raw_report_artifact_id and self._ctx.artifact_store:
                    orig_report = await self._ctx.artifact_store.get_json(
                        job_id, _state.original_raw_report_artifact_id
                    )
                    if orig_report:
                        equiv = _compute_behavioral_equivalence(
                            job_id=job_id,
                            sample_id=sample_id,
                            original_report=_normalize_cape_report(orig_report),
                            mutated_report=raw_report,
                            original_task_id=_state.original_sandbox_task_id,
                            mutated_task_id=sandbox_task_id,
                        )
                        equiv_dict = equiv.model_dump(mode="json")
                        equiv_id = await self._ctx.artifact_store.store_json(
                            job_id=job_id,
                            artifact_type="behavior_equivalence_result",
                            data=equiv_dict,
                        )
                        _state.equivalence_result_id = equiv_id
                        log.info(
                            "behavioral_equivalence_computed",
                            verdict=equiv.verdict,
                            score=equiv.overall_equivalence_score,
                            api_jaccard=equiv.api_call_jaccard_similarity,
                            api_sequence=equiv.api_call_sequence_similarity,
                        )
                    else:
                        log.warning("original_report_artifact_empty_skipping_equivalence")
                await self._ctx.state_store.save(_state)

        # ── 7. Emit event ─────────────────────────────────────────────────
        event = BehaviorAnalyzedEvent(
            job_id=job_id,
            sample_id=sample_id,
            correlation_id=data["correlation_id"],
            analysis_result_id=analysis_id,
            score=rule_score,
            detection_count=detection_count,
            ioc_count=len(ioc_list),
            ttp_count=len(ttp_ids),
            analysis_method=method.value,
        )
        self._pending_analyzed_events[job_id] = event
        log.info("behavior_analyzed_deferred",
                 analysis_id=analysis_id,
                 ioc_count=len(ioc_list),
                 score=rule_score,
                 method=method.value)

    # ──────────────────────────────────────────────────────────────────────
    # LLM layer
    # ──────────────────────────────────────────────────────────────────────

    async def _run_llm_analysis(
        self, raw_report: dict, rule_iocs: List[IOCEntry], log
    ) -> Optional[BehaviorLLMOutput]:
        try:
            prompt_template = _load_prompt(_BEHAVIOR_PROMPT_PATH)
            report_excerpt = json.dumps(_truncate_report(raw_report), indent=2)[:4000]
            rule_ioc_json = json.dumps(
                [{"type": i.type.value, "value": i.value} for i in rule_iocs[:20]]
            )
            prompt = prompt_template.replace("{{report_json}}", report_excerpt)
            prompt = prompt.replace("{{rule_based_iocs_json}}", rule_ioc_json)

            request = LLMRequest(
                system_prompt=(
                    "You are a malware analyst assistant. "
                    "Analyze the sandbox report and extract behavioral indicators. "
                    "Do NOT suggest evasion or stealth improvements. "
                    "Respond ONLY with valid JSON matching the schema."
                ),
                user_prompt=prompt,
                response_format="json",
                max_tokens=2048,
                temperature=0.1,
            )

            output = await self._ctx.llm_provider.generate_structured(
                request, BehaviorLLMOutput
            )
            return output

        except Exception as exc:
            log.warning("llm_analysis_failed", error=str(exc))
            return None


# ──────────────────────────────────────────────────────────────────────────────
# Rule-based helpers
# ──────────────────────────────────────────────────────────────────────────────

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:com|net|org|info|biz|io|ru|cn)\b"
)
_REGISTRY_KEY_RE = re.compile(
    r"HKEY_[A-Z_]+\\[^\s\"'<>|]+", re.IGNORECASE
)
_FILE_PATH_RE = re.compile(
    r"[A-Za-z]:\\[^\s\"'<>|:*?\\]+(?:\\[^\s\"'<>|:*?\\]+)*"
)
_MD5_RE = re.compile(r"\b[0-9a-f]{32}\b", re.IGNORECASE)
_SHA256_RE = re.compile(r"\b[0-9a-f]{64}\b", re.IGNORECASE)


def _flat_strings(obj, depth: int = 5) -> List[str]:
    """Recursively flatten JSON object to a list of string values."""
    if depth <= 0:
        return []
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        result = []
        for v in obj.values():
            result.extend(_flat_strings(v, depth - 1))
        return result
    if isinstance(obj, (list, tuple)):
        result = []
        for item in obj:
            result.extend(_flat_strings(item, depth - 1))
        return result
    return []


def _normalize_cape_report(raw: dict) -> dict:
    """
    Normalize a raw CAPE JSON report into the flat structure expected by agent helpers.
    If the dict doesn't look like a real CAPE report, it is returned unchanged.
    """
    if "malscore" not in raw and "behavior" not in raw:
        return raw  # already normalized, or not CAPE format

    normalized = dict(raw)

    # Score
    normalized["score"] = float(raw.get("malscore") or 0)

    # Detections — derived from malstatus + signatures families + yara
    detections: List[str] = []
    malstatus = str(raw.get("malstatus", "") or "").lower()
    if malstatus not in ("", "none", "undetected", "clean"):
        detections.append(malstatus)
    for sig in raw.get("signatures", []):
        if isinstance(sig, dict):
            for fam in (sig.get("families") or []):
                if fam and fam not in detections:
                    detections.append(str(fam))
    normalized["detections"] = detections

    # TTPs — flatten [{signature, ttps:[T1055,...]}, ...] → [{ttp_id, signature}]
    ttp_list: List[dict] = []
    for entry in raw.get("ttps", []):
        if not isinstance(entry, dict):
            continue
        sig_name = entry.get("signature", "")
        for tid in entry.get("ttps", []):
            if tid:
                ttp_list.append({"ttp_id": str(tid), "signature": sig_name})
    normalized["ttps"] = ttp_list

    # Behavior fields from behavior.*
    beh = raw.get("behavior", {}) if isinstance(raw.get("behavior"), dict) else {}
    procs = beh.get("processes", [])
    summary = beh.get("summary", {}) if isinstance(beh.get("summary"), dict) else {}

    # API call count
    total_calls = sum(len(p.get("calls", [])) for p in procs if isinstance(p, dict))
    normalized["api_call_count"] = total_calls

    # API calls (ordered sequence from process call traces)
    api_calls: List[dict] = []
    for p in procs:
        if not isinstance(p, dict):
            continue
        for call in p.get("calls", []):
            if not isinstance(call, dict):
                continue
            api_name = call.get("api") or call.get("name") or call.get("call")
            if api_name:
                api_calls.append({"api": str(api_name)})
    normalized["api_calls"] = api_calls

    # Registry operations
    reg_ops: List[dict] = []
    for key in summary.get("read_keys", []):
        reg_ops.append({"type": "read", "key": key})
    for key in summary.get("write_keys", []):
        reg_ops.append({"type": "write", "key": key})
    for key in summary.get("delete_keys", []):
        reg_ops.append({"type": "delete", "key": key})
    normalized["registry_operations"] = reg_ops

    # File operations
    file_ops: List[dict] = []
    for path in summary.get("files", []):
        file_ops.append({"type": "read", "path": path})
    for path in summary.get("write_files", []):
        file_ops.append({"type": "write", "path": path})
    for path in summary.get("delete_files", []):
        file_ops.append({"type": "delete", "path": path})
    normalized["file_operations"] = file_ops

    # Network operations
    net = raw.get("network", {}) if isinstance(raw.get("network"), dict) else {}
    net_ops: List[dict] = []
    for dns in net.get("dns", []):
        net_ops.append({"type": "dns", "domain": dns.get("request", ""), "ip": dns.get("response", "")})
    for http in net.get("http", []):
        net_ops.append({"type": "http", "url": http.get("uri", ""), "host": http.get("host", "")})
    for tcp in net.get("tcp", []):
        net_ops.append({"type": "tcp", "dest_ip": tcp.get("dst", ""), "dest_port": tcp.get("dport", "")})
    normalized["network_operations"] = net_ops

    # Process operations
    proc_ops: List[dict] = []
    for p in procs:
        if isinstance(p, dict):
            proc_ops.append({"pid": p.get("process_id"), "name": p.get("process_name", "")})
    for cmd in summary.get("executed_commands", []):
        proc_ops.append({"type": "command", "command": cmd})
    normalized["process_operations"] = proc_ops

    # Mutex operations
    normalized["mutex_operations"] = [
        m for m in summary.get("mutexes", []) if isinstance(m, str)
    ]

    # DLL loaded — from behavior.enhanced library events
    dlls = [
        e["data"]["file"]
        for e in beh.get("enhanced", [])
        if isinstance(e, dict)
        and e.get("object") == "library"
        and isinstance(e.get("data"), dict)
        and e["data"].get("file")
    ]
    normalized["dll_loaded"] = list(set(dlls))

    return normalized


def _extract_iocs_rule_based(report: dict) -> List[IOCEntry]:
    iocs: List[IOCEntry] = []
    seen: set = set()

    text_blob = " ".join(_flat_strings(report))

    def _add(ioc_type: IOCType, value: str, confidence: float = 0.8):
        key = (ioc_type, value)
        if key not in seen:
            seen.add(key)
            iocs.append(IOCEntry(
                type=ioc_type, value=value,
                source=IOCSource.RULE_BASED, confidence=confidence,
            ))

    for m in _IP_RE.finditer(text_blob):
        v = m.group()
        if not v.startswith("127.") and not v.startswith("0."):
            _add(IOCType.IP, v)

    for m in _DOMAIN_RE.finditer(text_blob):
        _add(IOCType.DOMAIN, m.group().lower())

    for m in _REGISTRY_KEY_RE.finditer(text_blob):
        _add(IOCType.REGISTRY, m.group(), confidence=0.9)

    for m in _FILE_PATH_RE.finditer(text_blob):
        _add(IOCType.FILE, m.group())

    for net_op in report.get("network_operations", []):
        if isinstance(net_op, dict):
            for f in ("dest_ip", "src_ip", "ip"):
                if f in net_op:
                    _add(IOCType.IP, str(net_op[f]))
            for f in ("domain", "host"):
                if f in net_op:
                    _add(IOCType.DOMAIN, str(net_op[f]).lower())
            for f in ("url", "uri"):
                if f in net_op:
                    _add(IOCType.URL, str(net_op[f]))
    for mutex in report.get("mutex_operations", []):
        if isinstance(mutex, str) and len(mutex) > 2:
            _add(IOCType.MUTEX, mutex, confidence=0.7)

    return iocs


def _compute_threat_score_0_10(report: dict) -> float:
    """Heuristic threat score 0.0-10.0. Uses CAPE score if present."""
    for key in ("score", "malscore"):
        s = report.get(key)
        if s is not None:
            try:
                v = float(s)
                if 0.0 <= v <= 10.0:
                    return v
            except (TypeError, ValueError):
                pass
    text = " ".join(_flat_strings(report)).lower()
    raw = 0.0
    for kw, w in {
        "network_connect": 1.5, "registry_write": 1.0, "file_create": 0.8,
        "process_inject": 2.0, "createremotethread": 2.5, "shellcode": 2.0,
        "powershell": 1.0, "certutil": 1.0, "wscript": 0.8,
        "rundll32": 1.2, "regsvr32": 1.2, "schtasks": 1.5,
        "mutex": 0.5, "bitcoin": 2.0, "ransom": 2.5,
    }.items():
        if kw in text:
            raw += w
    return min(10.0, raw)


def _extract_key_behaviors(report: dict) -> List[str]:
    behaviors = []
    for label, key in [
        ("network", "network_operations"), ("registry", "registry_operations"),
        ("file", "file_operations"), ("process", "process_operations"),
    ]:
        if report.get(key):
            behaviors.append(f"{len(report[key])} {label} ops")
    return behaviors[:5]


def _extract_anomalies(report: dict) -> List[str]:
    anomalies = []
    for sig in report.get("signatures", [])[:5]:
        if isinstance(sig, dict):
            name = sig.get("name", "") or sig.get("description", "")
            if name:
                anomalies.append(f"Signature: {name}")
    return anomalies


def _infer_categories(report: dict) -> List[str]:
    text = " ".join(_flat_strings(report)).lower()
    cats = []
    if any(k in text for k in ["network_connect", "dns_query", "socket"]):
        cats.append("network_communication")
    if any(k in text for k in ["registry_write", "registry_set"]):
        cats.append("registry_modification")
    if any(k in text for k in ["file_create", "file_write", "file_delete"]):
        cats.append("file_system_activity")
    if any(k in text for k in ["createremotethread", "process_inject", "shellcode"]):
        cats.append("process_injection")
    if any(k in text for k in ["schtasks", "run_key", "startup"]):
        cats.append("persistence_mechanism")
    return cats or ["undetermined"]


def _truncate_report(report: dict) -> dict:
    """Truncate report to first-level fields for LLM context."""
    result = {}
    keys_of_interest = [
        "network", "behavior", "signatures", "strings",
        "dropped", "static", "target", "info",
    ]
    for k in keys_of_interest:
        if k in report:
            v = report[k]
            if isinstance(v, dict):
                result[k] = {sk: sv for sk, sv in list(v.items())[:10]}
            elif isinstance(v, list):
                result[k] = v[:20]
            else:
                result[k] = v
    return result


def _load_prompt(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return "Analyze the following sandbox report and extract IOCs in JSON format:\n{{report_json}}"


# ──────────────────────────────────────────────────────────────────────────────
# Behavioral Equivalence
# ──────────────────────────────────────────────────────────────────────────────

def _extract_api_call_names(report: dict) -> List[str]:
    """Return deduplicated API call names from a sandbox raw report."""
    calls: set[str] = set()
    for entry in report.get("api_calls", []):
        if isinstance(entry, dict):
            name = entry.get("api", "") or entry.get("name", "") or entry.get("call", "")
        else:
            name = str(entry)
        if name:
            calls.add(name)
    # Also include behavior_summary keys like "api_stats" if present
    for key, val in (report.get("behavior_summary") or {}).items():
        if "api" in key.lower() and isinstance(val, list):
            calls.update(str(v) for v in val if v)
    return sorted(calls)


def _extract_api_call_sequence(report: dict) -> List[str]:
    """Return ordered API call sequence from a sandbox report."""
    sequence: List[str] = []

    # Prefer flattened/normalized api_calls when present.
    for entry in report.get("api_calls", []):
        if isinstance(entry, dict):
            name = entry.get("api", "") or entry.get("name", "") or entry.get("call", "")
        else:
            name = str(entry)
        if name:
            sequence.append(str(name))

    # Fallback: raw CAPE behavior.processes[*].calls[*]
    if not sequence:
        behavior = report.get("behavior", {})
        if isinstance(behavior, dict):
            for proc in behavior.get("processes", []):
                if not isinstance(proc, dict):
                    continue
                for call in proc.get("calls", []):
                    if not isinstance(call, dict):
                        continue
                    name = call.get("api", "") or call.get("name", "") or call.get("call", "")
                    if name:
                        sequence.append(str(name))

    return sequence


def _extract_resource_names(report: dict, key: str, name_field: str) -> List[str]:
    """Extract unique resource names (registry/file/network) from a sandbox report."""
    items: set[str] = set()
    for entry in report.get(key, []):
        if isinstance(entry, dict):
            val = entry.get(name_field, "") or entry.get("path", "") or entry.get("key", "")
        else:
            val = str(entry)
        if val:
            items.add(str(val))
    return sorted(items)


def _jaccard(set_a: set, set_b: set) -> float:
    if not set_a and not set_b:
        return 1.0
    union = set_a | set_b
    if not union:
        return 1.0
    return len(set_a & set_b) / len(union)


def _sequence_similarity(seq_a: List[str], seq_b: List[str]) -> float:
    """Order-aware similarity ratio for API call sequences."""
    if not seq_a and not seq_b:
        return 1.0
    if not seq_a or not seq_b:
        return 0.0
    return SequenceMatcher(a=seq_a, b=seq_b, autojunk=False).ratio()


def _compute_behavioral_equivalence(
    job_id: str,
    sample_id: str,
    original_report: dict,
    mutated_report: dict,
    original_task_id,
    mutated_task_id,
) -> BehaviorEquivalenceResult:
    """
    Compare original and mutated sandbox raw reports to produce a
    BehaviorEquivalenceResult with Jaccard-based API similarity, resource
    diffs, TTP preservation, and an overall equivalence verdict.
    """
    # ── API calls ──────────────────────────────────────────────────────────
    orig_apis = set(_extract_api_call_names(original_report))
    mut_apis = set(_extract_api_call_names(mutated_report))
    api_jaccard = _jaccard(orig_apis, mut_apis)
    orig_api_seq = _extract_api_call_sequence(original_report)
    mut_api_seq = _extract_api_call_sequence(mutated_report)
    api_seq_similarity = _sequence_similarity(orig_api_seq, mut_api_seq)
    # Blend set-based overlap and order-aware similarity.
    api_similarity = (api_jaccard * 0.60) + (api_seq_similarity * 0.40)

    # ── Registry ──────────────────────────────────────────────────────────
    orig_regs = set(_extract_resource_names(original_report, "registry_operations", "key"))
    mut_regs = set(_extract_resource_names(mutated_report, "registry_operations", "key"))

    # ── File I/O ──────────────────────────────────────────────────────────
    orig_files = set(_extract_resource_names(original_report, "file_operations", "path"))
    mut_files = set(_extract_resource_names(mutated_report, "file_operations", "path"))

    # ── Network ───────────────────────────────────────────────────────────
    orig_net = set(_extract_resource_names(original_report, "network_operations", "host"))
    mut_net = set(_extract_resource_names(mutated_report, "network_operations", "host"))

    # ── TTPs ──────────────────────────────────────────────────────────────
    orig_ttps = {t.get("ttp_id", "") for t in original_report.get("ttps", [])
                 if isinstance(t, dict) and t.get("ttp_id")}
    mut_ttps = {t.get("ttp_id", "") for t in mutated_report.get("ttps", [])
                if isinstance(t, dict) and t.get("ttp_id")}
    ttp_preservation = _jaccard(orig_ttps, mut_ttps)

    # ── Malicious strings (detections / signatures) ───────────────────────
    orig_sigs = set(original_report.get("detections", []))
    mut_sigs = set(mutated_report.get("detections", []))
    sig_preservation = _jaccard(orig_sigs, mut_sigs)

    # ── Overall score: weighted average ───────────────────────────────────
    # API call similarity gets the most weight (0.5), TTPs next (0.25),
    # resource ops (0.15), detections presence (0.10)
    resource_sim = (
        _jaccard(orig_regs, mut_regs) * 0.4
        + _jaccard(orig_files, mut_files) * 0.4
        + _jaccard(orig_net, mut_net) * 0.2
    )
    overall = (
        api_similarity * 0.50
        + ttp_preservation * 0.25
        + resource_sim * 0.15
        + sig_preservation * 0.10
    )

    # ── Verdict ────────────────────────────────────────────────────────────
    if overall >= 0.85:
        verdict = EquivalenceVerdict.EQUIVALENT
        confidence = min(1.0, overall)
    elif overall >= 0.65:
        verdict = EquivalenceVerdict.MOSTLY_EQUIVALENT
        confidence = overall
    else:
        verdict = EquivalenceVerdict.DIVERGENT
        confidence = 1.0 - overall

    # ── Limitations ───────────────────────────────────────────────────────
    limitations: List[str] = []
    if not orig_apis:
        limitations.append("No API calls captured in original report; Jaccard may be underestimated")
    if not mut_apis:
        limitations.append("No API calls captured in mutated report; Jaccard may be underestimated")
    if not orig_api_seq:
        limitations.append("No API sequence captured in original report; sequence similarity may be underestimated")
    if not mut_api_seq:
        limitations.append("No API sequence captured in mutated report; sequence similarity may be underestimated")
    if not orig_ttps and not mut_ttps:
        limitations.append("No TTP mappings in either report; TTP preservation not measurable")
    if not original_report.get("network_operations"):
        limitations.append("Original binary produced no network activity; network diff unavailable")

    summary = (
        f"Mutated variant shows {verdict.value} behavior relative to original "
        f"(overall score={overall:.2f}, API Jaccard={api_jaccard:.2f}, "
        f"API sequence={api_seq_similarity:.2f}, "
        f"TTP preservation={ttp_preservation:.2f}). "
        + (
            f"API calls removed: {sorted(orig_apis - mut_apis)[:5]}. "
            if orig_apis - mut_apis else ""
        )
        + (
            f"New API calls: {sorted(mut_apis - orig_apis)[:5]}."
            if mut_apis - orig_apis else ""
        )
    )

    return BehaviorEquivalenceResult(
        job_id=job_id,
        sample_id=sample_id,
        original_task_id=original_task_id,
        mutated_task_id=mutated_task_id,
        original_api_calls=sorted(orig_apis),
        mutated_api_calls=sorted(mut_apis),
        api_calls_only_in_original=sorted(orig_apis - mut_apis),
        api_calls_only_in_mutated=sorted(mut_apis - orig_apis),
        api_call_jaccard_similarity=round(api_jaccard, 4),
        api_call_sequence_similarity=round(api_seq_similarity, 4),
        registry_keys_only_in_original=sorted(orig_regs - mut_regs),
        registry_keys_only_in_mutated=sorted(mut_regs - orig_regs),
        file_paths_only_in_original=sorted(orig_files - mut_files),
        file_paths_only_in_mutated=sorted(mut_files - orig_files),
        network_hosts_only_in_original=sorted(orig_net - mut_net),
        network_hosts_only_in_mutated=sorted(mut_net - orig_net),
        original_ttp_ids=sorted(orig_ttps),
        mutated_ttp_ids=sorted(mut_ttps),
        ttp_preservation_rate=round(ttp_preservation, 4),
        original_malicious_strings=sorted(orig_sigs),
        mutated_malicious_strings=sorted(mut_sigs),
        malicious_string_preservation_rate=round(sig_preservation, 4),
        overall_equivalence_score=round(overall, 4),
        verdict=verdict,
        verdict_confidence=round(confidence, 4),
        summary=summary,
        limitations=limitations,
    )
