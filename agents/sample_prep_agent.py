"""
SamplePrepAgent — project detection and source parsing.

Wraps:
  - src.project_detector.ProjectDetector
  - src.project_parser.ProjectParser

Input command:  SamplePrepCommand
Output event:   SamplePreparedEvent
Error event:    ErrorEvent (code SAMPLE_PREP_FAILED)
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import structlog

# Ensure src/ is importable
_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from project_detector import ProjectDetector  # type: ignore
from project_parser import ProjectParser  # type: ignore

from broker.topics import Topic
from contracts.job import JobStatus
from contracts.messages import SamplePreparedEvent

from .base_agent import BaseAgent

logger = structlog.get_logger(__name__)


# Event field signatures for activation matching
_SIG_JOB_CREATED = frozenset({"source_path", "language", "project_name", "priority"})


class SamplePrepAgent(BaseAgent):
    """
    Detect + parse project source and store as artifact.

    Self-activates on: JobCreatedEvent (CREATED → SAMPLE_PREPARING)
    """

    agent_name = "SamplePrepAgent"
    command_stream = Topic.CMD_SAMPLE_PREP
    consumer_group = Topic.CG_SAMPLE_PREP
    event_consumer_group = Topic.CG_EVENTS_SAMPLE_PREP

    # Self-activation: when we see JobCreatedEvent and job is CREATED → claim as SAMPLE_PREPARING
    activates_on = {
        _SIG_JOB_CREATED: (JobStatus.CREATED, JobStatus.SAMPLE_PREPARING),
    }

    capabilities = {"stage": "sample_prep", "languages": ["c", "cpp", "python", "javascript"]}

    async def handle_event(self, data: dict, claimed_state) -> None:
        """Handle self-activated event from EVENTS_ALL."""
        await self.handle(data)
        # Transition to SAMPLE_READY after successful processing
        if self._ctx.state_store:
            state = await self._ctx.state_store.get(data["job_id"])
            if state and state.current_status == JobStatus.SAMPLE_PREPARING:
                await self.transition_and_save(state, JobStatus.SAMPLE_READY,
                                               reason="sample prep completed")

    async def handle(self, data: dict) -> None:
        job_id = data["job_id"]
        source_path = data["source_path"]
        project_name = data.get("project_name", "")
        language = data.get("language", "c")
        num_functions = data.get("num_functions", 3)
        requested_strategies = data.get("requested_strategies", [])

        log = logger.bind(job_id=job_id, source_path=source_path)

        # ── 1. Detect projects ────────────────────────────────────────────
        detector = ProjectDetector(source_path)
        loop = asyncio.get_event_loop()
        projects = await loop.run_in_executor(
            None, lambda: detector.detect_projects(recursive=True)
        )

        if not projects:
            raise ValueError(f"No projects detected in: {source_path}")

        target_project = next(
            (p for p in projects if p.name == project_name), projects[0]
        )
        log.info("project_detected", detected=target_project.name)

        # ── 2. Parse source files ─────────────────────────────────────────
        parser = ProjectParser()
        parse_result = await loop.run_in_executor(
            None, lambda: parser.parse_project(target_project)
        )

        # ── 3. Build artifact payload ─────────────────────────────────────
        source_payload = {
            "project_name": target_project.name,
            "source_path": source_path,
            "language": language,
            "num_functions": num_functions,
            "requested_strategies": requested_strategies,
            "source_files": [
                str(f) for f in parse_result.file_results.keys()
            ],
            "header_files": [
                str(f) for f in getattr(parse_result, "all_headers", [])
            ],
            "functions": [
                {
                    "name": fn.get("name_only", "") or fn.get("name", ""),
                    "file": str(fn.get("source_file", "")),
                    "start_line": fn.get("start_line", 0),
                    "end_line": fn.get("end_line", 0),
                    "body": fn.get("body", ""),
                }
                for fn in getattr(parse_result, "all_functions", [])
            ],
            "structs": [
                {
                    "name": s.get("name", "") if isinstance(s, dict) else str(s),
                    "body": s.get("body", "") if isinstance(s, dict) else "",
                    "file": str(s.get("source_file", "")) if isinstance(s, dict) else "",
                }
                for s in getattr(parse_result, "all_structs", [])
            ],
            "globals": [
                (g if isinstance(g, str) else g.get("name", str(g)))
                for g in getattr(parse_result, "all_globals", [])
            ][:50],  # cap to avoid oversized artifacts
            "raw_project": (
                target_project.to_dict()
                if hasattr(target_project, "to_dict")
                else {}
            ),
        }

        num_source_files = len(source_payload["source_files"])
        log.info("source_parsed", source_files=num_source_files,
                 functions=len(source_payload["functions"]))

        # ── 4. Store artifact ─────────────────────────────────────────────
        if self._ctx.artifact_store:
            artifact_id = await self._ctx.artifact_store.store_json(
                job_id=job_id,
                artifact_type="source_parse_result",
                data=source_payload,
            )
        else:
            artifact_id = f"source_{job_id[:8]}"

        # ── 5. Emit event ─────────────────────────────────────────────────
        event = SamplePreparedEvent(
            job_id=job_id,
            sample_id=data["sample_id"],
            correlation_id=data["correlation_id"],
            source_artifact_id=artifact_id,
            requested_strategies=requested_strategies,
            num_source_files=num_source_files,
            num_functions_selected=len(source_payload.get("functions", [])),
            language=language,
            project_name=target_project.name,
        )
        await self._ctx.broker.publish(Topic.EVENTS_ALL, event)
        log.info("sample_prepared", artifact_id=artifact_id)
