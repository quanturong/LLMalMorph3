"""
Report store — index and retrieval for TechnicalReport and ExecutiveSummary.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime
from typing import Optional

from contracts.reports import ExecutiveSummary, TechnicalReport

logger = logging.getLogger(__name__)


class ReportStore:
    def __init__(self, db_path: str = "state.db", reports_dir: str = "reports") -> None:
        self._db_path = db_path
        self._reports_dir = reports_dir
        os.makedirs(reports_dir, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    report_id    TEXT PRIMARY KEY,
                    job_id       TEXT NOT NULL,
                    sample_id    TEXT NOT NULL,
                    report_path  TEXT NOT NULL,
                    summary_path TEXT,
                    threat_score REAL,
                    risk_level   TEXT,
                    created_at   TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_report_job ON reports(job_id)")
            conn.commit()

    def save(
        self,
        report: TechnicalReport,
        summary: Optional[ExecutiveSummary] = None,
    ) -> tuple[str, Optional[str]]:
        """
        Persist report to disk and index it.
        Returns (report_path, summary_path).
        """
        report_path = os.path.join(self._reports_dir, f"report_{report.report_id}.json")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report.model_dump_json(indent=2))

        summary_path: Optional[str] = None
        if summary is not None:
            summary_path = os.path.join(
                self._reports_dir, f"summary_{summary.summary_id}.json"
            )
            with open(summary_path, "w", encoding="utf-8") as f:
                f.write(summary.model_dump_json(indent=2))

        with sqlite3.connect(self._db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO reports
                    (report_id, job_id, sample_id, report_path, summary_path, threat_score, risk_level, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report.report_id,
                report.job_id,
                report.sample_id,
                report_path,
                summary_path,
                report.threat_score,
                summary.risk_level.value if summary else None,
                datetime.utcnow().isoformat(),
            ))
            conn.commit()

        return report_path, summary_path

    def get(self, report_id: str) -> Optional[TechnicalReport]:
        with sqlite3.connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT report_path FROM reports WHERE report_id = ?", (report_id,)
            ).fetchone()
        if not row:
            return None
        with open(row[0], encoding="utf-8") as f:
            return TechnicalReport.model_validate_json(f.read())

    def list_for_job(self, job_id: str) -> list[dict]:
        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute(
                "SELECT report_id, threat_score, risk_level, created_at FROM reports WHERE job_id = ?",
                (job_id,),
            ).fetchall()
        return [
            {"report_id": r[0], "threat_score": r[1], "risk_level": r[2], "created_at": r[3]}
            for r in rows
        ]
