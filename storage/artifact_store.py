"""
Artifact store — manages file artifacts (source archives, compiled binaries,
raw sandbox reports) with SHA-256 content addressing.

Artifacts are stored on disk under a configurable base directory.
The metadata index is kept in SQLite.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class ArtifactStore:
    """
    Content-addressed artifact store.

    Each artifact is stored as:
        <base_dir>/<sha256[:2]>/<sha256>/  (content-addressed)

    together with a metadata row in SQLite.
    """

    def __init__(self, base_dir: str = "artifacts", db_path: str = "state.db") -> None:
        self._base_dir = Path(base_dir)
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id  TEXT PRIMARY KEY,
                    job_id       TEXT NOT NULL,
                    sample_id    TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    file_path    TEXT NOT NULL,
                    sha256       TEXT NOT NULL,
                    size_bytes   INTEGER NOT NULL,
                    created_at   TEXT NOT NULL,
                    metadata_json TEXT DEFAULT '{}'
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_job ON artifacts (job_id)")
            conn.commit()

    # ──────────────────────────────────────────────────────────────────────
    # Store
    # ──────────────────────────────────────────────────────────────────────

    def store_sync(
        self,
        job_id: str,
        sample_id: str,
        source_path: str,
        artifact_type: str,
        metadata: Optional[dict] = None,
    ) -> str:
        """
        Copy a file into the artifact store.
        Returns artifact_id (UUID string).
        """
        sha256 = self._sha256(source_path)
        size = os.path.getsize(source_path)

        dest_dir = self._base_dir / sha256[:2] / sha256
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = (dest_dir / Path(source_path).name).resolve()

        if not dest_path.exists():
            shutil.copy2(source_path, dest_path)

        artifact_id = str(uuid.uuid4())
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("""
                INSERT INTO artifacts
                    (artifact_id, job_id, sample_id, artifact_type, file_path, sha256, size_bytes, created_at, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                artifact_id,
                job_id,
                sample_id,
                artifact_type,
                str(dest_path),
                sha256,
                size,
                datetime.utcnow().isoformat(),
                json.dumps(metadata or {}),
            ))
            conn.commit()

        logger.debug("Stored artifact %s (%s) sha256=%s", artifact_id, artifact_type, sha256)
        return artifact_id

    def store_json_sync(
        self,
        job_id: str,
        sample_id: str,
        data: dict,
        artifact_type: str,
        filename: str,
        metadata: Optional[dict] = None,
    ) -> str:
        """
        Store a dict as a JSON artifact (no source file needed).
        Returns artifact_id.
        """
        import tempfile
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as tmp:
            json.dump(data, tmp, ensure_ascii=False, indent=2)
            tmp_path = tmp.name

        try:
            # Rename to desired filename in a temp dir
            tmp_dir = os.path.dirname(tmp_path)
            dest_tmp = os.path.join(tmp_dir, filename)
            shutil.move(tmp_path, dest_tmp)
            return self.store_sync(job_id, sample_id, dest_tmp, artifact_type, metadata)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    # ──────────────────────────────────────────────────────────────────────
    # Retrieve
    # ──────────────────────────────────────────────────────────────────────

    def get_path_sync(self, artifact_id: str) -> Optional[str]:
        with sqlite3.connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT file_path FROM artifacts WHERE artifact_id = ?", (artifact_id,)
            ).fetchone()
        return row[0] if row else None

    # ──────────────────────────────────────────────────────────────────────
    # Async compatibility layer (used by multi-agent pipeline)
    # ──────────────────────────────────────────────────────────────────────

    async def store(
        self,
        job_id: str,
        artifact_type: str,
        sample_id: str = "",
        source_path: str = "",
        file_path: Optional[Path] = None,
        metadata: Optional[dict] = None,
    ) -> str:
        """
        Async wrapper for storing file artifacts.

        Supports both call styles:
          - store(job_id=..., sample_id=..., source_path=..., artifact_type=...)
          - store(job_id=..., artifact_type=..., file_path=Path(...))
        """
        if file_path is not None:
            source_path = str(file_path)
        if not source_path:
            raise ValueError("source_path/file_path is required")
        if not sample_id:
            sample_id = job_id
        return self.store_sync(
            job_id=job_id,
            sample_id=sample_id,
            source_path=source_path,
            artifact_type=artifact_type,
            metadata=metadata,
        )

    async def store_json(
        self,
        job_id: str,
        data: dict,
        artifact_type: str,
        sample_id: str = "",
        filename: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> str:
        """Async wrapper for storing JSON artifacts."""
        if not sample_id:
            sample_id = job_id
        if not filename:
            filename = f"{artifact_type}.json"
        return self.store_json_sync(
            job_id=job_id,
            sample_id=sample_id,
            data=data,
            artifact_type=artifact_type,
            filename=filename,
            metadata=metadata,
        )

    async def get_path(self, *args) -> Optional[Path]:
        """
        Async path lookup.

        Accepts:
          - get_path(artifact_id)
          - get_path(job_id, artifact_id)  # job_id ignored for compatibility
        """
        if len(args) == 1:
            artifact_id = args[0]
        elif len(args) == 2:
            artifact_id = args[1]
        else:
            raise ValueError("get_path expects (artifact_id) or (job_id, artifact_id)")
        p = self.get_path_sync(artifact_id)
        return Path(p) if p else None

    async def get_json(self, *args) -> Optional[dict]:
        """
        Async JSON artifact load.

        Accepts:
          - get_json(artifact_id)
          - get_json(job_id, artifact_id)  # job_id ignored for compatibility
        """
        if len(args) == 1:
            artifact_id = args[0]
        elif len(args) == 2:
            artifact_id = args[1]
        else:
            raise ValueError("get_json expects (artifact_id) or (job_id, artifact_id)")

        path = self.get_path_sync(artifact_id)
        if not path or not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def get_metadata(self, artifact_id: str) -> Optional[dict]:
        with sqlite3.connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT metadata_json, sha256, size_bytes, artifact_type FROM artifacts WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone()
        if not row:
            return None
        meta = json.loads(row[0])
        meta.update({"sha256": row[1], "size_bytes": row[2], "artifact_type": row[3]})
        return meta

    def list_for_job(self, job_id: str) -> list[dict]:
        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute(
                "SELECT artifact_id, artifact_type, sha256, size_bytes, created_at FROM artifacts WHERE job_id = ?",
                (job_id,),
            ).fetchall()
        return [
            {"artifact_id": r[0], "type": r[1], "sha256": r[2], "size": r[3], "created_at": r[4]}
            for r in rows
        ]

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
