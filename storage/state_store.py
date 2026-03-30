"""
Job state store — persists JobState to Redis (hot) and SQLite (durable).

Hot path:  Redis Hash  (fast reads during active pipeline)
Cold path: SQLite      (survives Redis restart, used for historical queries)

Both stores are always written on update; reads prefer Redis.

Distributed support:
  - transition_atomic()  — compare-and-swap for distributed agent coordination
  - claim_job()          — atomic claim with agent ownership
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime
from typing import Optional

from contracts.job import JobState, JobStatus

logger = logging.getLogger(__name__)

_REDIS_KEY_PREFIX = "jobstate:"
_REDIS_TTL_S = 86_400 * 7  # 7 days


class StateStore:
    """
    Async-capable job state store with atomic CAS support for distributed agents.

    Usage:
        store = StateStore(redis_client=redis, db_path="state.db")
        await store.save(job_state)
        state = await store.get(job_id)
        ok = await store.transition_atomic(job_id, VARIANT_READY, BUILD_VALIDATING, "BuildAgent")
    """

    def __init__(
        self,
        redis_client=None,             # redis.asyncio.Redis — optional
        db_path: str = "state.db",
    ) -> None:
        self._redis = redis_client
        self._db_path = db_path
        self._init_sqlite()

    # ──────────────────────────────────────────────────────────────────────
    # SQLite init
    # ──────────────────────────────────────────────────────────────────────

    def _init_sqlite(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self._db_path)), exist_ok=True)
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS job_states (
                    job_id       TEXT PRIMARY KEY,
                    sample_id    TEXT NOT NULL,
                    current_status TEXT NOT NULL,
                    state_json   TEXT NOT NULL,
                    created_at   TEXT NOT NULL,
                    last_updated TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_status
                ON job_states (current_status)
            """)
            conn.commit()

    # ──────────────────────────────────────────────────────────────────────
    # Save
    # ──────────────────────────────────────────────────────────────────────

    async def save(self, state: JobState) -> None:
        serialized = state.model_dump_json()

        # Write to SQLite first (durable)
        self._sqlite_upsert(state, serialized)

        # Write to Redis (fast, optional)
        if self._redis is not None:
            key = f"{_REDIS_KEY_PREFIX}{state.job_id}"
            await self._redis.setex(key, _REDIS_TTL_S, serialized)

    def _sqlite_upsert(self, state: JobState, serialized: str) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("""
                INSERT INTO job_states (job_id, sample_id, current_status, state_json, created_at, last_updated)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    current_status = excluded.current_status,
                    state_json     = excluded.state_json,
                    last_updated   = excluded.last_updated
            """, (
                state.job_id,
                state.sample_id,
                state.current_status.value,
                serialized,
                state.created_at.isoformat(),
                state.last_updated.isoformat(),
            ))
            conn.commit()

    # ──────────────────────────────────────────────────────────────────────
    # Get
    # ──────────────────────────────────────────────────────────────────────

    async def get(self, job_id: str) -> Optional[JobState]:
        # Try Redis first
        if self._redis is not None:
            raw = await self._redis.get(f"{_REDIS_KEY_PREFIX}{job_id}")
            if raw:
                return JobState.model_validate_json(raw)

        # Fall back to SQLite
        return self._sqlite_get(job_id)

    def _sqlite_get(self, job_id: str) -> Optional[JobState]:
        with sqlite3.connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT state_json FROM job_states WHERE job_id = ?", (job_id,)
            ).fetchone()
        if row:
            return JobState.model_validate_json(row[0])
        return None

    # ──────────────────────────────────────────────────────────────────────
    # List
    # ──────────────────────────────────────────────────────────────────────

    def list_by_status(self, status: JobStatus) -> list[JobState]:
        """Synchronous query for monitoring/health endpoints."""
        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute(
                "SELECT state_json FROM job_states WHERE current_status = ?",
                (status.value,),
            ).fetchall()
        return [JobState.model_validate_json(r[0]) for r in rows]

    def count_by_status(self) -> dict[str, int]:
        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute(
                "SELECT current_status, COUNT(*) FROM job_states GROUP BY current_status"
            ).fetchall()
        return {row[0]: row[1] for row in rows}

    # ──────────────────────────────────────────────────────────────────────
    # Atomic CAS (Compare-And-Swap) for distributed coordination
    # ──────────────────────────────────────────────────────────────────────

    async def transition_atomic(
        self,
        job_id: str,
        expected_status: JobStatus,
        new_status: JobStatus,
        agent_name: str,
        reason: str = "",
    ) -> Optional[JobState]:
        """
        Atomic compare-and-swap state transition.

        Only succeeds if current_status == expected_status in SQLite.
        Uses SQLite row-level locking (single-writer) for atomicity.
        Returns updated JobState on success, None if CAS failed (another agent won).
        """
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT state_json FROM job_states WHERE job_id = ? AND current_status = ?",
                    (job_id, expected_status.value),
                ).fetchone()

                if row is None:
                    conn.execute("ROLLBACK")
                    return None

                state = JobState.model_validate_json(row[0])
                state.transition_to(new_status, triggered_by=agent_name, reason=reason)
                state.agent_in_charge = agent_name

                serialized = state.model_dump_json()
                conn.execute("""
                    UPDATE job_states
                    SET current_status = ?, state_json = ?, last_updated = ?
                    WHERE job_id = ? AND current_status = ?
                """, (
                    new_status.value,
                    serialized,
                    state.last_updated.isoformat(),
                    job_id,
                    expected_status.value,
                ))
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

        # Update Redis hot cache
        if self._redis is not None:
            try:
                key = f"{_REDIS_KEY_PREFIX}{job_id}"
                await self._redis.setex(key, _REDIS_TTL_S, serialized)
            except Exception as e:
                logger.warning("redis_cache_update_failed_after_cas", error=str(e))

        logger.debug(
            "cas_transition_success",
            extra=dict(job_id=job_id, agent=agent_name,
                       from_status=expected_status.value, to_status=new_status.value),
        )
        return state

    async def claim_job(
        self,
        job_id: str,
        expected_status: JobStatus,
        claiming_status: JobStatus,
        agent_name: str,
    ) -> Optional[JobState]:
        """
        Convenience wrapper: claim a job by transitioning from expected → claiming status.
        Returns the claimed JobState, or None if another agent already claimed it.
        """
        return await self.transition_atomic(
            job_id=job_id,
            expected_status=expected_status,
            new_status=claiming_status,
            agent_name=agent_name,
            reason=f"claimed by {agent_name}",
        )
