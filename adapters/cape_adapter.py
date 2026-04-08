"""
CAPE sandbox adapter — thin async wrapper around the existing CapeApiClient.

This adapter isolates all CAPE-specific HTTP calls from the agent layer.
Agents depend on this interface, not on CapeApiClient directly, making it
easy to swap backends (CAPE ↔ VT ↔ mock) without changing agent code.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Ensure src/ is on path for legacy imports
_src_path = os.path.join(os.path.dirname(__file__), "..", "src")
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)


class CapeAdapter:
    """
    Async adapter around src/sandbox_analyzer.CapeApiClient.

    All blocking HTTP calls are run in the thread pool executor.
    """

    def __init__(
        self,
        api_url: str,
        api_token: str = "",
        http_timeout_s: int = 30,
    ) -> None:
        from sandbox_analyzer import CapeApiClient
        self._client = CapeApiClient(
            api_url=api_url,
            api_token=api_token,
            timeout=http_timeout_s,
        )
        self._loop_executor = None  # uses default ThreadPoolExecutor

    async def test_connection(self) -> bool:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._client.test_connection)

    async def submit_file(
        self,
        filepath: str,
        platform: str = "windows",
        timeout_analysis: int = 120,
        machine: str = "",
        options: Optional[Dict[str, str]] = None,
    ) -> Optional[int]:
        """Submit a file and return task_id, or None on failure."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: self._client.submit_file(
                filepath=filepath,
                machine=machine,
                platform=platform,
                timeout_analysis=timeout_analysis,
                options=options or {},
            ),
        )

    async def submit_bytes(
        self,
        file_bytes: bytes,
        filename: str = "sample.exe",
        platform: str = "windows",
        timeout_analysis: int = 120,
        machine: str = "",
        options: Optional[Dict[str, str]] = None,
    ) -> Optional[int]:
        """Submit in-memory bytes (no plaintext on disk). Returns task_id."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: self._client.submit_bytes(
                file_bytes=file_bytes,
                filename=filename,
                machine=machine,
                platform=platform,
                timeout_analysis=timeout_analysis,
                options=options or {},
            ),
        )

    async def get_task_status(self, task_id: int) -> str:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: self._client.get_task_status(task_id)
        )

    async def get_report(self, task_id: int) -> Optional[Dict[str, Any]]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: self._client.get_report(task_id)
        )

    async def is_complete(self, task_id: int) -> bool:
        """Returns True if task reached a terminal status."""
        status = await self.get_task_status(task_id)
        return status in ("reported", "completed", "failed_analysis")
