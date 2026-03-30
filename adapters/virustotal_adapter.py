"""
VirusTotal adapter — thin async wrapper around src/sandbox_analyzer.VirusTotalApiClient.

Implements the same interface as CapeAdapter so agents can swap backends transparently.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_src_path = os.path.join(os.path.dirname(__file__), "..", "src")
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)


class VirusTotalAdapter:
    """
    Async adapter around src/sandbox_analyzer.VirusTotalApiClient.

    All blocking HTTP calls are run in the thread pool executor.
    Compatible with CapeAdapter's interface so agents need no backend-specific logic.
    """

    def __init__(
        self,
        api_key: str,
        api_url: str = "https://www.virustotal.com",
        http_timeout_s: int = 60,
    ) -> None:
        from sandbox_analyzer import VirusTotalApiClient
        self._client = VirusTotalApiClient(
            api_url=api_url,
            api_token=api_key,
            timeout=http_timeout_s,
        )

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
    ) -> Optional[str]:
        """Submit a file and return the VT analysis ID, or None on failure."""
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

    async def get_task_status(self, task_id: str) -> str:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: self._client.get_task_status(task_id)
        )

    async def get_report(self, task_id: str) -> Optional[Dict[str, Any]]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: self._client.get_report(task_id)
        )

    async def is_complete(self, task_id: str) -> bool:
        """Returns True if analysis reached a terminal status."""
        status = await self.get_task_status(task_id)
        return status in ("completed",)
