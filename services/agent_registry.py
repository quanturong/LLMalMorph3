"""
AgentRegistry — distributed agent discovery and capability tracking.

Each agent registers on startup with its capabilities and activation rules.
Other agents can discover peers by capability, check liveness via heartbeat
tracking, and find agents that handle specific event types.

Thread-safe via asyncio lock. Persistence via optional Redis or in-memory dict.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_HEARTBEAT_TIMEOUT_S = 90  # Agent considered dead if no heartbeat in 90s


@dataclass
class AgentRecord:
    """Metadata about a registered agent."""
    agent_name: str
    capabilities: Dict[str, Any] = field(default_factory=dict)
    command_stream: str = ""
    activates_on: List[str] = field(default_factory=list)
    status: str = "online"          # "online" | "busy" | "offline" | "dead"
    last_heartbeat: float = 0.0     # monotonic timestamp
    registered_at: float = 0.0
    jobs_processed: int = 0
    current_job_id: Optional[str] = None


class AgentRegistry:
    """
    In-memory agent registry with heartbeat-based liveness detection.

    Usage:
        registry = AgentRegistry()
        await registry.register("BuildAgent", capabilities={"compiler": "msvc"})
        agents = await registry.discover_by_capability("compiler")
        alive = await registry.get_alive_agents()
    """

    def __init__(self, heartbeat_timeout_s: float = _HEARTBEAT_TIMEOUT_S) -> None:
        self._agents: Dict[str, AgentRecord] = {}
        self._lock = asyncio.Lock()
        self._heartbeat_timeout_s = heartbeat_timeout_s

    async def register(
        self,
        agent_name: str,
        capabilities: Optional[Dict[str, Any]] = None,
        command_stream: str = "",
        activates_on: Optional[List[str]] = None,
    ) -> None:
        """Register or update an agent's metadata."""
        async with self._lock:
            now = time.monotonic()
            if agent_name in self._agents:
                rec = self._agents[agent_name]
                rec.capabilities = capabilities or rec.capabilities
                rec.command_stream = command_stream or rec.command_stream
                rec.activates_on = activates_on or rec.activates_on
                rec.status = "online"
                rec.last_heartbeat = now
            else:
                self._agents[agent_name] = AgentRecord(
                    agent_name=agent_name,
                    capabilities=capabilities or {},
                    command_stream=command_stream,
                    activates_on=activates_on or [],
                    status="online",
                    last_heartbeat=now,
                    registered_at=now,
                )
            logger.info("agent_registered: %s caps=%s", agent_name, capabilities)

    async def deregister(self, agent_name: str) -> None:
        """Mark an agent as offline."""
        async with self._lock:
            if agent_name in self._agents:
                self._agents[agent_name].status = "offline"
                logger.info("agent_deregistered: %s", agent_name)

    async def update_heartbeat(
        self,
        agent_name: str,
        status: str = "alive",
        current_job_id: Optional[str] = None,
        jobs_processed: int = 0,
    ) -> None:
        """Update heartbeat timestamp and optional status."""
        async with self._lock:
            if agent_name in self._agents:
                rec = self._agents[agent_name]
                rec.last_heartbeat = time.monotonic()
                rec.status = status
                rec.current_job_id = current_job_id
                rec.jobs_processed = jobs_processed

    async def discover_by_capability(self, capability: str) -> List[AgentRecord]:
        """Find all alive agents that have a given capability key."""
        async with self._lock:
            self._prune_dead()
            return [
                rec for rec in self._agents.values()
                if rec.status in ("online", "busy")
                and capability in rec.capabilities
            ]

    async def discover_by_event(self, event_type: str) -> List[AgentRecord]:
        """Find all alive agents that activate on a specific event type."""
        async with self._lock:
            self._prune_dead()
            return [
                rec for rec in self._agents.values()
                if rec.status in ("online", "busy")
                and event_type in rec.activates_on
            ]

    async def get_agent(self, agent_name: str) -> Optional[AgentRecord]:
        """Get a specific agent's record."""
        async with self._lock:
            return self._agents.get(agent_name)

    async def get_alive_agents(self) -> List[AgentRecord]:
        """Return all agents considered alive."""
        async with self._lock:
            self._prune_dead()
            return [
                rec for rec in self._agents.values()
                if rec.status in ("online", "busy")
            ]

    async def get_all_agents(self) -> Dict[str, AgentRecord]:
        """Return all registered agents (including dead/offline)."""
        async with self._lock:
            return dict(self._agents)

    async def get_dead_agents(self) -> List[AgentRecord]:
        """Return agents that missed heartbeat deadline."""
        async with self._lock:
            self._prune_dead()
            return [
                rec for rec in self._agents.values()
                if rec.status == "dead"
            ]

    def _prune_dead(self) -> None:
        """Mark agents as dead if heartbeat is stale. Must hold lock."""
        now = time.monotonic()
        for rec in self._agents.values():
            if rec.status in ("online", "busy"):
                if now - rec.last_heartbeat > self._heartbeat_timeout_s:
                    rec.status = "dead"
                    logger.warning("agent_dead_heartbeat_timeout: %s", rec.agent_name)
