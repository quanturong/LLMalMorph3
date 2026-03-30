"""
BaseAgent — abstract foundation for all agents in the distributed pipeline.

Provides:
  - dual subscription: command stream (direct) + EVENTS_ALL (self-activation)
  - self-activation via activates_on mapping (event_type → expected_job_status)
  - atomic state claim via StateStore CAS (prevents duplicate processing)
  - idempotency check (Redis SET NX on message_id)
  - heartbeat emission for health monitoring
  - peer-to-peer negotiation support
  - error handling → emit ErrorEvent
  - structured logging with job/correlation context
  - OpenTelemetry span per message
  - Prometheus duration tracking
"""

from __future__ import annotations

import abc
import asyncio
import json
import logging
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, ClassVar, Dict, FrozenSet, Optional, Tuple

import structlog

from broker.interface import AcknowledgeableMessage, BrokerInterface
from broker.topics import Topic
from contracts.job import JobStatus
from contracts.messages import (
    AgentRegistrationEvent,
    ErrorEvent,
    HeartbeatEvent,
    NegotiationRequest,
    NegotiationResponse,
)
from observability.metrics import AGENT_LATENCY, DLQ_COUNT, track_agent_duration
from observability.tracing import get_tracer

logger = structlog.get_logger(__name__)

_IDEMPOTENCY_WINDOW_S = 3600  # 1 hour
_HEARTBEAT_INTERVAL_S = 30


@dataclass
class AgentContext:
    """Runtime dependencies injected into every agent."""
    broker: BrokerInterface
    redis_client: Optional[Any] = None    # redis.asyncio.Redis
    state_store: Optional[Any] = None     # StateStore
    artifact_store: Optional[Any] = None  # ArtifactStore
    report_store: Optional[Any] = None    # ReportStore
    llm_provider: Optional[Any] = None    # LLMProviderInterface
    agent_registry: Optional[Any] = None  # AgentRegistry
    work_dir: str = "project_mutation_output"  # Working dir for build/variant/mut_src subdirs


class BaseAgent(abc.ABC):
    """
    Abstract base for all distributed pipeline agents.

    Distributed behavior:
        - Each agent subscribes to EVENTS_ALL with its own consumer group
        - activates_on: maps event field signatures → (expected_status, claiming_status)
        - When an event matches, agent attempts atomic CAS claim via StateStore
        - Only the agent that wins the claim processes the job
        - Agents also listen on their command_stream for backward compatibility

    Subclasses implement:
        - agent_name: str property
        - command_stream: str property
        - consumer_group: str property
        - event_consumer_group: str property (CG for EVENTS_ALL subscription)
        - activates_on: dict mapping event signatures to state transitions
        - handle(msg): async method that processes one message
        - handle_event(data, claimed_state): optional override for event-driven activation
    """

    @property
    @abc.abstractmethod
    def agent_name(self) -> str: ...

    @property
    @abc.abstractmethod
    def command_stream(self) -> str: ...

    @property
    @abc.abstractmethod
    def consumer_group(self) -> str: ...

    @property
    def event_consumer_group(self) -> str:
        """Consumer group for EVENTS_ALL subscription. Override in subclass."""
        return ""

    # ── Self-activation mapping ───────────────────────────────────────────
    # Format: { "field_signature": (expected_job_status, claiming_status) }
    # field_signature = frozenset of field names that identify the event type
    # When an event matches, agent tries CAS: expected → claiming
    activates_on: ClassVar[Dict[FrozenSet[str], Tuple[JobStatus, JobStatus]]] = {}

    # ── Agent capabilities (published at registration) ────────────────────
    capabilities: ClassVar[Dict[str, Any]] = {}

    def __init__(self, ctx: AgentContext) -> None:
        self._ctx = ctx
        self._running = False
        self._log = structlog.get_logger(self.agent_name)
        self._start_time = 0.0
        self._jobs_processed = 0
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._current_job_id: Optional[str] = None

    # ──────────────────────────────────────────────────────────────────────
    # Main loop — dual subscription
    # ──────────────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start dual consume loops: command stream + EVENTS_ALL self-activation."""
        self._running = True
        self._start_time = time.monotonic()
        self._log.info("agent_started", stream=self.command_stream,
                       event_cg=self.event_consumer_group,
                       activates_on=list(self.activates_on.keys()) if self.activates_on else [])

        # Register with agent registry
        await self._register()

        # Start heartbeat
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        # Subscribe to command stream (direct commands / backward compat)
        cmd_task = asyncio.create_task(
            self._ctx.broker.subscribe(
                stream=self.command_stream,
                consumer_group=self.consumer_group,
                consumer_name=self.agent_name,
                handler=self._dispatch,
            )
        )

        # Subscribe to EVENTS_ALL for self-activation (if agent has activates_on)
        if self.activates_on and self.event_consumer_group:
            event_task = asyncio.create_task(
                self._ctx.broker.subscribe(
                    stream=Topic.EVENTS_ALL,
                    consumer_group=self.event_consumer_group,
                    consumer_name=f"{self.agent_name}_event_listener",
                    handler=self._dispatch_event,
                )
            )
            await asyncio.gather(cmd_task, event_task)
        else:
            await cmd_task

    async def stop(self) -> None:
        self._running = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
        # Deregister
        await self._deregister()
        self._log.info("agent_stopped")

    # ──────────────────────────────────────────────────────────────────────
    # Command dispatch (from command stream — direct commands)
    # ──────────────────────────────────────────────────────────────────────

    async def _dispatch(self, msg: AcknowledgeableMessage) -> None:
        data = msg.data
        job_id = data.get("job_id", "unknown")
        message_id = data.get("message_id", msg.message_id)
        correlation_id = data.get("correlation_id", "")
        sample_id = data.get("sample_id", "")

        bound_log = self._log.bind(
            job_id=job_id,
            sample_id=sample_id,
            correlation_id=correlation_id,
        )

        # Idempotency check
        if not await self._acquire_idempotency_lock(message_id, bound_log):
            await msg.ack()
            return

        tracer = get_tracer()
        with tracer.start_as_current_span(
            f"{self.agent_name}.handle",
            attributes={
                "job.id": job_id,
                "sample.id": sample_id,
                "agent.name": self.agent_name,
            },
        ):
            start = time.monotonic()
            status = "success"
            try:
                self._current_job_id = job_id
                bound_log.info("command_received")
                await self.handle(data)
                await msg.ack()
                self._jobs_processed += 1
                bound_log.info("command_processed")
            except Exception as exc:
                status = "error"
                bound_log.error(
                    "command_failed",
                    exc_type=type(exc).__name__,
                    exc_msg=str(exc),
                )
                await self._emit_error(data, exc)
                await msg.nack(requeue=False)
                DLQ_COUNT.labels(agent=self.agent_name).inc()
            finally:
                self._current_job_id = None
                duration = time.monotonic() - start
                AGENT_LATENCY.labels(
                    agent_name=self.agent_name, status=status
                ).observe(duration)

    # ──────────────────────────────────────────────────────────────────────
    # Event dispatch (from EVENTS_ALL — self-activation)
    # ──────────────────────────────────────────────────────────────────────

    async def _dispatch_event(self, msg: AcknowledgeableMessage) -> None:
        """
        Event-driven self-activation:
        1. Match event against activates_on signatures
        2. If match, attempt atomic CAS claim via StateStore
        3. If claim succeeds, process the event
        4. If claim fails (another agent won), ack and skip
        """
        data = msg.data
        job_id = data.get("job_id", "")

        if not job_id:
            await msg.ack()
            return

        # Match event against our activation rules
        matched = self._match_activation(data)
        if matched is None:
            # Debug: Log what keys were in the event and what our activation rules expect
            event_keys = frozenset(data.keys())
            self._log.debug(
                "event_no_match",
                job_id=job_id,
                event_keys=sorted(event_keys),
                activates_on=[str(k) for k in self.activates_on.keys()],
            )
            await msg.ack()
            return

        expected_status, claiming_status = matched
        message_id = data.get("message_id", msg.message_id)

        bound_log = self._log.bind(
            job_id=job_id,
            sample_id=data.get("sample_id", ""),
            activation="event_driven",
        )

        # Idempotency
        if not await self._acquire_idempotency_lock(f"evt:{message_id}", bound_log):
            await msg.ack()
            return

        # Atomic CAS claim — only one agent instance wins
        state_store = self._ctx.state_store
        if state_store is None:
            bound_log.warning("no_state_store_for_cas")
            await msg.ack()
            return

        claimed_state = await state_store.claim_job(
            job_id=job_id,
            expected_status=expected_status,
            claiming_status=claiming_status,
            agent_name=self.agent_name,
        )

        if claimed_state is None:
            # Another agent already claimed this job or state doesn't match
            current_state = await state_store.get(job_id) if state_store else None
            bound_log.debug(
                "event_claim_failed",
                expected_status=expected_status.value if expected_status else None,
                current_status=current_state.current_status.value if current_state else "unknown",
                reason="state_mismatch_or_already_claimed"
            )
            await msg.ack()
            return

        bound_log.info(
            "job_claimed",
            from_status=expected_status.value,
            to_status=claiming_status.value,
        )

        tracer = get_tracer()
        with tracer.start_as_current_span(
            f"{self.agent_name}.handle_event",
            attributes={
                "job.id": job_id,
                "agent.name": self.agent_name,
                "activation": "event_driven",
            },
        ):
            start = time.monotonic()
            status = "success"
            try:
                self._current_job_id = job_id
                await self.handle_event(data, claimed_state)
                await msg.ack()
                self._jobs_processed += 1
                bound_log.info("event_processed")
            except Exception as exc:
                status = "error"
                bound_log.error(
                    "event_handling_failed",
                    exc_type=type(exc).__name__,
                    exc_msg=str(exc),
                )
                await self._emit_error(data, exc)
                await msg.nack(requeue=False)
                DLQ_COUNT.labels(agent=self.agent_name).inc()
            finally:
                self._current_job_id = None
                duration = time.monotonic() - start
                AGENT_LATENCY.labels(
                    agent_name=self.agent_name, status=status
                ).observe(duration)

    def _match_activation(self, data: dict) -> Optional[Tuple[JobStatus, JobStatus]]:
        """Check if incoming event matches any activates_on signature.

        activates_on values may be:
          - (from_status, to_status)           — key-presence match only
          - (from_status, to_status, guard_fn) — key-presence + value guard
        """
        data_keys = frozenset(data.keys())
        for signature, transition in self.activates_on.items():
            if signature.issubset(data_keys):
                if len(transition) == 3:
                    from_status, to_status, guard_fn = transition
                    if not guard_fn(data):
                        continue
                    return (from_status, to_status)
                return transition
        return None

    # ──────────────────────────────────────────────────────────────────────
    # Abstract handlers
    # ──────────────────────────────────────────────────────────────────────

    @abc.abstractmethod
    async def handle(self, data: dict) -> None:
        """Process one command message. Must not raise — emit ErrorEvent instead."""

    async def handle_event(self, data: dict, claimed_state) -> None:
        """
        Process one self-activated event. Default: delegate to handle().
        Override for custom event-driven logic (e.g., different data extraction).
        """
        await self.handle(data)

    # ──────────────────────────────────────────────────────────────────────
    # Heartbeat
    # ──────────────────────────────────────────────────────────────────────

    async def _heartbeat_loop(self) -> None:
        """Emit periodic heartbeat events."""
        try:
            while self._running:
                hb = HeartbeatEvent(
                    agent_name=self.agent_name,
                    agent_status="busy" if self._current_job_id else "alive",
                    current_job_id=self._current_job_id,
                    capabilities=self.capabilities,
                    uptime_s=time.monotonic() - self._start_time,
                    jobs_processed=self._jobs_processed,
                )
                try:
                    await self._ctx.broker.publish(Topic.HEARTBEAT, hb)
                except Exception:
                    pass  # heartbeat failure is non-critical
                await asyncio.sleep(_HEARTBEAT_INTERVAL_S)
        except asyncio.CancelledError:
            pass

    # ──────────────────────────────────────────────────────────────────────
    # Registration
    # ──────────────────────────────────────────────────────────────────────

    async def _register(self) -> None:
        """Register agent with the distributed registry."""
        reg = AgentRegistrationEvent(
            agent_name=self.agent_name,
            capabilities=self.capabilities,
            activates_on=[str(k) for k in self.activates_on.keys()],
            command_stream=self.command_stream,
            status="online",
        )
        try:
            await self._ctx.broker.publish(Topic.EVENTS_ALL, reg)
        except Exception:
            pass
        if self._ctx.agent_registry:
            await self._ctx.agent_registry.register(
                self.agent_name,
                capabilities=self.capabilities,
                command_stream=self.command_stream,
            )

    async def _deregister(self) -> None:
        """Deregister agent from the distributed registry."""
        if self._ctx.agent_registry:
            await self._ctx.agent_registry.deregister(self.agent_name)

    # ──────────────────────────────────────────────────────────────────────
    # Peer-to-peer negotiation
    # ──────────────────────────────────────────────────────────────────────

    async def negotiate(
        self,
        to_agent: str,
        request_type: str,
        payload: dict,
        job_id: str = "",
        timeout_s: float = 10.0,
    ) -> Optional[dict]:
        """
        Send a negotiation request to a peer agent and wait for response.
        Returns the response payload, or None on timeout.
        """
        req = NegotiationRequest(
            from_agent=self.agent_name,
            to_agent=to_agent,
            request_type=request_type,
            job_id=job_id,
            payload=payload,
            timeout_s=timeout_s,
        )
        await self._ctx.broker.publish(Topic.NEGOTIATE, req)
        # Note: response collection would require a reply stream or callback
        # For now, negotiation is fire-and-forget with convention-based replies
        return None

    async def handle_negotiation(self, request: dict) -> Optional[dict]:
        """Override to handle incoming negotiation requests. Return response payload."""
        return None

    # ──────────────────────────────────────────────────────────────────────
    # Helpers available to subclasses
    # ──────────────────────────────────────────────────────────────────────

    async def publish_event(self, event) -> None:
        """Publish any Pydantic event model to the events stream."""
        await self._ctx.broker.publish(Topic.EVENTS_ALL, event)

    async def publish_command(self, stream: str, command) -> None:
        """Publish a command to a specific agent stream."""
        await self._ctx.broker.publish(stream, command)

    async def transition_and_save(self, state, new_status: JobStatus, reason: str = "") -> None:
        """Helper to transition state and save to store."""
        from workflows.state_machine import JobStateMachine
        sm = JobStateMachine()
        sm.transition(state, new_status, self.agent_name, reason=reason)
        if self._ctx.state_store:
            await self._ctx.state_store.save(state)

    async def _emit_error(self, data: dict, exc: Exception) -> None:
        error_event = ErrorEvent(
            job_id=data.get("job_id", ""),
            sample_id=data.get("sample_id", ""),
            correlation_id=data.get("correlation_id", ""),
            error_code=type(exc).__name__.upper(),
            error_message=str(exc)[:500],
            agent=self.agent_name,
            stage=self.agent_name,
            is_retryable=self._is_retryable(exc),
            retry_count=data.get("retry_count", 0),
            raw_exception=traceback.format_exc()[:2000],
        )
        await self._ctx.broker.publish(Topic.EVENTS_ALL, error_event)

    def _is_retryable(self, exc: Exception) -> bool:
        """Override to customize retryability classification."""
        from llm.provider import LLMTimeoutError, LLMRateLimitError
        return isinstance(exc, (LLMTimeoutError, LLMRateLimitError, ConnectionError, TimeoutError))

    async def _acquire_idempotency_lock(self, message_id: str, log) -> bool:
        """
        Acquire a Redis SET NX lock for this message_id.
        Returns True if we should process, False if already processed.
        Falls back to True if Redis is unavailable.
        """
        if self._ctx.redis_client is None:
            return True
        key = f"idem:{self.agent_name}:{message_id}"
        try:
            acquired = await self._ctx.redis_client.set(
                key, "1", nx=True, ex=_IDEMPOTENCY_WINDOW_S
            )
            if not acquired:
                log.info("duplicate_message_skipped", message_id=message_id)
                return False
            return True
        except Exception as e:
            log.warning("idempotency_check_failed", error=str(e))
            return True  # fail open
