"""
In-memory broker implementation — for unit/integration tests only.

Thread-safe but not process-safe. Not for production use.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections import defaultdict
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from .interface import AcknowledgeableMessage, BrokerInterface, MessageHandler

logger = logging.getLogger(__name__)


class MemoryBroker(BrokerInterface):
    """
    Simple in-memory async broker backed by asyncio.Queue per stream.

    Consumer groups are simulated: each group gets its own queue view.
    Messages are delivered once per consumer group (not per consumer).
    """

    def __init__(self) -> None:
        # stream → consumer_group → asyncio.Queue
        self._queues: Dict[str, Dict[str, asyncio.Queue]] = defaultdict(
            lambda: defaultdict(asyncio.Queue)
        )
        # stream → list of raw entries (for replay in tests)
        self._log: Dict[str, List[dict]] = defaultdict(list)
        # pending messages waiting for ack: message_id → (stream, cg, entry)
        self._pending: Dict[str, tuple] = {}
        self._running = True

    # ──────────────────────────────────────────────────────────────────────
    # Publish
    # ──────────────────────────────────────────────────────────────────────

    async def publish(self, stream: str, message: BaseModel) -> str:
        data = json.loads(message.model_dump_json())
        return await self.publish_raw(stream, data)

    async def publish_raw(self, stream: str, data: dict) -> str:
        msg_id = str(uuid.uuid4())
        entry = {"_id": msg_id, **data}
        self._log[stream].append(entry)

        # Fan-out to all existing consumer groups for this stream
        # IMPORTANT: Use .get() to avoid creating new defaultdict entries during publish
        stream_groups = self._queues.get(stream, {})
        cg_count = len(stream_groups)
        job_id = data.get("job_id", "?")
        logger.debug(
            f"Publishing message",
            extra={
                "stream": stream,
                "msg_id": msg_id,
                "job_id": job_id,
                "num_consumer_groups": cg_count,
                "msg_keys": list(data.keys()),
            }
        )
        for cg_name, queue in stream_groups.items():
            await queue.put(entry)
            logger.debug(
                f"Queued message for consumer group",
                extra={
                    "stream": stream,
                    "consumer_group": cg_name,
                    "job_id": job_id,
                    "queue_size": queue.qsize(),
                }
            )

        return msg_id

    # ──────────────────────────────────────────────────────────────────────
    # Consumer group
    # ──────────────────────────────────────────────────────────────────────

    async def create_consumer_group(
        self,
        stream: str,
        consumer_group: str,
        from_id: str = "0",
    ) -> None:
        # Ensure the queue exists; messages published before group creation
        # are backfilled when from_id="0"
        if consumer_group not in self._queues[stream]:
            self._queues[stream][consumer_group] = asyncio.Queue()
            if from_id == "0":
                for entry in self._log.get(stream, []):
                    await self._queues[stream][consumer_group].put(entry)

    # ──────────────────────────────────────────────────────────────────────
    # Subscribe (consume loop)
    # ──────────────────────────────────────────────────────────────────────

    async def subscribe(
        self,
        stream: str,
        consumer_group: str,
        consumer_name: str,
        handler: MessageHandler,
        batch_size: int = 10,
        block_ms: int = 2000,
    ) -> None:
        await self.create_consumer_group(stream, consumer_group)
        queue = self._queues[stream][consumer_group]

        while self._running:
            try:
                entry = await asyncio.wait_for(
                    queue.get(), timeout=block_ms / 1000.0
                )
            except asyncio.TimeoutError:
                continue

            delivery_id = str(uuid.uuid4())
            self._pending[delivery_id] = (stream, consumer_group, entry)

            ack_msg = AcknowledgeableMessage(
                stream=stream,
                message_id=delivery_id,
                data=entry,
                _broker=self,
            )
            try:
                await handler(ack_msg)
            except Exception:
                # Handler did not ack/nack explicitly; treat as nack
                await self._nack(stream, delivery_id, requeue=True)

    # ──────────────────────────────────────────────────────────────────────
    # Ack / Nack
    # ──────────────────────────────────────────────────────────────────────

    async def _ack(self, stream: str, message_id: str) -> None:
        self._pending.pop(message_id, None)

    async def _nack(self, stream: str, message_id: str, requeue: bool) -> None:
        pending = self._pending.pop(message_id, None)
        if pending and requeue:
            orig_stream, cg, entry = pending
            await self._queues[orig_stream][cg].put(entry)

    # ──────────────────────────────────────────────────────────────────────
    # Utilities
    # ──────────────────────────────────────────────────────────────────────

    async def close(self) -> None:
        self._running = False

    def get_log(self, stream: str) -> List[dict]:
        """Return all messages ever published to a stream (for test assertions)."""
        return list(self._log.get(stream, []))

    def queue_size(self, stream: str, consumer_group: str) -> int:
        """Return number of undelivered messages in a consumer group queue."""
        return self._queues[stream][consumer_group].qsize()
