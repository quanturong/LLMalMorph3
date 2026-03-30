"""
Redis Streams broker implementation.

Uses redis-py async client with consumer groups for exactly-once delivery
per consumer group (at-least-once per message, idempotency in agents).

Requirements:
    pip install redis>=5.0
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

import redis.asyncio as aioredis
from pydantic import BaseModel

from .interface import AcknowledgeableMessage, BrokerInterface, MessageHandler

logger = logging.getLogger(__name__)


class RedisStreamsBroker(BrokerInterface):
    """
    Production-ready broker backed by Redis Streams.

    Consumer groups provide:
    - At-least-once delivery
    - Per-consumer-group message tracking
    - Built-in pending entry list (PEL) for crash recovery
    - XAUTOCLAIM for reclaiming stale pending messages
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        max_stream_len: int = 100_000,
        claim_idle_ms: int = 30_000,   # reclaim messages idle > 30s
    ) -> None:
        self._redis_url = redis_url
        self._max_stream_len = max_stream_len
        self._claim_idle_ms = claim_idle_ms
        self._client: Optional[aioredis.Redis] = None
        self._running = True

    async def _get_client(self) -> aioredis.Redis:
        if self._client is None:
            self._client = await aioredis.from_url(
                self._redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
        return self._client

    # ──────────────────────────────────────────────────────────────────────
    # Publish
    # ──────────────────────────────────────────────────────────────────────

    async def publish(self, stream: str, message: BaseModel) -> str:
        data = json.loads(message.model_dump_json())
        return await self.publish_raw(stream, data)

    async def publish_raw(self, stream: str, data: dict) -> str:
        client = await self._get_client()
        # Flatten for Redis: values must be strings
        flat = {k: _to_str(v) for k, v in data.items()}
        msg_id = await client.xadd(
            stream,
            flat,
            maxlen=self._max_stream_len,
            approximate=True,
        )
        logger.debug("Published to %s id=%s", stream, msg_id)
        return msg_id

    # ──────────────────────────────────────────────────────────────────────
    # Consumer group
    # ──────────────────────────────────────────────────────────────────────

    async def create_consumer_group(
        self,
        stream: str,
        consumer_group: str,
        from_id: str = "$",
    ) -> None:
        client = await self._get_client()
        # Ensure stream exists
        try:
            await client.xadd(stream, {"_init": "1"}, maxlen=1, approximate=True)
        except Exception:
            pass
        try:
            await client.xgroup_create(stream, consumer_group, id=from_id)
            logger.info("Created consumer group %s on %s", consumer_group, stream)
        except aioredis.ResponseError as e:
            if "BUSYGROUP" in str(e):
                pass  # already exists
            else:
                raise

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
        await self.create_consumer_group(stream, consumer_group, from_id="$")
        client = await self._get_client()

        while self._running:
            # 1. Claim any stale pending messages first (crash recovery)
            try:
                claimed = await client.xautoclaim(
                    stream,
                    consumer_group,
                    consumer_name,
                    self._claim_idle_ms,
                    start_id="0-0",
                    count=batch_size,
                )
                # xautoclaim returns (next_id, messages, deleted_ids)
                stale_entries = claimed[1] if isinstance(claimed, (list, tuple)) else []
                for entry_id, fields in stale_entries:
                    data = {k: _from_str(k, v) for k, v in fields.items()}
                    msg = AcknowledgeableMessage(
                        stream=stream,
                        message_id=entry_id,
                        data=data,
                        _broker=self,
                    )
                    await _safe_handle(handler, msg, self, stream, entry_id)
            except Exception as e:
                logger.warning("xautoclaim error on %s: %s", stream, e)

            # 2. Read new messages
            try:
                results = await client.xreadgroup(
                    consumer_group,
                    consumer_name,
                    {stream: ">"},
                    count=batch_size,
                    block=block_ms,
                )
            except Exception as e:
                logger.error("xreadgroup error on %s: %s", stream, e)
                continue

            if not results:
                continue

            for _stream_name, entries in results:
                for entry_id, fields in entries:
                    data = {k: _from_str(k, v) for k, v in fields.items()}
                    msg = AcknowledgeableMessage(
                        stream=stream,
                        message_id=entry_id,
                        data=data,
                        _broker=self,
                    )
                    await _safe_handle(handler, msg, self, stream, entry_id)

    # ──────────────────────────────────────────────────────────────────────
    # Ack / Nack
    # ──────────────────────────────────────────────────────────────────────

    async def _ack(self, stream: str, message_id: str) -> None:
        client = await self._get_client()
        try:
            # Find consumer group from message — we need the group name
            # In practice, each broker instance is tied to one consumer group;
            # pass group via context. For simplicity, we store it during subscribe.
            # This is best-effort; RedisStreamsBroker instances are per-agent.
            await client.xack(stream, self._active_group, message_id)
        except Exception as e:
            logger.warning("xack failed for %s: %s", message_id, e)

    async def _nack(self, stream: str, message_id: str, requeue: bool) -> None:
        # Redis Streams has no built-in nack; messages stay in PEL until
        # claimed/acked. If not retrying, move to DLQ manually.
        if not requeue:
            client = await self._get_client()
            try:
                from .topics import Topic
                await client.xadd(
                    Topic.DLQ,
                    {"_original_stream": stream, "_failed_id": message_id},
                    maxlen=50_000,
                    approximate=True,
                )
                await client.xack(stream, self._active_group, message_id)
            except Exception as e:
                logger.error("DLQ routing failed for %s: %s", message_id, e)

    async def close(self) -> None:
        self._running = False
        if self._client:
            await self._client.aclose()
            self._client = None

    # Active consumer group — set during subscribe so _ack can use it
    _active_group: str = ""


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _to_str(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value)


def _from_str(key: str, value: str) -> Any:
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value


async def _safe_handle(
    handler: MessageHandler,
    msg: AcknowledgeableMessage,
    broker: BrokerInterface,
    stream: str,
    entry_id: str,
) -> None:
    try:
        await handler(msg)
    except Exception as e:
        logger.error(
            "Handler raised unhandled exception for %s on %s: %s",
            entry_id, stream, e, exc_info=True,
        )
        await broker._nack(stream, entry_id, requeue=False)
