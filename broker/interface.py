"""
Broker interface — abstract base class all broker implementations must satisfy.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

from pydantic import BaseModel


MessageHandler = Callable[["AcknowledgeableMessage"], Awaitable[None]]


@dataclass
class AcknowledgeableMessage:
    """
    A message received from the broker along with its delivery metadata.
    The consumer MUST call ack() on success or nack() on failure so the
    broker can manage retry / DLQ routing.
    """
    stream: str
    message_id: str          # broker-assigned delivery ID (not our UUID)
    data: dict               # raw key-value fields from the stream entry

    _broker: Any = None      # back-reference for ack/nack; set by broker

    async def ack(self) -> None:
        if self._broker is not None:
            await self._broker._ack(self.stream, self.message_id)

    async def nack(self, requeue: bool = True) -> None:
        if self._broker is not None:
            await self._broker._nack(self.stream, self.message_id, requeue)


class BrokerInterface(abc.ABC):
    """
    Abstract async message broker.

    Implementations: MemoryBroker (tests), RedisStreamsBroker (production).
    """

    @abc.abstractmethod
    async def publish(self, stream: str, message: BaseModel) -> str:
        """
        Publish a Pydantic model to a stream.
        Returns the broker-assigned message ID.
        """

    @abc.abstractmethod
    async def publish_raw(self, stream: str, data: dict) -> str:
        """Publish a raw dict (for forwarding / re-queuing)."""

    @abc.abstractmethod
    async def subscribe(
        self,
        stream: str,
        consumer_group: str,
        consumer_name: str,
        handler: MessageHandler,
        batch_size: int = 10,
        block_ms: int = 2000,
    ) -> None:
        """
        Start consuming from a stream until cancelled.
        Calls handler for each message; handler is responsible for ack/nack.
        """

    @abc.abstractmethod
    async def create_consumer_group(
        self,
        stream: str,
        consumer_group: str,
        from_id: str = "0",
    ) -> None:
        """Create consumer group if it does not exist."""

    @abc.abstractmethod
    async def close(self) -> None:
        """Release resources."""

    @abc.abstractmethod
    async def _ack(self, stream: str, message_id: str) -> None:
        """Internal: acknowledge a message."""

    @abc.abstractmethod
    async def _nack(self, stream: str, message_id: str, requeue: bool) -> None:
        """Internal: negative-acknowledge a message."""
