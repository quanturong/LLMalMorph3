"""
Broker package — message transport abstraction layer.

Primary:   Redis Streams  (redis_streams.py)
Test/Dev:  In-memory      (memory_broker.py)
"""

from .interface import BrokerInterface, MessageHandler, AcknowledgeableMessage
from .topics import Topic
from .memory_broker import MemoryBroker

__all__ = [
    "BrokerInterface",
    "MessageHandler",
    "AcknowledgeableMessage",
    "Topic",
    "MemoryBroker",
]
