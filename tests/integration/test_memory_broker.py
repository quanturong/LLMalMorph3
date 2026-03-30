import asyncio

from broker.memory_broker import MemoryBroker


async def _noop_handler(msg):
    await msg.ack()


def test_memory_broker_publish_subscribe():
    async def _run():
        broker = MemoryBroker()
        await broker.create_consumer_group("stream.a", "cg1")
        await broker.publish_raw("stream.a", {"hello": "world"})

        task = asyncio.create_task(
            broker.subscribe("stream.a", "cg1", "consumer1", _noop_handler, block_ms=50)
        )
        await asyncio.sleep(0.1)
        await broker.close()
        await asyncio.sleep(0.05)
        task.cancel()

        logs = broker.get_log("stream.a")
        assert len(logs) == 1
        assert logs[0]["hello"] == "world"

    asyncio.run(_run())
