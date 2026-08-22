import asyncio
from typing import Union

from app.core.events import SecurityEvent, DetectionAlert


class EventManager:

    def __init__(self):
        # Store events/alerts history (with capacity limit)
        self.events: list[Union[SecurityEvent, DetectionAlert]] = []
        self.clients: set[asyncio.Queue] = set()

    async def publish(self, event: Union[SecurityEvent, DetectionAlert]):
        self.events.append(event)

        # Keep memory usage bounded during development
        if len(self.events) > 1000:
            self.events.pop(0)

        disconnected_clients = []

        for queue in self.clients:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                disconnected_clients.append(queue)

        for queue in disconnected_clients:
            self.clients.discard(queue)

    def subscribe(self) -> asyncio.Queue:
        queue = asyncio.Queue(maxsize=200)
        self.clients.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue):
        self.clients.discard(queue)


event_manager = EventManager()