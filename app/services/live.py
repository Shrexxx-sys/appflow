"""
live.py - keeps track of open WebSocket connections and pushes messages to them.

Think of it like a group chat per session: every dashboard watching session 5
joins "room 5". When new data for session 5 arrives, we send it to everyone in room 5.
"""
import logging
from collections import defaultdict

from fastapi import WebSocket

log = logging.getLogger("appflow.live")


class LiveManager:
    def __init__(self) -> None:
        self.rooms: dict[int, set[WebSocket]] = defaultdict(set)

    async def join(self, session_id: int, ws: WebSocket) -> None:
        await ws.accept()
        self.rooms[session_id].add(ws)

    def leave(self, session_id: int, ws: WebSocket) -> None:
        self.rooms[session_id].discard(ws)
        if not self.rooms[session_id]:
            del self.rooms[session_id]

    def viewer_count(self, session_id: int) -> int:
        return len(self.rooms.get(session_id, ()))

    async def broadcast(self, session_id: int, message: dict) -> None:
        """Send to every viewer. A broken connection is removed instead of crashing the request."""
        for ws in list(self.rooms.get(session_id, ())):
            try:
                await ws.send_json(message)
            except Exception:
                log.info("Dropping dead WebSocket for session %s", session_id)
                self.leave(session_id, ws)

    async def close_room(self, session_id: int) -> None:
        """Used when a session is deleted: disconnect everyone watching it."""
        for ws in list(self.rooms.get(session_id, ())):
            try:
                await ws.close(code=4410)  # 4410 ~ "gone"
            except Exception:
                pass
            self.leave(session_id, ws)


manager = LiveManager()  # one shared instance for the whole app
