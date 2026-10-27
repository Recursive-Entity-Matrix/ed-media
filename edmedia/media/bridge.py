"""Loopback socket bridge for Proton / Wine environments.

Allows EDMedia running inside a Wine/Proton prefix to seamlessly communicate
with the Linux host's active desktop media player over 127.0.0.1.
"""

from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional
from urllib.request import Request, urlopen

from edmedia.core.types import PlaybackStatus, TrackInfo
from edmedia.media.base import MediaController

logger = logging.getLogger(__name__)

DEFAULT_BRIDGE_HOST = "127.0.0.1"
DEFAULT_BRIDGE_PORT = 48231


class LoopbackBridgeClient(MediaController):
    """Client running inside Wine prefix to connect to host EDMedia bridge."""

    def __init__(self, host: str = DEFAULT_BRIDGE_HOST, port: int = DEFAULT_BRIDGE_PORT):
        self.base_url = f"http://{host}:{port}"

    def is_available(self) -> bool:
        try:
            req = Request(f"{self.base_url}/status", method="GET")
            with urlopen(req, timeout=0.5) as resp:
                return resp.status == 200
        except Exception:
            return False

    def get_current_track(self) -> Optional[TrackInfo]:
        try:
            req = Request(f"{self.base_url}/track", method="GET")
            with urlopen(req, timeout=0.5) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    status = PlaybackStatus(data.get("status", "Stopped"))
                    return TrackInfo(
                        title=data.get("title", ""),
                        artist=data.get("artist", ""),
                        album=data.get("album", ""),
                        duration_ms=data.get("duration_ms", 0),
                        status=status,
                    )
        except Exception:
            pass
        return None

    def _post(self, endpoint: str) -> bool:
        try:
            req = Request(f"{self.base_url}/{endpoint}", method="POST")
            with urlopen(req, timeout=0.5) as resp:
                return resp.status == 200
        except Exception as e:
            logger.error("Failed to post to bridge %s: %s", endpoint, e)
            return False

    def play_pause(self) -> bool:
        return self._post("play_pause")

    def next_track(self) -> bool:
        return self._post("next")

    def prev_track(self) -> bool:
        return self._post("prev")


class BridgeHandler(BaseHTTPRequestHandler):
    """HTTP request handler for host bridge server."""

    controller: MediaController = None  # Class-level controller injection

    def do_GET(self):
        if self.path == "/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
        elif self.path == "/track":
            track = self.controller.get_current_track() if self.controller else TrackInfo()
            if track is None:
                track = TrackInfo()
            data = {
                "title": track.title,
                "artist": track.artist,
                "album": track.album,
                "duration_ms": track.duration_ms,
                "status": track.status.value,
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        success = False
        if self.path == "/play_pause" and self.controller:
            success = self.controller.play_pause()
        elif self.path == "/next" and self.controller:
            success = self.controller.next_track()
        elif self.path == "/prev" and self.controller:
            success = self.controller.prev_track()

        code = 200 if success else 400
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"success": true}' if success else b'{"success": false}')

    def log_message(self, format, *args):
        # Suppress noisy HTTP request logging
        pass


class LoopbackBridgeServer:
    """HTTP bridge server running on the Linux host to serve Wine guests."""

    def __init__(
        self,
        media_controller: MediaController,
        host: str = DEFAULT_BRIDGE_HOST,
        port: int = DEFAULT_BRIDGE_PORT,
    ):
        self.media_controller = media_controller
        self.host = host
        self.port = port
        self.server: Optional[HTTPServer] = None
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        BridgeHandler.controller = self.media_controller
        self.server = HTTPServer((self.host, self.port), BridgeHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True, name="EDMediaBridge")
        self.thread.start()
        logger.info("Host bridge listening on http://%s:%d", self.host, self.port)

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        logger.info("Host bridge stopped")
