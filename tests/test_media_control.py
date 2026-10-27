"""Unit tests for MediaController integrations and change polling."""

import time
import unittest
from typing import Optional

from edmedia.core.poller import MediaPoller
from edmedia.core.types import PlaybackStatus, TrackInfo
from edmedia.media.base import MediaController
from edmedia.media.bridge import LoopbackBridgeClient, LoopbackBridgeServer


class MockMediaController(MediaController):
    def __init__(self):
        self.current = TrackInfo(title="Track 1", artist="Artist 1", status=PlaybackStatus.PLAYING)
        self.play_pause_calls = 0
        self.next_calls = 0
        self.prev_calls = 0

    def is_available(self) -> bool:
        return True

    def get_current_track(self) -> Optional[TrackInfo]:
        return self.current

    def play_pause(self) -> bool:
        self.play_pause_calls += 1
        return True

    def next_track(self) -> bool:
        self.next_calls += 1
        return True

    def prev_track(self) -> bool:
        self.prev_calls += 1
        return True


class TestMediaControl(unittest.TestCase):
    def test_poller_change_detection(self):
        ctrl = MockMediaController()
        changes = []

        poller = MediaPoller(ctrl, on_track_changed=lambda t: changes.append(t), poll_interval=0.05)

        # First poll should detect initial track
        poller.poll_once()
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].title, "Track 1")

        # Second poll with identical track should not trigger callback
        poller.poll_once()
        self.assertEqual(len(changes), 1)

        # Track change
        ctrl.current = TrackInfo(title="Track 2", artist="Artist 1", status=PlaybackStatus.PLAYING)
        poller.poll_once()
        self.assertEqual(len(changes), 2)
        self.assertEqual(changes[1].title, "Track 2")

    def test_loopback_bridge_roundtrip(self):
        ctrl = MockMediaController()
        # Use ephemeral high port for unit testing
        port = 49152 + (hash("test_port") % 1000)
        server = LoopbackBridgeServer(ctrl, host="127.0.0.1", port=port)
        server.start()

        time.sleep(0.1)

        client = LoopbackBridgeClient(host="127.0.0.1", port=port)
        try:
            self.assertTrue(client.is_available())

            # Test GET /track
            track = client.get_current_track()
            self.assertIsNotNone(track)
            self.assertEqual(track.title, "Track 1")
            self.assertEqual(track.artist, "Artist 1")
            self.assertEqual(track.status, PlaybackStatus.PLAYING)

            # Test POST /next
            ok = client.next_track()
            self.assertTrue(ok)
            self.assertEqual(ctrl.next_calls, 1)

            # Test POST /prev
            ok = client.prev_track()
            self.assertTrue(ok)
            self.assertEqual(ctrl.prev_calls, 1)

            # Test POST /play_pause
            ok = client.play_pause()
            self.assertTrue(ok)
            self.assertEqual(ctrl.play_pause_calls, 1)

        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
