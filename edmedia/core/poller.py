"""Media status polling and track change detector."""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Optional

from edmedia.core.types import TrackInfo
from edmedia.media.base import MediaController

logger = logging.getLogger(__name__)


class MediaPoller:
    """Polls the active media player at a fixed interval and triggers callbacks on change."""

    def __init__(
        self,
        media_controller: MediaController,
        on_track_changed: Optional[Callable[[TrackInfo], None]] = None,
        on_periodic_sync: Optional[Callable[[TrackInfo], None]] = None,
        poll_interval: float = 1.0,
    ):
        self.media_controller = media_controller
        self.on_track_changed = on_track_changed
        self.on_periodic_sync = on_periodic_sync
        self.poll_interval = poll_interval
        self._last_track: Optional[TrackInfo] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    @property
    def current_track(self) -> Optional[TrackInfo]:
        with self._lock:
            return self._last_track

    def poll_once(self) -> Optional[TrackInfo]:
        """Perform a single poll step, returning new track if changed."""
        try:
            track = self.media_controller.get_current_track()
        except Exception as e:
            logger.warning("Error querying media controller: %s", e)
            track = None

        if track is None:
            track = TrackInfo()

        with self._lock:
            changed = track.has_changed_from(self._last_track)
            if changed:
                logger.info("Track change detected: %s [%s]", track.display_line, track.status.value)
                self._last_track = track

        if changed and self.on_track_changed:
            try:
                self.on_track_changed(track)
            except Exception as e:
                logger.exception("Error executing track change callback: %s", e)
        elif not changed and self.on_periodic_sync and track:
            try:
                self.on_periodic_sync(track)
            except Exception as e:
                logger.debug("Error executing periodic sync callback: %s", e)

        return track if changed else None

    def start(self) -> None:
        """Start background polling thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._worker, daemon=True, name="EDMediaPoller")
        self._thread.start()
        logger.info("MediaPoller started (interval: %.1fs)", self.poll_interval)

    def stop(self) -> None:
        """Stop background polling thread."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        logger.info("MediaPoller stopped")

    def _worker(self) -> None:
        while self._running:
            self.poll_once()
            time.sleep(self.poll_interval)
