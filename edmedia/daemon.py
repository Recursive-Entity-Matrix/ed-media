"""Main EDMedia daemon orchestrating game attachment, polling, and cockpit hooks."""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from edmedia.core.playlist import PlaylistManager
from edmedia.core.poller import MediaPoller
from edmedia.core.reanchor import ReAnchorEngine
from edmedia.core.types import ButtonKind, TrackInfo
from edmedia.debug import get_platform_tracer
from edmedia.media import get_default_media_controller

logger = logging.getLogger("edmedia")


def find_elite_pid() -> Optional[int]:
    """Find process ID of running EliteDangerous64.exe."""
    try:
        import psutil
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            name = proc.info.get("name") or ""
            if "EliteDangerous64.exe" in name:
                return proc.info["pid"]
    except ImportError:
        # Fallback for Linux /proc scan
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                try:
                    cmdline_path = f"/proc/{entry}/cmdline"
                    with open(cmdline_path, "rb") as f:
                        cmdline = f.read().decode("latin-1", errors="ignore")
                        if "EliteDangerous64.exe" in cmdline:
                            return int(entry)
                except Exception:
                    continue
    return None


class EDMediaDaemon:
    """Core daemon managing the bridge between Elite Dangerous and desktop media."""

    def __init__(self, exe_path: Optional[str | Path] = None, poll_interval: float = 1.0):
        self.explicit_exe_path = exe_path
        self.poll_interval = poll_interval
        self.stop_event = threading.Event()
        self.media_controller = get_default_media_controller()

    def handle_button_press(self, button: ButtonKind, controller_addr: int, thread_id: int) -> None:
        """Invoked when the player presses a media button in the cockpit."""
        logger.info("Handling cockpit button: %s from thread %d", button.name, thread_id)

        # Store the active AudioPlayer controller pointer for single-entry clamping
        if hasattr(self, "playlist_mgr") and controller_addr:
            self.playlist_mgr.set_controller(controller_addr)

        if button == ButtonKind.PLAY_PAUSE:
            self.media_controller.play_pause()
        elif button == ButtonKind.NEXT:
            self.media_controller.next_track()
        elif button == ButtonKind.PREVIOUS:
            self.media_controller.prev_track()

        # Update in-game memory immediately with currently playing track
        if hasattr(self, "poller") and self.poller.current_track:
            self.playlist_mgr.update_first_item(self.poller.current_track)

    def handle_track_changed(self, track: TrackInfo) -> None:
        """Invoked when desktop media changes tracks."""
        logger.info("Applying track to cockpit UI: %s", track.display_line)
        if hasattr(self, "playlist_mgr"):
            self.playlist_mgr.update_first_item(track)
        if hasattr(self, "tracer"):
            self.tracer.request_ui_refresh()

    def run_session(self, pid: int) -> None:
        """Run an attached session against the running game process."""
        logger.info("Found Elite Dangerous process (PID: %d)", pid)

        # 1. Analyze and re-anchor target binary
        engine = ReAnchorEngine(self.explicit_exe_path)
        report = engine.analyze()
        logger.info("PE Re-Anchor Confidence: %.1f%%", report.confidence * 100)

        # 2. Initialize Tracer
        self.tracer = get_platform_tracer(pid, report)
        self.tracer.on_button_pressed = self.handle_button_press

        # 3. Initialize Playlist Manager with process memory accessor
        class TracerMemoryAccessor:
            def __init__(self, tracer):
                self.tracer = tracer
            def read_bytes(self, address: int, size: int) -> bytes:
                return self.tracer.read_bytes(address, size)
            def write_bytes(self, address: int, data: bytes) -> bool:
                return self.tracer.write_bytes(address, data)

        self.playlist_mgr = PlaylistManager(TracerMemoryAccessor(self.tracer))

        # 4. Attach and arm hardware breakpoints
        if not self.tracer.attach():
            logger.error("Failed to attach tracer to PID %d", pid)
            return

        self.tracer.setup_default_hooks()

        # 5. Start Media Poller
        self.poller = MediaPoller(
            self.media_controller,
            on_track_changed=self.handle_track_changed,
            poll_interval=self.poll_interval,
        )
        self.poller.start()

        # Perform initial sync
        initial_track = self.media_controller.get_current_track()
        if initial_track:
            self.handle_track_changed(initial_track)

        # 6. Run event loop until stop_event or process termination
        try:
            self.tracer.run_event_loop(self.stop_event)
        finally:
            logger.info("Cleaning up session for PID %d...", pid)
            self.poller.stop()
            self.tracer.detach()

    def start(self, once: bool = False) -> None:
        """Main lifecycle loop with auto-attachment."""
        logger.info("EDMedia Daemon starting (Media Provider: %s)", self.media_controller.player_name)

        def sig_handler(signum, frame):
            logger.info("Received signal %d, stopping daemon...", signum)
            self.stop_event.set()

        signal.signal(signal.SIGINT, sig_handler)
        signal.signal(signal.SIGTERM, sig_handler)

        while not self.stop_event.is_set():
            pid = find_elite_pid()
            if pid:
                try:
                    self.run_session(pid)
                except Exception as e:
                    logger.exception("Error during session: %s", e)
                if once:
                    break
            else:
                logger.debug("Waiting for EliteDangerous64.exe to launch...")
                time.sleep(2.0)

        logger.info("EDMedia Daemon shutdown complete.")
