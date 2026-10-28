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
    """Find process ID of running EliteDangerous64.exe across native and Proton/Wine."""
    try:
        import psutil
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                name = proc.info.get("name") or ""
                cmdline = proc.info.get("cmdline") or []

                # Exclude WatchDog and Launcher wrappers
                if "WatchDog" in name or (cmdline and any("WatchDog" in str(arg) for arg in cmdline)):
                    continue
                if "EDLaunch" in name:
                    continue

                # 1. Direct name match (including Linux 15-char comm truncation 'EliteDangerous6')
                if name.startswith("EliteDangerous"):
                    return proc.pid

                # 2. Command-line match under Wine/Proton (e.g. S:\...\EliteDangerous64.exe)
                if cmdline and any(str(arg).lower().endswith("elitedangerous64.exe") for arg in cmdline):
                    return proc.pid
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except ImportError:
        pass

    # Fallback for Linux /proc scan without psutil
    try:
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                try:
                    cmdline_path = f"/proc/{entry}/cmdline"
                    with open(cmdline_path, "rb") as f:
                        raw = f.read()
                        if b"WatchDog" in raw:
                            continue
                        if b"EliteDangerous64.exe" in raw:
                            return int(entry)
                except Exception:
                    continue
    except Exception:
        pass

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
            try:
                self.playlist_mgr.update_first_item(self.poller.current_track)
            except Exception as e:
                logger.error("Could not update playlist item on button press: %s", e)

    def handle_track_changed(self, track: TrackInfo) -> None:
        """Invoked when desktop media changes tracks."""
        logger.info("Applying track to cockpit UI: %s", track.display_line)
        if hasattr(self, "playlist_mgr"):
            try:
                if not self.playlist_mgr.controller_address and hasattr(self, "report"):
                    if self.report.refresh_vtable and self.report.refresh_vtable.va > 0:
                        vtable_va = self.tracer.to_runtime_va(self.report.refresh_vtable.rva)
                        self.playlist_mgr.find_active_controller(vtable_va)

                if self.playlist_mgr.controller_address:
                    self.playlist_mgr.update_first_item(track)
            except Exception as e:
                logger.error("Could not update playlist item on track change: %s", e)
        if hasattr(self, "tracer"):
            self.tracer.request_ui_refresh()

    def handle_periodic_sync(self, track: TrackInfo) -> None:
        """Periodically ensures the in-game playlist is clamped and displaying desktop media."""
        if hasattr(self, "playlist_mgr"):
            try:
                if not self.playlist_mgr.controller_address and hasattr(self, "report"):
                    if self.report.refresh_vtable and self.report.refresh_vtable.va > 0:
                        vtable_va = self.tracer.to_runtime_va(self.report.refresh_vtable.rva)
                        self.playlist_mgr.find_active_controller(vtable_va)

                if self.playlist_mgr.controller_address:
                    self.playlist_mgr.update_first_item(track)
            except Exception:
                pass

    def run_session(self, pid: int) -> None:
        """Run an attached session against the running game process."""
        logger.info("Found Elite Dangerous process (PID: %d)", pid)

        # 1. Analyze and re-anchor target binary
        engine = ReAnchorEngine(self.explicit_exe_path)
        report = engine.analyze()
        self.report = report
        logger.info("PE Re-Anchor Confidence: %.1f%%", report.confidence * 100)

        # 2. Initialize Tracer and configure hooks
        self.tracer = get_platform_tracer(pid, report)
        self.tracer.on_button_pressed = self.handle_button_press
        self.tracer.setup_default_hooks()

        # 3. Initialize Playlist Manager with process memory accessor
        class TracerMemoryAccessor:
            def __init__(self, tracer):
                self.tracer = tracer
            def read_bytes(self, address: int, size: int) -> bytes:
                return self.tracer.read_bytes(address, size)
            def write_bytes(self, address: int, data: bytes) -> bool:
                return self.tracer.write_bytes(address, data)

        expected_vt = self.tracer.to_runtime_va(report.refresh_vtable.rva) if report.refresh_vtable else None
        self.playlist_mgr = PlaylistManager(
            TracerMemoryAccessor(self.tracer),
            image_base=report.image_base,
            image_size=0x6500000,
            expected_vtable_va=expected_vt,
        )

        # 4. Attach and arm hardware breakpoints across all threads
        if not self.tracer.attach():
            logger.error("Failed to attach tracer to PID %d", pid)
            return

        thread_count = len(getattr(self.tracer, "_attached_threads", []))
        logger.info("Successfully attached to PID %d (%d threads armed with DR0-DR2)", pid, thread_count)

        # 4b. Auto-discover AudioPlayer controller in heap memory if already instantiated
        if report.refresh_vtable and report.refresh_vtable.va > 0:
            runtime_vtable = self.tracer.to_runtime_va(report.refresh_vtable.rva)
            self.playlist_mgr.find_active_controller(runtime_vtable)

        # 5. Start Media Poller with change detection and periodic background sync
        self.poller = MediaPoller(
            self.media_controller,
            on_track_changed=self.handle_track_changed,
            on_periodic_sync=self.handle_periodic_sync,
            poll_interval=self.poll_interval,
        )
        self.poller.start()

        # Perform initial sync with currently active track
        initial_track = self.media_controller.get_current_track()
        if initial_track:
            logger.info("Active track synced: %s [%s]", initial_track.display_line, initial_track.status.value)
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

        waiting_logged = False
        while not self.stop_event.is_set():
            pid = find_elite_pid()
            if pid:
                waiting_logged = False
                try:
                    self.run_session(pid)
                except Exception as e:
                    logger.exception("Error during session: %s", e)
                if once:
                    break
            else:
                if not waiting_logged:
                    logger.info("Waiting for EliteDangerous64.exe to launch...")
                    waiting_logged = True
                time.sleep(2.0)

        logger.info("EDMedia Daemon shutdown complete.")
