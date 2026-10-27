"""Windows System Media Transport Controls (SMTC) Media Controller.

Interacts with native Windows media players (Spotify, Chrome, Edge, Media Player)
via Windows Runtime (WinRT) APIs and Win32 media keys fallback.
"""

from __future__ import annotations

import asyncio
import ctypes
import logging
from typing import Optional

from edmedia.core.types import PlaybackStatus, TrackInfo
from edmedia.media.base import MediaController

logger = logging.getLogger(__name__)

# Try WinRT imports
try:
    from winsdk.windows.media.control import (
        GlobalSystemMediaTransportControlsSessionManager as SMTCManager,
        GlobalSystemMediaTransportControlsSessionPlaybackStatus as WinRTPlaybackStatus,
    )
except ImportError:
    try:
        from winrt.windows.media.control import (
            GlobalSystemMediaTransportControlsSessionManager as SMTCManager,
            GlobalSystemMediaTransportControlsSessionPlaybackStatus as WinRTPlaybackStatus,
        )
    except ImportError:
        SMTCManager = None
        WinRTPlaybackStatus = None

# Win32 Virtual Keys
VK_MEDIA_NEXT_TRACK = 0xB0
VK_MEDIA_PREV_TRACK = 0xB1
VK_MEDIA_STOP = 0xB2
VK_MEDIA_PLAY_PAUSE = 0xB3
KEYEVENTF_EXTENDEDKEY = 0x0001
KEYEVENTF_KEYUP = 0x0002


class WindowsSMTCController(MediaController):
    """Controls Windows media players via SMTC WinRT API with Win32 media key fallback."""

    def __init__(self):
        self._manager = None
        self._loop = None

    def _get_loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is None or self._loop.is_closed():
            try:
                self._loop = asyncio.get_event_loop()
            except RuntimeError:
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
        return self._loop

    def is_available(self) -> bool:
        return ctypes.windll is not None if hasattr(ctypes, "windll") else False

    def _get_session_manager(self):
        if SMTCManager is None:
            return None
        if self._manager is None:
            try:
                loop = self._get_loop()
                self._manager = loop.run_until_complete(SMTCManager.request_async())
            except Exception as e:
                logger.debug("Failed to initialize Windows SMTC Manager: %s", e)
                self._manager = None
        return self._manager

    def get_current_track(self) -> Optional[TrackInfo]:
        manager = self._get_session_manager()
        if not manager:
            return None

        try:
            session = manager.get_current_session()
            if not session:
                return None

            loop = self._get_loop()
            media_props = loop.run_until_complete(session.try_get_media_properties_async())
            playback_info = session.get_playback_info()

            status = PlaybackStatus.STOPPED
            if playback_info:
                raw_st = playback_info.playback_status
                if WinRTPlaybackStatus and raw_st == WinRTPlaybackStatus.PLAYING:
                    status = PlaybackStatus.PLAYING
                elif WinRTPlaybackStatus and raw_st == WinRTPlaybackStatus.PAUSED:
                    status = PlaybackStatus.PAUSED

            title = media_props.title or "Unknown Title"
            artist = media_props.artist or "Unknown Artist"
            album = media_props.album_title or ""

            return TrackInfo(
                title=title,
                artist=artist,
                album=album,
                status=status,
            )
        except Exception as e:
            logger.debug("Error reading Windows SMTC track: %s", e)
            return None

    def _send_media_key(self, vk_code: int) -> bool:
        """Simulate Win32 media keyboard press via keybd_event."""
        if not hasattr(ctypes, "windll"):
            return False
        try:
            user32 = ctypes.windll.user32
            user32.keybd_event(vk_code, 0, KEYEVENTF_EXTENDEDKEY, 0)
            user32.keybd_event(vk_code, 0, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, 0)
            return True
        except Exception as e:
            logger.error("Failed to send Win32 media key %x: %s", vk_code, e)
            return False

    def play_pause(self) -> bool:
        manager = self._get_session_manager()
        if manager:
            try:
                session = manager.get_current_session()
                if session:
                    loop = self._get_loop()
                    loop.run_until_complete(session.try_toggle_play_pause_async())
                    return True
            except Exception:
                pass
        return self._send_media_key(VK_MEDIA_PLAY_PAUSE)

    def next_track(self) -> bool:
        manager = self._get_session_manager()
        if manager:
            try:
                session = manager.get_current_session()
                if session:
                    loop = self._get_loop()
                    loop.run_until_complete(session.try_skip_next_async())
                    return True
            except Exception:
                pass
        return self._send_media_key(VK_MEDIA_NEXT_TRACK)

    def prev_track(self) -> bool:
        manager = self._get_session_manager()
        if manager:
            try:
                session = manager.get_current_session()
                if session:
                    loop = self._get_loop()
                    loop.run_until_complete(session.try_skip_previous_async())
                    return True
            except Exception:
                pass
        return self._send_media_key(VK_MEDIA_PREV_TRACK)
