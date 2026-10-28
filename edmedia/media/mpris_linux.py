"""Linux MPRIS2 D-Bus Media Controller.

Interacts with standard Linux media players (Spotify, Firefox, Zen, Chrome, mpv, VLC)
over the D-Bus session bus.
"""

from __future__ import annotations

import logging
import subprocess
from typing import List, Optional

from edmedia.core.types import PlaybackStatus, TrackInfo
from edmedia.media.base import MediaController

logger = logging.getLogger(__name__)

try:
    import dbus
except ImportError:
    dbus = None


class LinuxMPRISController(MediaController):
    """Controls Linux desktop media players via MPRIS D-Bus interface."""

    MPRIS_PREFIX = "org.mpris.MediaPlayer2."
    PLAYER_IFACE = "org.mpris.MediaPlayer2.Player"
    PROPS_IFACE = "org.freedesktop.DBus.Properties"

    def __init__(self):
        self._bus: Optional[dbus.SessionBus] = None
        self._active_service: Optional[str] = None

    def _get_bus(self) -> Optional[dbus.SessionBus]:
        if dbus is None:
            return None
        if self._bus is None:
            try:
                self._bus = dbus.SessionBus()
            except Exception as e:
                logger.warning("Failed to connect to D-Bus Session Bus: %s", e)
                self._bus = None
        return self._bus

    def is_available(self) -> bool:
        return self._get_bus() is not None or self._check_playerctl_available()

    def _check_playerctl_available(self) -> bool:
        try:
            res = subprocess.run(["which", "playerctl"], capture_output=True, text=True)
            return res.returncode == 0
        except Exception:
            return False

    def list_players(self) -> List[str]:
        """List all active MPRIS media players on the session bus."""
        bus = self._get_bus()
        if not bus:
            return []
        try:
            names = bus.list_names()
            return [str(n) for n in names if str(n).startswith(self.MPRIS_PREFIX)]
        except Exception as e:
            logger.error("Failed to list D-Bus service names: %s", e)
            return []

    def get_best_player(self) -> Optional[str]:
        """Find the most relevant active media player (preferring Playing > Paused)."""
        players = self.list_players()
        if not players:
            return None

        bus = self._get_bus()
        if not bus:
            return players[0]

        playing_player = None
        paused_player = None

        for player_name in players:
            try:
                obj = bus.get_object(player_name, "/org/mpris/MediaPlayer2")
                props = dbus.Interface(obj, self.PROPS_IFACE)
                status = str(props.Get(self.PLAYER_IFACE, "PlaybackStatus"))
                if status == "Playing":
                    playing_player = player_name
                    break
                elif status == "Paused" and not paused_player:
                    paused_player = player_name
            except Exception:
                continue

        chosen = playing_player or paused_player or players[0]
        self._active_service = chosen
        return chosen

    def get_current_track(self) -> Optional[TrackInfo]:
        """Retrieve current metadata and status from active MPRIS player."""
        player_name = self.get_best_player()
        if not player_name:
            return None

        bus = self._get_bus()
        if not bus:
            return None

        try:
            obj = bus.get_object(player_name, "/org/mpris/MediaPlayer2")
            props = dbus.Interface(obj, self.PROPS_IFACE)

            raw_status = str(props.Get(self.PLAYER_IFACE, "PlaybackStatus"))
            status = PlaybackStatus.STOPPED
            if raw_status == "Playing":
                status = PlaybackStatus.PLAYING
            elif raw_status == "Paused":
                status = PlaybackStatus.PAUSED

            metadata = props.Get(self.PLAYER_IFACE, "Metadata")
            title = str(metadata.get("xesam:title", "Unknown Title"))

            # Artist can be an array of strings or a single string
            raw_artist = metadata.get("xesam:artist", "")
            if isinstance(raw_artist, (list, dbus.Array)):
                artist = ", ".join(str(a) for a in raw_artist)
            else:
                artist = str(raw_artist)

            album = str(metadata.get("xesam:album", ""))

            # Length is in microseconds
            length_us = int(metadata.get("mpris:length", 0))
            duration_ms = length_us // 1000

            track_id = str(metadata.get("mpris:trackid", ""))

            return TrackInfo(
                title=title or "Unknown Title",
                artist=artist or "Unknown Artist",
                album=album,
                duration_ms=duration_ms,
                status=status,
                track_id=track_id,
            )
        except Exception as e:
            logger.debug("Error reading MPRIS metadata: %s", e)
            return None

    def _call_player_method(self, method_name: str) -> bool:
        player_name = self.get_best_player()
        if not player_name:
            return False

        bus = self._get_bus()
        if not bus:
            return False

        try:
            obj = bus.get_object(player_name, "/org/mpris/MediaPlayer2")
            player = dbus.Interface(obj, self.PLAYER_IFACE)
            getattr(player, method_name)()
            logger.info("Sent %s to %s", method_name, player_name)
            return True
        except Exception as e:
            err_msg = str(e)
            if "not available now" in err_msg or "ActionNotSupported" in err_msg or "UnknownMethod" in err_msg:
                logger.info("%s is not available on player %s (single track/end of queue)", method_name, player_name)
            else:
                logger.warning("Failed to send %s to %s: %s", method_name, player_name, e)
            return False

    def play_pause(self) -> bool:
        return self._call_player_method("PlayPause")

    def next_track(self) -> bool:
        return self._call_player_method("Next")

    def prev_track(self) -> bool:
        return self._call_player_method("Previous")
