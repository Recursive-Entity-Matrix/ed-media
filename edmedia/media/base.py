"""Base interface for desktop media player integrations."""

from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from typing import Optional

from edmedia.core.types import TrackInfo


class MediaController(ABC):
    """Abstract interface for querying and controlling desktop media players."""

    @abstractmethod
    def get_current_track(self) -> Optional[TrackInfo]:
        """Fetch currently playing track information."""
        ...

    @abstractmethod
    def play_pause(self) -> bool:
        """Toggle play/pause on the active player."""
        ...

    @abstractmethod
    def next_track(self) -> bool:
        """Skip to next track."""
        ...

    @abstractmethod
    def prev_track(self) -> bool:
        """Skip to previous track."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if media provider is supported and accessible."""
        ...

    @property
    def player_name(self) -> str:
        """Name of the media provider or active player."""
        return self.__class__.__name__


def get_default_media_controller() -> MediaController:
    """Instantiate appropriate media controller based on current platform."""
    if sys.platform == "win32":
        from edmedia.media.smtc_windows import WindowsSMTCController
        controller = WindowsSMTCController()
        if controller.is_available():
            return controller
        # If running inside Proton or SMTC fails, check loopback bridge
        from edmedia.media.bridge import LoopbackBridgeClient
        bridge = LoopbackBridgeClient()
        if bridge.is_available():
            return bridge
        return controller

    # Linux native
    from edmedia.media.mpris_linux import LinuxMPRISController
    return LinuxMPRISController()
