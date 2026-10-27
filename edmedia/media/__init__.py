"""Media controller integrations for Linux MPRIS, Windows SMTC, and Proton bridge."""

from edmedia.media.base import MediaController, get_default_media_controller
from edmedia.media.mpris_linux import LinuxMPRISController
from edmedia.media.smtc_windows import WindowsSMTCController
from edmedia.media.bridge import LoopbackBridgeClient, LoopbackBridgeServer

__all__ = [
    "MediaController",
    "get_default_media_controller",
    "LinuxMPRISController",
    "WindowsSMTCController",
    "LoopbackBridgeClient",
    "LoopbackBridgeServer",
]
