"""Core data models and type definitions for EDMedia."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional


class ButtonKind(Enum):
    """In-game cockpit audio player button interface slots."""
    PLAY_PAUSE = 0x140
    PREVIOUS = 0x148
    NEXT = 0x150
    CLEAR = 0x168
    REMOVE_ITEM = 0x48
    SKIP_TO_ITEM = 0x49  # Virtual distinction for second 0x48 slot


class PlaybackStatus(Enum):
    """Desktop media playback state."""
    STOPPED = "Stopped"
    PAUSED = "Paused"
    PLAYING = "Playing"


@dataclass
class TrackInfo:
    """Metadata representing currently playing desktop media."""
    title: str = "No Media Detected"
    artist: str = "EDMedia Ready"
    album: str = ""
    duration_ms: int = 0
    position_ms: int = 0
    status: PlaybackStatus = PlaybackStatus.STOPPED
    track_id: str = ""

    @property
    def display_line(self) -> str:
        """Formatted display line for cockpit GalNet media banner."""
        if self.artist and self.artist != "Unknown Artist":
            return f"{self.title} - {self.artist}"
        return self.title

    def has_changed_from(self, other: Optional[TrackInfo]) -> bool:
        """Check if track title, artist, or status changed."""
        if other is None:
            return True
        return (
            self.title != other.title
            or self.artist != other.artist
            or self.status != other.status
        )


@dataclass
class AnchorTarget:
    """A resolved function or data structure anchor within EliteDangerous64.exe."""
    name: str
    rva: int
    va: int
    slot: Optional[int] = None
    confidence: float = 1.0
    signature: bytes = b""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "rva": hex(self.rva),
            "va": hex(self.va),
            "slot": hex(self.slot) if self.slot is not None else None,
            "confidence": self.confidence,
        }


@dataclass
class AnchorReport:
    """Complete collection of recovered game hooks and vtables."""
    image_base: int = 0x140000000
    handlers: Dict[str, AnchorTarget] = field(default_factory=dict)
    refresh_driver: Optional[AnchorTarget] = None
    refresh_vtable: Optional[AnchorTarget] = None
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            "image_base": hex(self.image_base),
            "confidence": self.confidence,
            "handlers": {k: v.to_dict() for k, v in self.handlers.items()},
            "refresh_driver": self.refresh_driver.to_dict() if self.refresh_driver else None,
            "refresh_vtable": self.refresh_vtable.to_dict() if self.refresh_vtable else None,
        }


class BreakpointKind(Enum):
    """Hardware breakpoint role."""
    BUTTON_PLAY_PAUSE = "play_pause"
    BUTTON_PREV = "prev"
    BUTTON_NEXT = "next"
    BUTTON_CLEAR = "clear"
    UI_RENDER_LOOP = "ui_loop"


@dataclass
class Breakpoint:
    """Hardware execute breakpoint configuration."""
    dr_index: int  # 0, 1, 2, or 3
    address: int  # Runtime VA
    kind: BreakpointKind
    enabled: bool = True


@dataclass
class PlaylistRecord:
    """In-memory 40-byte (0x28) item record layout in Elite Dangerous cockpit list."""
    title_ptr: int = 0          # uint64 (+0x00) pointer to refcounted string
    secondary_id_ptr: int = 0   # uint64 (+0x08) pointer to audio/secondary ID string
    status_flags: bytes = b"\x01\x00\x00\x00"  # 4 bytes (+0x10) (01 = ready, 02 = playing)
    padding_14: bytes = b"\x00\x00\x00\x00"   # 4 bytes (+0x14) alignment padding
    metadata_ptr: int = 0       # uint64 (+0x18) pointer to metadata string
    duration_sec: int = 0       # uint32 (+0x20) duration in seconds
    padding: int = 0            # uint32 (+0x24) alignment padding

    RECORD_SIZE = 40
    RECORD_FORMAT = "<QQ4s4sQII"

    def pack(self) -> bytes:
        return struct.pack(
            self.RECORD_FORMAT,
            self.title_ptr,
            self.secondary_id_ptr,
            self.status_flags,
            self.padding_14,
            self.metadata_ptr,
            self.duration_sec,
            self.padding,
        )

    @classmethod
    def unpack(cls, data: bytes) -> PlaylistRecord:
        if len(data) < cls.RECORD_SIZE:
            raise ValueError(f"Data length {len(data)} is less than {cls.RECORD_SIZE}")
        fields = struct.unpack(cls.RECORD_FORMAT, data[: cls.RECORD_SIZE])
        return cls(
            title_ptr=fields[0],
            secondary_id_ptr=fields[1],
            status_flags=fields[2],
            padding_14=fields[3],
            metadata_ptr=fields[4],
            duration_sec=fields[5],
            padding=fields[6],
        )
