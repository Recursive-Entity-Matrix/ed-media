"""Cockpit Playlist and Refcounted String Memory Management.

Implements the single active playlist entry paradigm:
- Clamps internal item count to 1 (at controller + 0xb8).
- Directly rewrites the 40-byte item record at index 0.
- Safely manages refcounted string buffers (preserving refcount=3) without corruption.
"""

from __future__ import annotations

import logging
import struct
from typing import Optional, Protocol

from edmedia.core.types import PlaylistRecord, TrackInfo

logger = logging.getLogger(__name__)


class MemoryAccessor(Protocol):
    """Protocol for reading and writing process virtual memory."""
    def read_bytes(self, address: int, size: int) -> bytes:
        ...

    def write_bytes(self, address: int, data: bytes) -> bool:
        ...


class SafeMemoryIO:
    """Helper for reading/writing primitive types to process memory."""

    def __init__(self, mem: MemoryAccessor):
        self.mem = mem

    def read_u8(self, addr: int) -> int:
        data = self.mem.read_bytes(addr, 1)
        return data[0] if data else 0

    def write_u8(self, addr: int, val: int) -> bool:
        return self.mem.write_bytes(addr, struct.pack("<B", val & 0xFF))

    def read_u32(self, addr: int) -> int:
        data = self.mem.read_bytes(addr, 4)
        return struct.unpack("<I", data)[0] if len(data) == 4 else 0

    def write_u32(self, addr: int, val: int) -> bool:
        return self.mem.write_bytes(addr, struct.pack("<I", val & 0xFFFFFFFF))

    def read_u64(self, addr: int) -> int:
        data = self.mem.read_bytes(addr, 8)
        return struct.unpack("<Q", data)[0] if len(data) == 8 else 0

    def write_u64(self, addr: int, val: int) -> bool:
        return self.mem.write_bytes(addr, struct.pack("<Q", val & 0xFFFFFFFFFFFFFFFF))

    def read_string(self, addr: int, max_len: int = 512) -> str:
        raw = self.mem.read_bytes(addr, max_len)
        null_idx = raw.find(b"\x00")
        if null_idx != -1:
            raw = raw[:null_idx]
        return raw.decode("utf-8", errors="replace")


class RefcountedString:
    """Manages an Elite Dangerous refcounted string object in heap memory.

    Layout relative to text start pointer T:
      T - 0x14 (8 bytes, uint64): Length in bytes (including terminating NUL)
      T - 0x0C (8 bytes, uint64): Buffer capacity in bytes
      T - 0x04 (4 bytes, uint32): Reference Count (CRITICAL: Must be preserved; live is 3)
      T        (char[]):          UTF-8 characters + NUL terminator
    """

    LEN_OFFSET = -0x14
    CAP_OFFSET = -0x0C
    REFCOUNT_OFFSET = -0x04

    def __init__(self, io: SafeMemoryIO, text_address: int):
        self.io = io
        self.text_address = text_address

    @property
    def length(self) -> int:
        return self.io.read_u64(self.text_address + self.LEN_OFFSET)

    @property
    def capacity(self) -> int:
        return self.io.read_u64(self.text_address + self.CAP_OFFSET)

    @property
    def refcount(self) -> int:
        return self.io.read_u32(self.text_address + self.REFCOUNT_OFFSET)

    def read_text(self) -> str:
        length = self.length
        if length <= 1 or length > 4096:
            return ""
        raw = self.io.mem.read_bytes(self.text_address, length - 1)
        return raw.decode("utf-8", errors="replace")

    def write_text(self, new_text: str) -> bool:
        """Safely write new text into the string object, preserving refcount."""
        encoded = new_text.encode("utf-8") + b"\x00"
        new_len = len(encoded)

        cap = self.capacity
        if cap == 0:
            cap = 256  # Fallback assumption if uninitialized

        # If string exceeds capacity, truncate safely to fit buffer
        if new_len > cap:
            encoded = encoded[: cap - 1] + b"\x00"
            new_len = len(encoded)

        old_len = self.length

        # 1. Update length field (T - 0x14)
        if not self.io.write_u64(self.text_address + self.LEN_OFFSET, new_len):
            logger.error("Failed to write string length")
            return False

        # 2. Write new text bytes at T
        if not self.io.mem.write_bytes(self.text_address, encoded):
            logger.error("Failed to write string data")
            return False

        # 3. Zero out residual tail bytes up to old length
        if old_len > new_len:
            residual = old_len - new_len
            zero_fill = b"\x00" * residual
            self.io.mem.write_bytes(self.text_address + new_len, zero_fill)

        return True


class PlaylistManager:
    """Controls the cockpit AudioPlayer playlist object and single-entry state."""

    # Offsets inside the AudioPlayer / Playlist controller object (RCX / RDI)
    OFFSET_VECTOR_START = 0xA0   # uint64 pointer to item array
    OFFSET_VECTOR_END = 0xA8     # uint64 pointer to item array end
    OFFSET_START_INDEX = 0xB0    # uint64 start index
    OFFSET_ITEM_COUNT = 0xB8     # uint64 item count
    OFFSET_CAPACITY = 0x228      # uint32 max items capacity
    OFFSET_ACTIVE_FLAG = 0x22C   # uint8 active flag

    def __init__(self, mem: MemoryAccessor):
        self.io = SafeMemoryIO(mem)
        self.controller_address: Optional[int] = None
        self.current_title_string: Optional[RefcountedString] = None

    def set_controller(self, address: int) -> None:
        """Register the captured AudioPlayer controller pointer."""
        if address != self.controller_address:
            self.controller_address = address
            self.current_title_string = None
            logger.info("Captured AudioPlayer controller at 0x%x", address)

    def clamp_single_entry(self) -> bool:
        """Clamp item count to 1 and ensure start index is 0."""
        if not self.controller_address:
            return False

        # Set count = 1
        self.io.write_u64(self.controller_address + self.OFFSET_ITEM_COUNT, 1)

        # Set start index = 0
        self.io.write_u64(self.controller_address + self.OFFSET_START_INDEX, 0)

        # Ensure active flag is set
        self.io.write_u8(self.controller_address + self.OFFSET_ACTIVE_FLAG, 1)
        return True

    def get_first_item_record(self) -> Optional[PlaylistRecord]:
        """Read 40-byte record for Item 0."""
        if not self.controller_address:
            return None

        array_start = self.io.read_u64(self.controller_address + self.OFFSET_VECTOR_START)
        if not array_start:
            return None

        raw_record = self.io.mem.read_bytes(array_start, PlaylistRecord.RECORD_SIZE)
        if len(raw_record) < PlaylistRecord.RECORD_SIZE:
            return None

        return PlaylistRecord.unpack(raw_record)

    def update_first_item(self, track: TrackInfo) -> bool:
        """Update Item 0 with track Title, Artist, and duration."""
        if not self.controller_address:
            return False

        self.clamp_single_entry()

        array_start = self.io.read_u64(self.controller_address + self.OFFSET_VECTOR_START)
        if not array_start:
            return False

        record = self.get_first_item_record()
        if not record:
            return False

        # If title string pointer is valid, update the refcounted string
        if record.title_ptr:
            if not self.current_title_string or self.current_title_string.text_address != record.title_ptr:
                self.current_title_string = RefcountedString(self.io, record.title_ptr)

            display_text = track.display_line
            self.current_title_string.write_text(display_text)

        # Update duration
        duration_sec = track.duration_ms // 1000 if track.duration_ms > 0 else 0
        self.io.write_u32(array_start + 0x20, duration_sec)
        return True
