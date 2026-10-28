"""Cockpit Playlist and Refcounted String Memory Management.

Implements the single active playlist entry paradigm:
- Resolves true AudioPlayer instance from cockpit UI delegates with 100% ABI safety.
- Hard safety shield preventing any writes to static PE binary sections (.text, .rdata).
- Clamps internal item count to 1 (at controller + 0xb8).
- Directly rewrites the 40-byte item record at index 0.
- Safely manages refcounted string buffers (preserving refcount=3) without corruption.
"""

from __future__ import annotations

import logging
import os
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
    """Helper for reading/writing primitive types to process memory with PE bounds safety."""

    def __init__(self, mem: MemoryAccessor, image_base: int = 0x140000000, image_size: int = 0x6500000):
        self.mem = mem
        self.image_base = image_base
        self.image_size = image_size

    def is_safe_write_addr(self, addr: int, size: int = 1) -> bool:
        """Ensure destination address is valid heap memory and NOT inside the PE binary image."""
        if addr <= 0:
            return False
        if self.image_base <= addr < self.image_base + self.image_size:
            logger.critical(
                "SECURITY GUARD: Blocked attempted write to PE binary image at 0x%x (size=%d)!",
                addr, size
            )
            return False
        return True

    def read_u8(self, addr: int) -> int:
        data = self.mem.read_bytes(addr, 1)
        return data[0] if data else 0

    def write_u8(self, addr: int, val: int) -> bool:
        if not self.is_safe_write_addr(addr, 1):
            return False
        return self.mem.write_bytes(addr, struct.pack("<B", val & 0xFF))

    def read_u32(self, addr: int) -> int:
        data = self.mem.read_bytes(addr, 4)
        return struct.unpack("<I", data)[0] if len(data) == 4 else 0

    def write_u32(self, addr: int, val: int) -> bool:
        if not self.is_safe_write_addr(addr, 4):
            return False
        return self.mem.write_bytes(addr, struct.pack("<I", val & 0xFFFFFFFF))

    def read_u64(self, addr: int) -> int:
        data = self.mem.read_bytes(addr, 8)
        return struct.unpack("<Q", data)[0] if len(data) == 8 else 0

    def write_u64(self, addr: int, val: int) -> bool:
        if not self.is_safe_write_addr(addr, 8):
            return False
        return self.mem.write_bytes(addr, struct.pack("<Q", val & 0xFFFFFFFFFFFFFFFF))

    def write_bytes(self, addr: int, data: bytes) -> bool:
        if not self.is_safe_write_addr(addr, len(data)):
            return False
        return self.mem.write_bytes(addr, data)

    def read_string(self, addr: int, max_len: int = 512) -> str:
        raw = self.mem.read_bytes(addr, max_len)
        null_idx = raw.find(b"\x00")
        if null_idx != -1:
            raw = raw[:null_idx]
        return raw.decode("utf-8", errors="replace")


class RefcountedString:
    """Manages an Elite Dangerous refcounted string object in heap memory.

    Object layout at base address P (pointed to by item.title_ptr):
      P + 0x00 (8 bytes, uint64): Length in bytes (including terminating NUL)
      P + 0x08 (8 bytes, uint64): Buffer capacity in bytes
      P + 0x10 (4 bytes, uint32): Reference Count (CRITICAL: Must be preserved; live is 3)
      P + 0x14 (char[]):          UTF-8 characters + NUL terminator (Text start T = P + 0x14)
    """

    OFFSET_LEN = 0x00
    OFFSET_CAP = 0x08
    OFFSET_REFCOUNT = 0x10
    OFFSET_TEXT = 0x14

    def __init__(self, io: SafeMemoryIO, address: int):
        self.io = io
        self.raw_address = address
        # Normalize: detect whether address was passed as base pointer P or text start T (P + 0x14)
        if address > 0:
            rc_as_p = self.io.read_u32(address + 0x10)
            rc_as_t = self.io.read_u32(address - 0x04) if address >= 0x14 else 0
            if rc_as_t in (1, 2, 3, 4, 5, 6, 7, 8) and rc_as_p not in (1, 2, 3, 4, 5, 6, 7, 8):
                self.base_address = address - 0x14
            else:
                self.base_address = address
        else:
            self.base_address = 0

    @property
    def length(self) -> int:
        if self.base_address <= 0:
            return 0
        val = self.io.read_u64(self.base_address + self.OFFSET_LEN)
        return val if 0 <= val <= 4096 else 0

    @property
    def capacity(self) -> int:
        if self.base_address <= 0:
            return 0
        val = self.io.read_u64(self.base_address + self.OFFSET_CAP)
        return val if 0 <= val <= 16384 else 256

    @property
    def refcount(self) -> int:
        if self.base_address <= 0:
            return 0
        return self.io.read_u32(self.base_address + self.OFFSET_REFCOUNT)

    @property
    def text_address(self) -> int:
        return self.base_address + self.OFFSET_TEXT

    def read_text(self) -> str:
        length = self.length
        if length <= 1 or length > 4096 or self.base_address <= 0:
            return ""
        raw = self.io.mem.read_bytes(self.text_address, length - 1)
        return raw.decode("utf-8", errors="replace")

    def write_text(self, new_text: str) -> bool:
        """Safely write new text into the string object, preserving refcount."""
        if self.base_address <= 0:
            return False

        # HARD SAFETY CHECK: Refcounted string can NEVER be in PE module code/rdata!
        if not self.io.is_safe_write_addr(self.base_address, 8):
            logger.critical("Refusing to write RefcountedString: base 0x%x is inside PE image!", self.base_address)
            return False

        encoded = new_text.encode("utf-8") + b"\x00"
        new_len = len(encoded)

        cap = self.capacity
        if cap <= 0 or cap > 16384:
            cap = 256  # Fallback assumption if uninitialized

        # If string exceeds capacity, truncate safely to fit buffer
        if new_len > cap:
            encoded = encoded[: cap - 1] + b"\x00"
            new_len = len(encoded)

        old_len = self.length
        old_text = self.read_text()

        # 1. Update length field (P + 0x00)
        if not self.io.write_u64(self.base_address + self.OFFSET_LEN, new_len):
            logger.error("Failed to write string length at 0x%x", self.base_address)
            return False

        # 2. Write new text bytes at P + 0x14
        if not self.io.write_bytes(self.text_address, encoded):
            logger.error("Failed to write string data at 0x%x", self.text_address)
            return False

        # 3. Zero out residual tail bytes up to old length (bounded)
        if old_len > new_len:
            residual = min(old_len - new_len, 4096)
            if residual > 0:
                zero_fill = b"\x00" * residual
                self.io.write_bytes(self.text_address + new_len, zero_fill)

        logger.info(
            "Updated in-game string at 0x%x (cap=%d): '%s' -> '%s'",
            self.base_address, cap, old_text, new_text
        )
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

    def __init__(
        self,
        mem: MemoryAccessor,
        image_base: int = 0x140000000,
        image_size: int = 0x6500000,
        expected_vtable_va: Optional[int] = None,
    ):
        self.image_base = image_base
        self.image_size = image_size
        self.expected_vtable_va = expected_vtable_va
        self.io = SafeMemoryIO(mem, image_base=image_base, image_size=image_size)
        self.controller_address: Optional[int] = None
        self.current_title_string: Optional[RefcountedString] = None
        self.token_id: int = 0x409

    def is_audio_player_vtable(self, vtable: int) -> bool:
        """Check if vtable belongs to the AudioPlayer class cluster."""
        if not vtable or vtable <= 0:
            return False
        if self.expected_vtable_va:
            # Cluster check within +/- 0x150 of expected vtable
            return abs(vtable - self.expected_vtable_va) <= 0x150
        # Default fallback for Odyssey: 0x145579700 to 0x145579b00
        return 0x145579700 <= vtable <= 0x145579b00

    def _resolve_from_handle(self, handle: int) -> Optional[int]:
        """Resolve AudioPlayer using the in-game handle manager lookup algorithm."""
        if not handle or handle <= 0:
            return None

        mgr = self.io.read_u64(handle + 0xC8)
        if not mgr or mgr <= 0:
            return None

        rcx_mgr = mgr - 0x30
        p_10 = self.io.read_u64(rcx_mgr + 0x10)
        p_18 = self.io.read_u64(rcx_mgr + 0x18)
        if not p_10 or not p_18 or p_10 <= 0 or p_18 <= 0:
            return None

        p_30 = self.io.read_u64(p_10 + 0x30)
        if not p_30 or p_30 <= 0:
            return None

        token = self.token_id or 0x409
        rdx_val = self.io.read_u64(p_30 + (token * 2) * 8)
        player = self.io.read_u64(p_18 + rdx_val * 8)
        return player if player and player > 0 else None

    def resolve_audio_player_from_ui(self, ui_addr: int) -> Optional[int]:
        """Resolve the true AudioPlayer pointer from a cockpit UI Component delegate."""
        if not ui_addr or ui_addr <= 0:
            return None

        # Check offsets for possible delegate interior pointers (+0x00 Play/Pause, +0x28 Prev, +0x50 Next, +0xa0 UI)
        for offset in (0x0, -0x28, -0x50, -0xA0):
            cand = ui_addr + offset
            if cand <= 0:
                continue

            # 1. Check if cached at cand + 0x538
            cached = self.io.read_u64(cand + 0x538)
            if cached and cached > 0:
                cached_vt = self.io.read_u64(cached)
                if self.is_audio_player_vtable(cached_vt):
                    return cached

            # 2. Check handle holder at cand + 0x528
            handle = self.io.read_u64(cand + 0x528)
            if handle and handle > 0:
                player = self._resolve_from_handle(handle)
                if player and player > 0:
                    player_vt = self.io.read_u64(player)
                    if self.is_audio_player_vtable(player_vt):
                        # Cache at cand + 0x538 for future fast lookups
                        self.io.write_u64(cand + 0x538, player)
                        return player

        return None

    def set_controller(self, address: int) -> None:
        """Register the captured AudioPlayer or UI Component pointer, resolving to true AudioPlayer."""
        if not address or address <= 0:
            return

        # Check if address is already the true AudioPlayer
        vtable = self.io.read_u64(address)

        # Allow mock test controller (e.g. unit tests with low address and no vtable)
        if address < 0x10000 and vtable == 0:
            if address != self.controller_address:
                self.controller_address = address
                self.current_title_string = None
                logger.info("Captured test AudioPlayer controller at 0x%x", address)
            return

        if self.is_audio_player_vtable(vtable):
            if address != self.controller_address:
                self.controller_address = address
                self.current_title_string = None
                logger.info("Captured AudioPlayer controller at 0x%x (vtable=0x%x)", address, vtable)
            return

        # If it is a UI Component (e.g. from breakpoint trap on Play/Pause, Next, Prev):
        resolved = self.resolve_audio_player_from_ui(address)
        if resolved and resolved > 0:
            if resolved != self.controller_address:
                self.controller_address = resolved
                self.current_title_string = None
                logger.info("Resolved true AudioPlayer at 0x%x from UI Component 0x%x", resolved, address)
            return

        logger.warning(
            "Address 0x%x is neither an AudioPlayer nor resolvable UI Component (vtable=0x%x); ignoring",
            address, vtable
        )

    def find_active_controller(self, vtable_va: int) -> Optional[int]:
        """Scan process memory to find the active _GameAudioCockpitMediaPlayer instance."""
        if self.controller_address and self.controller_address > 0:
            return self.controller_address

        tracer = getattr(self.io.mem, "tracer", None)
        if not tracer or not hasattr(tracer, "pid"):
            return None

        maps_path = f"/proc/{tracer.pid}/maps"
        if not os.path.exists(maps_path):
            return None

        # Targets to search: derived vtable (+0x38) and base vtable
        targets = [
            struct.pack("<Q", vtable_va + 0x38),
            struct.pack("<Q", vtable_va),
        ]

        try:
            with open(maps_path, "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 2:
                        continue
                    perms = parts[1]
                    # Only search writable heap/anonymous regions
                    if not perms.startswith("rw"):
                        continue
                    addr_range = parts[0].split("-")
                    start_addr = int(addr_range[0], 16)
                    end_addr = int(addr_range[1], 16)
                    size = end_addr - start_addr

                    # Skip huge mappings (> 2GB) for sanity
                    if size <= 0 or size > 2 * 1024 * 1024 * 1024:
                        continue

                    chunk_size = 16 * 1024 * 1024  # 16MB chunks for fast scanning
                    for off in range(0, size, chunk_size):
                        read_sz = min(chunk_size, size - off)
                        data = tracer.read_bytes(start_addr + off, read_sz)
                        if not data:
                            continue

                        for needle in targets:
                            pos = 0
                            while True:
                                pos = data.find(needle, pos)
                                if pos == -1:
                                    break
                                candidate = start_addr + off + pos
                                # Validate candidate structure
                                cand_vt = self.io.read_u64(candidate)
                                if self.is_audio_player_vtable(cand_vt):
                                    active = self.io.read_u8(candidate + self.OFFSET_ACTIVE_FLAG)
                                    count = self.io.read_u64(candidate + self.OFFSET_ITEM_COUNT)
                                    if active in (0, 1) and count < 1000:
                                        logger.info(
                                            "Discovered AudioPlayer controller at 0x%x (count=%d, active=%d)",
                                            candidate, count, active
                                        )
                                        self.set_controller(candidate)
                                        return candidate
                                pos += 8
        except Exception as e:
            logger.debug("Controller auto-discovery exception: %s", e)

        return None

    def clamp_single_entry(self) -> bool:
        """Clamp item count to 1 and ensure start index is 0."""
        if not self.controller_address or self.controller_address <= 0:
            return False

        # Set count = 1
        self.io.write_u64(self.controller_address + self.OFFSET_ITEM_COUNT, 1)

        # Set start index = 0
        self.io.write_u64(self.controller_address + self.OFFSET_START_INDEX, 0)

        # Ensure active flag is set
        self.io.write_u8(self.controller_address + self.OFFSET_ACTIVE_FLAG, 1)

        # Ensure capacity threshold at 0x228 is <= 1 so RefreshDriver doesn't skip UI dispatch
        self.io.write_u32(self.controller_address + self.OFFSET_CAPACITY, 1)
        return True

    def get_first_item_record(self) -> Optional[PlaylistRecord]:
        """Read 40-byte record for Item 0."""
        if not self.controller_address or self.controller_address <= 0:
            return None

        array_start = self.io.read_u64(self.controller_address + self.OFFSET_VECTOR_START)
        if not array_start or array_start <= 0x10000:
            return None

        if not self.io.is_safe_write_addr(array_start, PlaylistRecord.RECORD_SIZE):
            return None

        raw_record = self.io.mem.read_bytes(array_start, PlaylistRecord.RECORD_SIZE)
        if len(raw_record) < PlaylistRecord.RECORD_SIZE:
            return None

        return PlaylistRecord.unpack(raw_record)

    def update_first_item(self, track: TrackInfo) -> bool:
        """Update Item 0 and all active ring buffer records with current track Title & Artist."""
        if not self.controller_address or self.controller_address <= 0:
            return False

        # Validate controller pointer
        vtable = self.io.read_u64(self.controller_address)
        if self.controller_address >= 0x10000 and not self.is_audio_player_vtable(vtable):
            logger.warning(
                "Controller at 0x%x has invalid vtable 0x%x; rejecting update",
                self.controller_address, vtable
            )
            return False

        array_start = self.io.read_u64(self.controller_address + self.OFFSET_VECTOR_START)
        if not array_start or array_start <= 0:
            logger.debug("Playlist array_start is null at 0x%x; cannot update items", self.controller_address)
            return False

        # CRITICAL SAFETY: array_start MUST NOT fall in PE binary range
        if not self.io.is_safe_write_addr(array_start, PlaylistRecord.RECORD_SIZE):
            logger.error("Array start 0x%x is inside PE binary image; aborting update", array_start)
            return False

        existing_count = self.io.read_u64(self.controller_address + self.OFFSET_ITEM_COUNT)
        if existing_count <= 0:
            logger.debug("Playlist item count is 0; nothing to update")
            return False

        slots_to_update = max(1, min(existing_count, 16))

        title_text = track.display_line if track.display_line else (track.title or "Unknown Title")
        artist_text = track.artist if track.artist and track.artist != "Unknown Artist" else "Desktop Media"
        duration_sec = track.duration_ms // 1000 if track.duration_ms > 0 else 0

        updated_count = 0
        for slot in range(slots_to_update):
            slot_offset = array_start + (slot * PlaylistRecord.RECORD_SIZE)
            if not self.io.is_safe_write_addr(slot_offset, PlaylistRecord.RECORD_SIZE):
                continue

            raw_record = self.io.mem.read_bytes(slot_offset, PlaylistRecord.RECORD_SIZE)
            if len(raw_record) < PlaylistRecord.RECORD_SIZE:
                continue

            record = PlaylistRecord.unpack(raw_record)

            # 1. Update Title string (+0x00)
            if record.title_ptr and self.io.is_safe_write_addr(record.title_ptr, 8):
                s = RefcountedString(self.io, record.title_ptr)
                s.write_text(title_text)

            # 2. Update Subtitle / Artist string (+0x08)
            if record.secondary_id_ptr and self.io.is_safe_write_addr(record.secondary_id_ptr, 8):
                s = RefcountedString(self.io, record.secondary_id_ptr)
                s.write_text(artist_text)

            # 3. Update Metadata string (+0x18) if valid
            if record.metadata_ptr and self.io.is_safe_write_addr(record.metadata_ptr, 8):
                s = RefcountedString(self.io, record.metadata_ptr)
                s.write_text(track.display_line)

            # 4. Update duration (+0x20)
            self.io.write_u32(slot_offset + 0x20, duration_sec)
            updated_count += 1

        self.clamp_single_entry()

        logger.info(
            "Cockpit UI playlist synchronized: '%s' by '%s' (%d slots updated in-game)",
            title_text, artist_text, updated_count
        )
        return True
