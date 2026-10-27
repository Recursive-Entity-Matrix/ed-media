"""Unit tests for PlaylistManager and RefcountedString memory manipulation."""

import struct
import unittest

from edmedia.core.playlist import (
    PlaylistManager,
    RefcountedString,
    SafeMemoryIO,
)
from edmedia.core.types import PlaylistRecord, TrackInfo


class MockMemory:
    """In-memory dictionary simulating virtual process memory."""

    def __init__(self):
        self.data = bytearray(0x10000)

    def read_bytes(self, address: int, size: int) -> bytes:
        if address < 0 or address + size > len(self.data):
            return b""
        return bytes(self.data[address : address + size])

    def write_bytes(self, address: int, data: bytes) -> bool:
        if address < 0 or address + len(data) > len(self.data):
            return False
        self.data[address : address + len(data)] = data
        return True


class TestPlaylist(unittest.TestCase):
    def setUp(self):
        self.mem = MockMemory()
        self.io = SafeMemoryIO(self.mem)

    def test_refcounted_string_safe_rewrite(self):
        # Setup string at text address 0x1000
        # Layout:
        # T - 0x14: length uint64
        # T - 0x0c: capacity uint64
        # T - 0x04: refcount uint32 (MUST BE PRESERVED AT 3)
        # T: UTF-8 characters + NUL
        text_addr = 0x1000
        initial_text = "GalNet News: Thargoid War Update"
        initial_bytes = initial_text.encode("utf-8") + b"\x00"

        self.io.write_u64(text_addr - 0x14, len(initial_bytes))
        self.io.write_u64(text_addr - 0x0C, 256)
        self.io.write_u32(text_addr - 0x04, 3)  # Live refcount = 3
        self.mem.write_bytes(text_addr, initial_bytes)

        rstring = RefcountedString(self.io, text_addr)
        self.assertEqual(rstring.length, len(initial_bytes))
        self.assertEqual(rstring.capacity, 256)
        self.assertEqual(rstring.refcount, 3)
        self.assertEqual(rstring.read_text(), initial_text)

        # Rewrite string with new desktop track title
        new_track = "Solar Fields - Sol"
        success = rstring.write_text(new_track)
        self.assertTrue(success)

        # Verify new text
        self.assertEqual(rstring.read_text(), new_track)
        # Verify length updated
        self.assertEqual(rstring.length, len(new_track.encode("utf-8")) + 1)
        # Verify refcount is STILL 3 (NOT CORRUPTED)
        self.assertEqual(rstring.refcount, 3)

    def test_playlist_manager_single_entry_clamp(self):
        controller_addr = 0x2000
        array_addr = 0x3000
        title_str_addr = 0x4000

        # Setup controller object with 7 items (GalNet news playlist)
        self.io.write_u64(controller_addr + 0xA0, array_addr)  # array start
        self.io.write_u64(controller_addr + 0xB0, 2)           # start index = 2
        self.io.write_u64(controller_addr + 0xB8, 7)           # item count = 7
        self.io.write_u8(controller_addr + 0x22C, 1)           # active flag

        # Setup Item 0 record at array_addr
        initial_record = PlaylistRecord(
            title_ptr=title_str_addr,
            secondary_id_ptr=0,
            status_flags=b"\x01\x00\x00\x00",
            metadata_ptr=0,
            duration_sec=180,
            padding=0,
        )
        self.mem.write_bytes(array_addr, initial_record.pack())

        # Setup title string object
        initial_bytes = b"Vanilla Article\x00"
        self.io.write_u64(title_str_addr - 0x14, len(initial_bytes))
        self.io.write_u64(title_str_addr - 0x0C, 256)
        self.io.write_u32(title_str_addr - 0x04, 3)
        self.mem.write_bytes(title_str_addr, initial_bytes)

        # Test PlaylistManager
        mgr = PlaylistManager(self.mem)
        mgr.set_controller(controller_addr)

        # Clamp single entry
        mgr.clamp_single_entry()

        # Item count must be clamped to 1
        self.assertEqual(self.io.read_u64(controller_addr + 0xB8), 1)
        # Start index must be reset to 0
        self.assertEqual(self.io.read_u64(controller_addr + 0xB0), 0)

        # Update Item 0 with new TrackInfo
        track = TrackInfo(title="Midnight City", artist="M83", duration_ms=243000)
        mgr.update_first_item(track)

        # Verify string updated
        updated_rstring = RefcountedString(self.io, title_str_addr)
        self.assertEqual(updated_rstring.read_text(), "Midnight City - M83")
        self.assertEqual(updated_rstring.refcount, 3)

        # Verify duration updated to seconds
        self.assertEqual(self.io.read_u32(array_addr + 0x20), 243)


if __name__ == "__main__":
    unittest.main()
