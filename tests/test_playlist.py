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

    def test_pe_binary_protection(self):
        """Verify that any write attempting to touch PE binary space is strictly blocked."""
        pe_text_addr = 0x1400039F0
        pe_rdata_addr = 0x145337328

        # 1. Direct SafeMemoryIO write protection
        self.assertFalse(self.io.is_safe_write_addr(pe_text_addr, 8))
        self.assertFalse(self.io.is_safe_write_addr(pe_rdata_addr, 40))
        self.assertFalse(self.io.write_u64(pe_text_addr, 0x12345678))
        self.assertFalse(self.io.write_bytes(pe_text_addr, b"Code Blue Cam\x00"))

        # 2. RefcountedString write protection
        s = RefcountedString(self.io, pe_text_addr)
        self.assertFalse(s.write_text("Corrupting Binary"))

    def test_resolve_audio_player_from_ui_component(self):
        """Verify that UI component delegate is safely resolved to true AudioPlayer."""
        ui_delegate_addr = 0x5000
        handle_addr = 0x6000
        mgr_addr = 0x7000
        audio_player_addr = 0x8000
        p10_addr = 0x9000
        p18_addr = 0xA000
        p30_addr = 0xB000

        # UI delegate vtable: 0x145336F10 (Play/Pause)
        self.io.write_u64(ui_delegate_addr, 0x145336F10)

        # Handle pointer at ui_delegate + 0x528
        self.io.write_u64(ui_delegate_addr + 0x528, handle_addr)

        # Handle structure: +0xC8 is mgr pointer
        self.io.write_u64(handle_addr + 0xC8, mgr_addr)

        # Manager structure: rcx_mgr = mgr - 0x30
        rcx_mgr = mgr_addr - 0x30
        self.io.write_u64(rcx_mgr + 0x10, p10_addr)
        self.io.write_u64(rcx_mgr + 0x18, p18_addr)

        # p10 structure: +0x30 is p30_addr
        self.io.write_u64(p10_addr + 0x30, p30_addr)

        # Lookup table at p30: token 0x409 * 2 = 0x812
        token = 0x409
        slot_idx = 5
        self.io.write_u64(p30_addr + (token * 2) * 8, slot_idx)

        # Object table at p18: slot 5 is audio_player_addr
        self.io.write_u64(p18_addr + (slot_idx * 8), audio_player_addr)

        # AudioPlayer vtable at 0x8000 is 0x1455799C8
        self.io.write_u64(audio_player_addr, 0x1455799C8)

        # Initialize manager with mock memory
        mgr = PlaylistManager(self.mem, expected_vtable_va=0x145579990)

        # Attempt to set controller with the UI delegate
        mgr.set_controller(ui_delegate_addr)

        # Manager MUST have resolved the controller to audio_player_addr (0x8000), NOT 0x5000!
        self.assertEqual(mgr.controller_address, audio_player_addr)

        # Cached pointer at ui_delegate + 0x538 must be filled with audio_player_addr
        self.assertEqual(self.io.read_u64(ui_delegate_addr + 0x538), audio_player_addr)


if __name__ == "__main__":
    unittest.main()
