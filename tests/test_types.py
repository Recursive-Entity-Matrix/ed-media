"""Unit tests for EDMedia core types and data structures."""

import struct
import unittest

from edmedia.core.types import (
    ButtonKind,
    PlaybackStatus,
    PlaylistRecord,
    TrackInfo,
)


class TestTypes(unittest.TestCase):
    def test_button_kind_slots(self):
        self.assertEqual(ButtonKind.PLAY_PAUSE.value, 0x140)
        self.assertEqual(ButtonKind.PREVIOUS.value, 0x148)
        self.assertEqual(ButtonKind.NEXT.value, 0x150)
        self.assertEqual(ButtonKind.CLEAR.value, 0x168)

    def test_track_info_display_and_equality(self):
        t1 = TrackInfo(title="Starlight", artist="Muse", status=PlaybackStatus.PLAYING)
        self.assertEqual(t1.display_line, "Starlight - Muse")

        t2 = TrackInfo(title="Starlight", artist="Muse", status=PlaybackStatus.PLAYING)
        self.assertFalse(t1.has_changed_from(t2))

        t3 = TrackInfo(title="Starlight", artist="Muse", status=PlaybackStatus.PAUSED)
        self.assertTrue(t1.has_changed_from(t3))

        t4 = TrackInfo(title="Supermassive Black Hole", artist="Muse", status=PlaybackStatus.PLAYING)
        self.assertTrue(t1.has_changed_from(t4))

    def test_playlist_record_packing(self):
        record = PlaylistRecord(
            title_ptr=0x14789000,
            secondary_id_ptr=0x14789100,
            status_flags=b"\x01\x00\x00\x00",
            metadata_ptr=0x14789200,
            duration_sec=215,
            padding=0,
        )
        packed = record.pack()
        self.assertEqual(len(packed), 40)

        unpacked = PlaylistRecord.unpack(packed)
        self.assertEqual(unpacked.title_ptr, 0x14789000)
        self.assertEqual(unpacked.secondary_id_ptr, 0x14789100)
        self.assertEqual(unpacked.status_flags, b"\x01\x00\x00\x00")
        self.assertEqual(unpacked.metadata_ptr, 0x14789200)
        self.assertEqual(unpacked.duration_sec, 215)


if __name__ == "__main__":
    unittest.main()
