"""Tests for Dynamic PE Re-Anchor and Signature Engine."""

import os
import unittest
from pathlib import Path

from edmedia.core.reanchor import ReAnchorEngine, COMMON_STEAM_PATHS


class TestReAnchor(unittest.TestCase):
    def setUp(self):
        self.game_exe = None
        for path in COMMON_STEAM_PATHS:
            if path.is_file():
                self.game_exe = path
                break

    def test_reanchor_local_binary(self):
        """Validate dynamic signature scanning against local EliteDangerous64.exe."""
        if not self.game_exe:
            self.skipTest("EliteDangerous64.exe not found on test system")

        engine = ReAnchorEngine(self.game_exe)
        report = engine.analyze()

        # 1. 100% confidence requirement
        self.assertEqual(report.confidence, 1.0, f"Expected 100% confidence, got {report.confidence * 100}%")

        # 2. Preferred Image Base check
        self.assertEqual(report.image_base, 0x140000000)

        # 3. Handlers verification
        self.assertIn("AudioPlayerOnPlayPauseToggle", report.handlers)
        self.assertEqual(report.handlers["AudioPlayerOnPlayPauseToggle"].va, 0x1444f9380)

        self.assertIn("AudioPlayerOnPrevious", report.handlers)
        self.assertEqual(report.handlers["AudioPlayerOnPrevious"].va, 0x1444f93d0)

        self.assertIn("AudioPlayerOnNext", report.handlers)
        self.assertEqual(report.handlers["AudioPlayerOnNext"].va, 0x1444f9330)

        self.assertIn("AudioPlayerOnClearPlaylist", report.handlers)
        self.assertEqual(report.handlers["AudioPlayerOnClearPlaylist"].va, 0x1444f92e0)

        # 4. Refresh Driver & Vtable verification
        self.assertIsNotNone(report.refresh_driver)
        self.assertEqual(report.refresh_driver.va, 0x1441afc70)

        self.assertIsNotNone(report.refresh_vtable)
        self.assertEqual(report.refresh_vtable.va, 0x145579990)


if __name__ == "__main__":
    unittest.main()
