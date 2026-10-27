"""Dynamic PE Re-Anchor and Signature Engine.

Scans EliteDangerous64.exe binaries dynamically at startup to guarantee that
in-game hooks, refresh drivers, and vtables remain resilient against game patches.
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from edmedia.core.types import AnchorReport, AnchorTarget, ButtonKind

try:
    import pefile
except ImportError:
    pefile = None


COMMON_STEAM_PATHS = [
    Path("/games/steam/steamapps/common/Elite Dangerous/Products/elite-dangerous-odyssey-64/EliteDangerous64.exe"),
    Path.home() / ".local/share/Steam/steamapps/common/Elite Dangerous/Products/elite-dangerous-odyssey-64/EliteDangerous64.exe",
    Path.home() / ".steam/steam/steamapps/common/Elite Dangerous/Products/elite-dangerous-odyssey-64/EliteDangerous64.exe",
    Path("C:/Program Files (x86)/Steam/steamapps/common/Elite Dangerous/Products/elite-dangerous-odyssey-64/EliteDangerous64.exe"),
    Path("D:/SteamLibrary/steamapps/common/Elite Dangerous/Products/elite-dangerous-odyssey-64/EliteDangerous64.exe"),
]


class ReAnchorEngine:
    """Dynamic signature scanner and RVA resolver for Elite Dangerous PE binaries."""

    # Standard thunk prologue: push rbx; sub rsp, 0x20; mov rax, [rcx]; mov rbx, rdx; call [rax + slot]
    THUNK_PROLOGUE = b"\x40\x53\x48\x83\xec\x20\x48\x8b\x01\x48\x8b\xda\xff\x90"

    # Refresh driver unique byte sequence (including cmp byte ptr [rcx + 0x22c], 0; mov rbx, rdx; mov rdi, rcx)
    REFRESH_DRIVER_SIG = (
        b"\x40\x55\x53\x57\x48\x8d\x6c\x24\xb9\x48\x81\xec\x00\x01\x00\x00"
        b"\x80\xb9\x2c\x02\x00\x00\x00\x48\x8b\xda\x48\x8b\xf9"
    )

    REFRESH_VTABLE_SLOT_OFFSET = 0xA0  # Slot 20 * 8 bytes = 0xa0

    def __init__(self, exe_path: Optional[str | Path] = None):
        self.exe_path = self.resolve_exe_path(exe_path)
        self.image_base = 0x140000000
        self._sections: List[Tuple[str, int, int, int]] = []  # name, rva, size, raw_offset
        self._raw_data: Optional[bytes] = None

    @classmethod
    def resolve_exe_path(cls, explicit_path: Optional[str | Path] = None) -> Path:
        """Find the active EliteDangerous64.exe binary."""
        if explicit_path:
            p = Path(explicit_path)
            if p.is_file():
                return p.resolve()
            raise FileNotFoundError(f"Specified Elite binary does not exist: {explicit_path}")

        # Check known common paths
        for path in COMMON_STEAM_PATHS:
            if path.is_file():
                return path.resolve()

        # Check running processes if psutil is available
        try:
            import psutil
            for proc in psutil.process_iter(["name", "exe"]):
                if proc.info["name"] and "EliteDangerous64.exe" in proc.info["name"]:
                    if proc.info["exe"] and os.path.isfile(proc.info["exe"]):
                        return Path(proc.info["exe"]).resolve()
        except Exception:
            pass

        raise FileNotFoundError(
            "Could not automatically locate EliteDangerous64.exe. "
            "Please specify the path with --exe."
        )

    def load_binary(self) -> None:
        """Read binary and parse section headers."""
        if self._raw_data is not None:
            return

        with open(self.exe_path, "rb") as f:
            self._raw_data = f.read()

        if pefile is not None:
            pe = pefile.PE(data=self._raw_data, fast_load=True)
            self.image_base = pe.OPTIONAL_HEADER.ImageBase
            for sec in pe.sections:
                sec_name = sec.Name.decode("latin-1", errors="ignore").rstrip("\x00")
                self._sections.append((sec_name, sec.VirtualAddress, sec.Misc_VirtualSize, sec.PointerToRawData))
        else:
            # Fallback manual PE header parser
            self._parse_pe_manually(self._raw_data)

    def _parse_pe_manually(self, data: bytes) -> None:
        """Minimal fallback PE section parser when pefile is unavailable."""
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise ValueError("Not a valid PE executable (invalid DOS header)")
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            raise ValueError("Not a valid PE executable (invalid PE signature)")

        num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
        opt_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
        opt_offset = pe_offset + 24

        magic = struct.unpack_from("<H", data, opt_offset)[0]
        if magic == 0x20B:  # PE32+ (64-bit)
            self.image_base = struct.unpack_from("<Q", data, opt_offset + 24)[0]
        else:
            self.image_base = struct.unpack_from("<I", data, opt_offset + 28)[0]

        sec_table_offset = opt_offset + opt_header_size
        for i in range(num_sections):
            sec_offset = sec_table_offset + (i * 40)
            name = data[sec_offset : sec_offset + 8].decode("latin-1", errors="ignore").rstrip("\x00")
            virt_size = struct.unpack_from("<I", data, sec_offset + 8)[0]
            virt_addr = struct.unpack_from("<I", data, sec_offset + 12)[0]
            raw_offset = struct.unpack_from("<I", data, sec_offset + 20)[0]
            self._sections.append((name, virt_addr, virt_size, raw_offset))

    def offset_to_rva(self, file_offset: int) -> int:
        """Convert physical file offset to relative virtual address (RVA)."""
        for _, virt_addr, virt_size, raw_offset in self._sections:
            if raw_offset <= file_offset < raw_offset + virt_size:
                return virt_addr + (file_offset - raw_offset)
        # Fallback if unmapped
        return file_offset

    def rva_to_va(self, rva: int) -> int:
        """Convert RVA to static Virtual Address."""
        return self.image_base + rva

    def find_handler(self, slot_int: int) -> Optional[Tuple[int, int]]:
        """Find button handler thunk for the specified slot. Returns (RVA, VA) or None."""
        if self._raw_data is None:
            self.load_binary()

        needle = self.THUNK_PROLOGUE + struct.pack("<I", slot_int)
        pos = self._raw_data.find(needle)
        if pos != -1:
            rva = self.offset_to_rva(pos)
            va = self.rva_to_va(rva)
            return rva, va
        return None

    def find_refresh_driver(self) -> Optional[Tuple[int, int]]:
        """Find Refresh Driver function via byte signature. Returns (RVA, VA) or None."""
        if self._raw_data is None:
            self.load_binary()

        pos = self._raw_data.find(self.REFRESH_DRIVER_SIG)
        if pos != -1:
            rva = self.offset_to_rva(pos)
            va = self.rva_to_va(rva)
            return rva, va
        return None

    def find_refresh_vtable(self, refresh_driver_va: int) -> Optional[Tuple[int, int]]:
        """Find virtual method table containing Refresh Driver at slot 20 (+0xa0)."""
        if self._raw_data is None:
            self.load_binary()

        packed_target = struct.pack("<Q", refresh_driver_va)
        pos = self._raw_data.find(packed_target)
        if pos != -1:
            hit_rva = self.offset_to_rva(pos)
            hit_va = self.rva_to_va(hit_rva)
            vtable_va = hit_va - self.REFRESH_VTABLE_SLOT_OFFSET
            vtable_rva = hit_rva - self.REFRESH_VTABLE_SLOT_OFFSET
            return vtable_rva, vtable_va
        return None

    def analyze(self) -> AnchorReport:
        """Run complete re-anchoring analysis and produce AnchorReport."""
        self.load_binary()

        report = AnchorReport(image_base=self.image_base)
        button_slots = {
            "AudioPlayerOnPlayPauseToggle": ButtonKind.PLAY_PAUSE.value,
            "AudioPlayerOnPrevious": ButtonKind.PREVIOUS.value,
            "AudioPlayerOnNext": ButtonKind.NEXT.value,
            "AudioPlayerOnClearPlaylist": ButtonKind.CLEAR.value,
        }

        resolved_count = 0
        total_targets = len(button_slots) + 2  # buttons + refresh_driver + refresh_vtable

        for name, slot in button_slots.items():
            result = self.find_handler(slot)
            if result:
                rva, va = result
                report.handlers[name] = AnchorTarget(
                    name=name,
                    rva=rva,
                    va=va,
                    slot=slot,
                    confidence=1.0,
                )
                resolved_count += 1
            else:
                report.handlers[name] = AnchorTarget(
                    name=name,
                    rva=0,
                    va=0,
                    slot=slot,
                    confidence=0.0,
                )

        # Refresh Driver
        driver_res = self.find_refresh_driver()
        if driver_res:
            rva, va = driver_res
            report.refresh_driver = AnchorTarget(
                name="RefreshDriver",
                rva=rva,
                va=va,
                confidence=1.0,
            )
            resolved_count += 1

            # Refresh Vtable
            vtable_res = self.find_refresh_vtable(va)
            if vtable_res:
                vrva, vva = vtable_res
                report.refresh_vtable = AnchorTarget(
                    name="RefreshVtable",
                    rva=vrva,
                    va=vva,
                    slot=self.REFRESH_VTABLE_SLOT_OFFSET,
                    confidence=1.0,
                )
                resolved_count += 1

        report.confidence = resolved_count / total_targets
        return report


def main() -> None:
    """CLI tool for testing dynamic re-anchoring on local EliteDangerous64.exe."""
    parser = argparse.ArgumentParser(description="EDMedia Dynamic PE Re-Anchor Utility")
    parser.add_argument("exe_path", nargs="?", default=None, help="Path to EliteDangerous64.exe")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    args = parser.parse_args()

    try:
        engine = ReAnchorEngine(args.exe_path)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Analyzing binary: {engine.exe_path}")
    report = engine.analyze()

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return

    print("\n" + "=" * 78)
    print(f"EDMedia Dynamic Re-Anchor Report (ImageBase: {hex(report.image_base)})")
    print(f"Confidence: {report.confidence * 100:.1f}%")
    print("=" * 78)
    print(f"{'Target Name':<32} {'Slot':<10} {'RVA':<14} {'Static VA':<18} {'Status'}")
    print("-" * 78)

    for name, target in report.handlers.items():
        slot_str = hex(target.slot) if target.slot else "-"
        status = "OK (100%)" if target.confidence == 1.0 else "MISSING"
        print(f"{name:<32} {slot_str:<10} {hex(target.rva):<14} {hex(target.va):<18} {status}")

    if report.refresh_driver:
        rd = report.refresh_driver
        status = "OK (100%)" if rd.confidence == 1.0 else "MISSING"
        print(f"{rd.name:<32} {'-':<10} {hex(rd.rva):<14} {hex(rd.va):<18} {status}")

    if report.refresh_vtable:
        rv = report.refresh_vtable
        slot_str = f"+{hex(rv.slot)}" if rv.slot else "-"
        status = "OK (100%)" if rv.confidence == 1.0 else "MISSING"
        print(f"{rv.name:<32} {slot_str:<10} {hex(rv.rva):<14} {hex(rv.va):<18} {status}")

    print("=" * 78)


if __name__ == "__main__":
    main()
