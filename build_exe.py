"""PyInstaller executable build script for EDMedia."""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path


def build():
    root = Path(__file__).resolve().parent
    entry_point = root / "edmedia" / "cli.py"

    output_name = "edmedia"
    if platform.system() == "Windows":
        output_name = "edmedia.exe"

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--name",
        output_name,
        "--onefile",
        "--clean",
        "--add-data",
        f"{root / 'pyproject.toml'}{os.pathsep}.",
        "--hidden-import",
        "edmedia",
        "--hidden-import",
        "edmedia.core",
        "--hidden-import",
        "edmedia.core.types",
        "--hidden-import",
        "edmedia.core.reanchor",
        "--hidden-import",
        "edmedia.core.playlist",
        "--hidden-import",
        "edmedia.core.poller",
        "--hidden-import",
        "edmedia.debug",
        "--hidden-import",
        "edmedia.debug.base",
        "--hidden-import",
        "edmedia.debug.linux_ptrace",
        "--hidden-import",
        "edmedia.debug.win32_debug",
        "--hidden-import",
        "edmedia.media",
        "--hidden-import",
        "edmedia.media.base",
        "--hidden-import",
        "edmedia.media.mpris_linux",
        "--hidden-import",
        "edmedia.media.smtc_windows",
        "--hidden-import",
        "edmedia.media.bridge",
        "--hidden-import",
        "edmedia.daemon",
        "--hidden-import",
        "edmedia.cli",
        "--hidden-import",
        "pefile",
        "--hidden-import",
        "psutil",
        str(entry_point),
    ]

    print("Building EDMedia executable...")
    print("Command:", " ".join(cmd))

    try:
        subprocess.run(cmd, check=True)
        dist_bin = root / "dist" / output_name
        print(f"\nSuccessfully built binary: {dist_bin}")
    except subprocess.CalledProcessError as e:
        print(f"\nBuild failed: {e}", file=sys.stderr)
        sys.exit(e.returncode)
    except FileNotFoundError:
        print("\nPyInstaller not found in environment. Install with: pip install pyinstaller", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    build()
