"""Unified Command Line Interface for EDMedia."""

from __future__ import annotations

import argparse
import logging
import sys

from edmedia.core.reanchor import ReAnchorEngine
from edmedia.daemon import EDMediaDaemon
from edmedia.media import get_default_media_controller, LoopbackBridgeServer


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def cmd_run(args: argparse.Namespace) -> None:
    setup_logging(args.verbose)
    daemon = EDMediaDaemon(exe_path=args.exe, poll_interval=args.interval)
    daemon.start(once=args.once)


def cmd_reanchor(args: argparse.Namespace) -> None:
    try:
        engine = ReAnchorEngine(args.exe)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Analyzing binary: {engine.exe_path}")
    report = engine.analyze()

    if args.json:
        import json
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


def cmd_media(args: argparse.Namespace) -> None:
    setup_logging(args.verbose)
    ctrl = get_default_media_controller()
    print(f"Using Media Controller: {ctrl.player_name}")

    action = args.action or "status"
    if action == "status":
        track = ctrl.get_current_track()
        if track:
            print(f"Status:   {track.status.value}")
            print(f"Title:    {track.title}")
            print(f"Artist:   {track.artist}")
            print(f"Album:    {track.album}")
            print(f"Duration: {track.duration_ms // 1000}s")
            print(f"Display:  {track.display_line}")
        else:
            print("No active media player or track detected.")
    elif action == "play-pause":
        ok = ctrl.play_pause()
        print(f"Play/Pause toggled: {'Success' if ok else 'Failed'}")
    elif action == "next":
        ok = ctrl.next_track()
        print(f"Next track: {'Success' if ok else 'Failed'}")
    elif action == "prev":
        ok = ctrl.prev_track()
        print(f"Previous track: {'Success' if ok else 'Failed'}")


def cmd_bridge(args: argparse.Namespace) -> None:
    setup_logging(args.verbose)
    ctrl = get_default_media_controller()
    server = LoopbackBridgeServer(ctrl, host=args.host, port=args.port)
    server.start()
    print(f"Loopback bridge running on http://{args.host}:{args.port}")
    print("Press Ctrl+C to exit.")
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="edmedia",
        description="EDMedia: Complete Functional Replacement for Elite Dangerous GalNet Media Player",
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # Run
    p_run = subparsers.add_parser("run", help="Run background daemon with auto-attach")
    p_run.add_argument("--exe", default=None, help="Path to EliteDangerous64.exe")
    p_run.add_argument("--interval", type=float, default=1.0, help="Poll interval in seconds")
    p_run.add_argument("--once", action="store_true", help="Exit after first session ends")
    p_run.add_argument("-v", "--verbose", action="store_true", help="Verbose debug logging")

    # Re-Anchor
    p_reanchor = subparsers.add_parser("reanchor", help="Verify PE signature resolution")
    p_reanchor.add_argument("exe", nargs="?", default=None, help="Path to EliteDangerous64.exe")
    p_reanchor.add_argument("--json", action="store_true", help="Output JSON format")

    # Media
    p_media = subparsers.add_parser("media", help="Test media player control")
    p_media.add_argument("action", nargs="?", choices=["status", "play-pause", "next", "prev"], default="status")
    p_media.add_argument("-v", "--verbose", action="store_true", help="Verbose debug logging")

    # Bridge
    p_bridge = subparsers.add_parser("bridge", help="Run Proton/Wine loopback bridge server")
    p_bridge.add_argument("--host", default="127.0.0.1", help="Host address")
    p_bridge.add_argument("--port", type=int, default=48231, help="Port number")
    p_bridge.add_argument("-v", "--verbose", action="store_true", help="Verbose debug logging")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "run":
        cmd_run(args)
    elif args.command == "reanchor":
        cmd_reanchor(args)
    elif args.command == "media":
        cmd_media(args)
    elif args.command == "bridge":
        cmd_bridge(args)


if __name__ == "__main__":
    main()
