"""Debugger and Hardware Breakpoint implementations."""

import sys
from edmedia.debug.base import BaseTracer
from edmedia.core.types import AnchorReport


def get_platform_tracer(pid: int, anchor_report: AnchorReport) -> BaseTracer:
    """Instantiate platform-specific hardware breakpoint tracer."""
    if sys.platform == "win32":
        from edmedia.debug.win32_debug import Win32DebugTracer
        return Win32DebugTracer(pid, anchor_report)
    else:
        from edmedia.debug.linux_ptrace import LinuxPtraceTracer
        return LinuxPtraceTracer(pid, anchor_report)


__all__ = [
    "BaseTracer",
    "get_platform_tracer",
]
