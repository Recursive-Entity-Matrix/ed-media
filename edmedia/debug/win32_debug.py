"""Windows Hardware Breakpoint Engine (x86_64).

Uses Win32 Debug APIs (OpenProcess, SetThreadContext, DR0-DR3) to achieve
invisible hardware execution breakpoints without code patching.
"""

from __future__ import annotations

import ctypes
import logging
import struct
import time
from typing import Dict, List, Optional, Set

from edmedia.core.types import (
    AnchorReport,
    Breakpoint,
    BreakpointKind,
    ButtonKind,
)
from edmedia.debug.base import BaseTracer

logger = logging.getLogger(__name__)

# Win32 Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
THREAD_ALL_ACCESS = 0x1F03FF
TH32CS_SNAPTHREAD = 0x00000004
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
EXCEPTION_SINGLE_STEP = 0x80000004

CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = CONTEXT_AMD64 | 0x1
CONTEXT_INTEGER = CONTEXT_AMD64 | 0x2
CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x4
CONTEXT_FLOATS = CONTEXT_AMD64 | 0x8
CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x10
CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATS | CONTEXT_DEBUG_REGISTERS


class M128A(ctypes.Structure):
    _fields_ = [("Low", ctypes.c_ulonglong), ("High", ctypes.c_longlong)]


class CONTEXT64(ctypes.Structure):
    """Win32 x86_64 CONTEXT structure matching winnt.h."""
    _fields_ = [
        ("P1Home", ctypes.c_ulonglong),
        ("P2Home", ctypes.c_ulonglong),
        ("P3Home", ctypes.c_ulonglong),
        ("P4Home", ctypes.c_ulonglong),
        ("P5Home", ctypes.c_ulonglong),
        ("P6Home", ctypes.c_ulonglong),
        ("ContextFlags", ctypes.c_ulong),
        ("MxCsr", ctypes.c_ulong),
        ("SegCs", ctypes.c_ushort),
        ("SegDs", ctypes.c_ushort),
        ("SegEs", ctypes.c_ushort),
        ("SegFs", ctypes.c_ushort),
        ("SegGs", ctypes.c_ushort),
        ("SegSs", ctypes.c_ushort),
        ("EFlags", ctypes.c_ulong),
        ("Dr0", ctypes.c_ulonglong),
        ("Dr1", ctypes.c_ulonglong),
        ("Dr2", ctypes.c_ulonglong),
        ("Dr3", ctypes.c_ulonglong),
        ("Dr6", ctypes.c_ulonglong),
        ("Dr7", ctypes.c_ulonglong),
        ("Rax", ctypes.c_ulonglong),
        ("Rcx", ctypes.c_ulonglong),
        ("Rdx", ctypes.c_ulonglong),
        ("Rbx", ctypes.c_ulonglong),
        ("Rsp", ctypes.c_ulonglong),
        ("Rbp", ctypes.c_ulonglong),
        ("Rsi", ctypes.c_ulonglong),
        ("Rdi", ctypes.c_ulonglong),
        ("R8", ctypes.c_ulonglong),
        ("R9", ctypes.c_ulonglong),
        ("R10", ctypes.c_ulonglong),
        ("R11", ctypes.c_ulonglong),
        ("R12", ctypes.c_ulonglong),
        ("R13", ctypes.c_ulonglong),
        ("R14", ctypes.c_ulonglong),
        ("R15", ctypes.c_ulonglong),
        ("Rip", ctypes.c_ulonglong),
        ("Header", M128A * 2),
        ("Legacy", M128A * 8),
        ("Xmm0", M128A),
        ("Xmm1", M128A),
        ("Xmm2", M128A),
        ("Xmm3", M128A),
        ("Xmm4", M128A),
        ("Xmm5", M128A),
        ("Xmm6", M128A),
        ("Xmm7", M128A),
        ("Xmm8", M128A),
        ("Xmm9", M128A),
        ("Xmm10", M128A),
        ("Xmm11", M128A),
        ("Xmm12", M128A),
        ("Xmm13", M128A),
        ("Xmm14", M128A),
        ("Xmm15", M128A),
        ("VectorRegister", M128A * 26),
        ("VectorControl", ctypes.c_ulonglong),
        ("DebugControl", ctypes.c_ulonglong),
        ("LastBranchToRip", ctypes.c_ulonglong),
        ("LastBranchFromRip", ctypes.c_ulonglong),
        ("LastExceptionToRip", ctypes.c_ulonglong),
        ("LastExceptionFromRip", ctypes.c_ulonglong),
    ]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong),
        ("cntUsage", ctypes.c_ulong),
        ("th32ThreadID", ctypes.c_ulong),
        ("th32OwnerProcessID", ctypes.c_ulong),
        ("tpBasePri", ctypes.c_long),
        ("tpDeltaPri", ctypes.c_long),
        ("dwFlags", ctypes.c_ulong),
    ]


class Win32DebugTracer(BaseTracer):
    """Windows x86_64 Hardware Breakpoint Tracer using Win32 API."""

    def __init__(self, pid: int, anchor_report: AnchorReport):
        super().__init__(pid, anchor_report)
        self._h_process = None
        self._kernel32 = getattr(ctypes, "windll", None).kernel32 if hasattr(ctypes, "windll") else None

    def attach(self) -> bool:
        if not self._kernel32:
            return False

        self._h_process = self._kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        if not self._h_process:
            logger.error("Failed to OpenProcess on pid %d", self.pid)
            return False

        self.is_attached = True
        logger.info("Attached to Windows process %d", self.pid)
        return True

    def detach(self) -> None:
        self.is_attached = False
        if self._h_process and self._kernel32:
            self._kernel32.CloseHandle(self._h_process)
            self._h_process = None
        logger.info("Detached from Windows process %d", self.pid)

    def read_bytes(self, address: int, size: int) -> bytes:
        if not self._h_process or not self._kernel32:
            return b""
        buf = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        ok = self._kernel32.ReadProcessMemory(
            self._h_process,
            ctypes.c_void_p(address),
            buf,
            size,
            ctypes.byref(bytes_read),
        )
        return buf.raw[: bytes_read.value] if ok else b""

    def write_bytes(self, address: int, data: bytes) -> bool:
        if not self._h_process or not self._kernel32 or not data:
            return False
        bytes_written = ctypes.c_size_t(0)
        ok = self._kernel32.WriteProcessMemory(
            self._h_process,
            ctypes.c_void_p(address),
            data,
            len(data),
            ctypes.byref(bytes_written),
        )
        return bool(ok and bytes_written.value == len(data))

    def _get_process_thread_ids(self) -> List[int]:
        """Enumerate thread IDs belonging to the process."""
        if not self._kernel32:
            return []
        h_snap = self._kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        if h_snap == -1:
            return []

        tids = []
        te = THREADENTRY32()
        te.dwSize = ctypes.sizeof(THREADENTRY32)

        if self._kernel32.Thread32First(h_snap, ctypes.byref(te)):
            while True:
                if te.th32OwnerProcessID == self.pid:
                    tids.append(te.th32ThreadID)
                if not self._kernel32.Thread32Next(h_snap, ctypes.byref(te)):
                    break

        self._kernel32.CloseHandle(h_snap)
        return tids

    def _compute_dr7(self) -> int:
        val = 0x400  # Base bit 10
        for idx, bp in self.breakpoints.items():
            if bp.enabled:
                val |= (1 << (2 * idx)) | (1 << (2 * idx + 1))
        return val

    def _arm_thread(self, tid: int) -> bool:
        if not self._kernel32:
            return False
        h_thread = self._kernel32.OpenThread(THREAD_ALL_ACCESS, False, tid)
        if not h_thread:
            return False

        try:
            self._kernel32.SuspendThread(h_thread)
            ctx = CONTEXT64()
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
            if self._kernel32.GetThreadContext(h_thread, ctypes.byref(ctx)):
                for idx in range(4):
                    addr = self.breakpoints[idx].address if idx in self.breakpoints and self.breakpoints[idx].enabled else 0
                    setattr(ctx, f"Dr{idx}", addr)
                ctx.Dr7 = self._compute_dr7()
                self._kernel32.SetThreadContext(h_thread, ctypes.byref(ctx))
            self._kernel32.ResumeThread(h_thread)
            return True
        finally:
            self._kernel32.CloseHandle(h_thread)

    def arm_breakpoint(self, dr_index: int, address: int, kind: BreakpointKind) -> bool:
        if not (0 <= dr_index <= 3):
            raise ValueError(f"Invalid DR index: {dr_index}")

        self.breakpoints[dr_index] = Breakpoint(
            dr_index=dr_index,
            address=address,
            kind=kind,
            enabled=True,
        )

        for tid in self._get_process_thread_ids():
            self._arm_thread(tid)
        return True

    def disarm_breakpoint(self, dr_index: int) -> bool:
        if dr_index in self.breakpoints:
            self.breakpoints[dr_index].enabled = False
        for tid in self._get_process_thread_ids():
            self._arm_thread(tid)
        return True

    def run_event_loop(self, stop_event) -> None:
        """Event loop for Windows debugging."""
        logger.info("Entering Windows hardware breakpoint monitor loop...")
        while not stop_event.is_set():
            # In polling/snapshot mode on Windows, ensure new threads are armed
            for tid in self._get_process_thread_ids():
                self._arm_thread(tid)
            time.sleep(1.0)
