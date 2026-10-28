"""Linux ptrace Hardware Breakpoint Engine (x86_64).

Uses OS debug registers (DR0-DR3) and /proc/$pid/mem for zero-overhead,
anti-tamper-invisible debugging on Linux and Proton.
"""

from __future__ import annotations

import ctypes
import logging
import os
import signal
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

# Linux Ptrace Constants
PTRACE_PEEKTEXT = 1
PTRACE_PEEKDATA = 2
PTRACE_PEEKUSER = 3
PTRACE_POKETEXT = 4
PTRACE_POKEDATA = 5
PTRACE_POKEUSER = 6
PTRACE_CONT = 7
PTRACE_KILL = 8
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_SETOPTIONS = 0x4200
PTRACE_SEIZE = 0x4206
PTRACE_INTERRUPT = 0x4207

PTRACE_O_TRACESYSGOOD = 1
PTRACE_O_TRACEFORK = 2
PTRACE_O_TRACECLONE = 8
PTRACE_O_TRACEEXEC = 16

WALL_FLAG = 0x40000000

# x86_64 Debug Register Offsets in struct user
DR_OFFSETS = {
    0: 848,  # u_debugreg[0]
    1: 856,  # u_debugreg[1]
    2: 864,  # u_debugreg[2]
    3: 872,  # u_debugreg[3]
    4: 880,  # u_debugreg[4]
    5: 888,  # u_debugreg[5]
    6: 896,  # u_debugreg[6] (Status Register)
    7: 904,  # u_debugreg[7] (Control Register)
}


class UserRegsStruct(ctypes.Structure):
    """x86_64 user_regs_struct representation matching sys/user.h."""
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]


class LinuxPtraceTracer(BaseTracer):
    """Linux x86_64 Hardware Breakpoint Tracer using ptrace and /proc/pid/mem."""

    def __init__(self, pid: int, anchor_report: AnchorReport):
        super().__init__(pid, anchor_report)
        self._libc = ctypes.CDLL("libc.so.6", use_errno=True)
        self._libc.ptrace.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        self._libc.ptrace.restype = ctypes.c_ulonglong
        self._mem_fd: Optional[int] = None
        self._attached_threads: Set[int] = set()
        self._last_button_time: float = 0.0
        self._detect_runtime_base()

    def _ptrace(self, request: int, pid: int, addr: int = 0, data: int = 0) -> int:
        ctypes.set_errno(0)
        res = self._libc.ptrace(
            ctypes.c_int(request),
            ctypes.c_int(pid),
            ctypes.c_void_p(addr),
            ctypes.c_void_p(data),
        )
        err = ctypes.get_errno()
        if res == 0xFFFFFFFFFFFFFFFF and err != 0:
            raise OSError(err, os.strerror(err))
        return res

    def _detect_runtime_base(self) -> None:
        """Parse /proc/<pid>/maps to determine the game's actual ASLR load address."""
        maps_path = f"/proc/{self.pid}/maps"
        if not os.path.exists(maps_path):
            return

        try:
            with open(maps_path, "r") as f:
                for line in f:
                    if "EliteDangerous64.exe" in line:
                        base_str = line.split("-")[0]
                        base_va = int(base_str, 16)
                        # Wine maps PE headers at 0x140000000 or the 64-bit base (>= 0x100000000)
                        if base_va >= 0x100000000:
                            self.calculate_aslr_shift(base_va)
                            return
        except Exception as e:
            logger.warning("Could not read /proc/%d/maps: %s", self.pid, e)

        # Fallback to preferred ImageBase (0x140000000)
        self.calculate_aslr_shift(self.anchor_report.image_base)

    def attach(self) -> bool:
        """Attach to target process and all existing threads."""
        try:
            mem_path = f"/proc/{self.pid}/mem"
            self._mem_fd = os.open(mem_path, os.O_RDWR)
        except Exception as e:
            logger.warning("Failed to open %s for direct memory access: %s", mem_path, e)

        self._sync_threads()
        self.is_attached = True
        logger.info("Attached to process %d (%d threads armed)", self.pid, len(self._attached_threads))
        return True

    def detach(self) -> None:
        """Disarm debug registers and detach from all threads."""
        self.is_attached = False

        # Clear DR7 on all attached threads
        for tid in list(self._attached_threads):
            try:
                self._ptrace(PTRACE_POKEUSER, tid, DR_OFFSETS[7], 0)
                self._ptrace(PTRACE_DETACH, tid, 0, 0)
            except Exception:
                pass

        self._attached_threads.clear()

        if self._mem_fd is not None:
            try:
                os.close(self._mem_fd)
            except Exception:
                pass
            self._mem_fd = None

        logger.info("Detached from process %d", self.pid)

    def read_bytes(self, address: int, size: int) -> bytes:
        if size <= 0:
            return b""
        if self._mem_fd is not None:
            try:
                return os.pread(self._mem_fd, size, address)
            except Exception:
                pass
        return b""

    def write_bytes(self, address: int, data: bytes) -> bool:
        if not data:
            return True
        if self._mem_fd is not None:
            try:
                written = os.pwrite(self._mem_fd, data, address)
                return written == len(data)
            except Exception as e:
                logger.error("Failed to write memory at 0x%x: %s", address, e)
                return False
        return False

    def _get_active_tids(self) -> List[int]:
        """List all thread IDs in /proc/<pid>/task."""
        task_dir = f"/proc/{self.pid}/task"
        if not os.path.isdir(task_dir):
            return [self.pid]
        try:
            return [int(entry) for entry in os.listdir(task_dir) if entry.isdigit()]
        except Exception:
            return [self.pid]

    def _sync_threads(self) -> None:
        """Discover and arm newly created threads."""
        current_tids = self._get_active_tids()
        for tid in current_tids:
            if tid not in self._attached_threads:
                try:
                    self._attach_and_arm_thread(tid)
                    self._attached_threads.add(tid)
                except Exception as e:
                    logger.debug("Failed to attach to thread %d: %s", tid, e)

    def _attach_and_arm_thread(self, tid: int) -> None:
        """Attach to a single thread and apply all configured debug registers."""
        try:
            self._ptrace(PTRACE_ATTACH, tid, 0, 0)
            # Wait for thread stop notification
            os.waitpid(tid, WALL_FLAG)
            self._arm_thread_registers(tid)
            self._ptrace(PTRACE_CONT, tid, 0, 0)
        except Exception as e:
            # Thread might have died or already attached
            raise e

    def _compute_dr7(self) -> int:
        """Compute DR7 value for all active execute breakpoints."""
        val = 0x400  # Bit 10 is reserved/always 1
        for idx, bp in self.breakpoints.items():
            if bp.enabled:
                # Local enable (bit 2*i) + Global enable (bit 2*i+1)
                val |= (1 << (2 * idx)) | (1 << (2 * idx + 1))
                # Condition: R/W = 00 (execute), Len = 00 (1-byte / instruction)
        return val

    def _arm_thread_registers(self, tid: int) -> None:
        """Set DR0-DR3 and DR7 on specified thread."""
        dr7 = self._compute_dr7()
        for idx in range(4):
            addr = self.breakpoints[idx].address if idx in self.breakpoints and self.breakpoints[idx].enabled else 0
            self._ptrace(PTRACE_POKEUSER, tid, DR_OFFSETS[idx], addr)
        self._ptrace(PTRACE_POKEUSER, tid, DR_OFFSETS[7], dr7)

    def arm_breakpoint(self, dr_index: int, address: int, kind: BreakpointKind) -> bool:
        """Configure and arm a hardware breakpoint across all threads."""
        if not (0 <= dr_index <= 3):
            raise ValueError(f"Invalid DR index: {dr_index}")

        self.breakpoints[dr_index] = Breakpoint(
            dr_index=dr_index,
            address=address,
            kind=kind,
            enabled=True,
        )

        logger.info("Arming DR%d at 0x%x for %s", dr_index, address, kind.value)

        # Update all currently attached threads
        for tid in list(self._attached_threads):
            try:
                # Stop thread briefly via tgkill to modify debug registers
                self._libc.syscall(234, self.pid, tid, signal.SIGSTOP)  # SYS_tgkill
                os.waitpid(tid, WALL_FLAG)
                self._arm_thread_registers(tid)
                self._ptrace(PTRACE_CONT, tid, 0, 0)
            except Exception:
                pass
        return True

    def disarm_breakpoint(self, dr_index: int) -> bool:
        """Disarm a hardware breakpoint across all threads."""
        if dr_index in self.breakpoints:
            self.breakpoints[dr_index].enabled = False

        dr7 = self._compute_dr7()
        for tid in list(self._attached_threads):
            try:
                self._libc.syscall(234, self.pid, tid, signal.SIGSTOP)  # SYS_tgkill
                os.waitpid(tid, WALL_FLAG)
                self._ptrace(PTRACE_POKEUSER, tid, DR_OFFSETS[dr_index], 0)
                self._ptrace(PTRACE_POKEUSER, tid, DR_OFFSETS[7], dr7)
                self._ptrace(PTRACE_CONT, tid, 0, 0)
            except Exception:
                pass
        return True

    def run_event_loop(self, stop_event) -> None:
        """Main event polling loop for hardware breakpoint traps."""
        logger.info("Entering ptrace hardware breakpoint event loop...")
        last_sync = 0.0

        while not stop_event.is_set():
            now = time.time()
            if now - last_sync > 2.0:
                self._sync_threads()
                last_sync = now

            try:
                # Wait for any stopped child/thread
                pid, status = os.waitpid(-1, os.WNOHANG | WALL_FLAG)
            except ChildProcessError:
                time.sleep(0.01)
                continue
            except Exception as e:
                logger.debug("waitpid error: %s", e)
                time.sleep(0.01)
                continue

            if pid == 0:
                time.sleep(0.005)
                continue

            if os.WIFSTOPPED(status):
                sig = os.WSTOPSIG(status)
                if sig == signal.SIGTRAP:
                    self._handle_trap(pid)
                elif sig == signal.SIGSTOP:
                    # Synthetic stop for thread sync; resume it
                    try:
                        self._ptrace(PTRACE_CONT, pid, 0, 0)
                    except Exception:
                        pass
                else:
                    # Pass other signals through
                    try:
                        self._ptrace(PTRACE_CONT, pid, 0, sig)
                    except Exception:
                        pass
            elif os.WIFEXITED(status) or os.WIFSIGNALED(status):
                self._attached_threads.discard(pid)

    def _handle_trap(self, tid: int) -> None:
        """Handle hardware breakpoint hit and execute queue advance suppression."""
        try:
            dr6 = self._ptrace(PTRACE_PEEKUSER, tid, DR_OFFSETS[6], 0)
        except Exception:
            dr6 = 0

        # Read CPU registers
        regs = UserRegsStruct()
        try:
            self._ptrace(PTRACE_GETREGS, tid, 0, ctypes.addressof(regs))
        except Exception as e:
            logger.debug("Failed to get registers for tid %d: %s", tid, e)
            try:
                self._ptrace(PTRACE_CONT, tid, 0, 0)
            except Exception:
                pass
            return

        # Determine which breakpoint triggered (bits 0-3 of DR6)
        hit_index = None
        for i in range(4):
            if dr6 & (1 << i):
                hit_index = i
                break

        if hit_index is not None and hit_index in self.breakpoints:
            bp = self.breakpoints[hit_index]
            controller_addr = regs.rcx  # 'this' pointer passed in RCX

            now = time.time()
            if now - self._last_button_time >= 0.35:
                self._last_button_time = now
                try:
                    if bp.kind == BreakpointKind.BUTTON_PLAY_PAUSE:
                        logger.info("Cockpit Play/Pause Trap on tid %d (controller=0x%x)", tid, controller_addr)
                        if self.on_button_pressed:
                            self.on_button_pressed(ButtonKind.PLAY_PAUSE, controller_addr, tid)

                    elif bp.kind == BreakpointKind.BUTTON_NEXT:
                        logger.info("Cockpit Next Trap on tid %d (controller=0x%x)", tid, controller_addr)
                        if self.on_button_pressed:
                            self.on_button_pressed(ButtonKind.NEXT, controller_addr, tid)

                    elif bp.kind == BreakpointKind.BUTTON_PREV:
                        logger.info("Cockpit Previous Trap on tid %d (controller=0x%x)", tid, controller_addr)
                        if self.on_button_pressed:
                            self.on_button_pressed(ButtonKind.PREVIOUS, controller_addr, tid)

                    elif bp.kind == BreakpointKind.UI_RENDER_LOOP:
                        if self.pending_ui_refresh:
                            if self.on_ui_refresh:
                                self.on_ui_refresh(tid)
                except Exception as e:
                    logger.exception("Error during breakpoint trap callback: %s", e)

            # CRITICAL: For cockpit button traps, BLOCK the in-game action by skipping
            # the virtual method call at offset 0x0c (`call [rax + slot]`)!
            # All 4 button thunks have the exact 18-byte (0x12) prologue:
            #   0x00: push rbx
            #   0x02: sub rsp, 0x20
            #   0x06: mov rax, [rcx]
            #   0x09: mov rbx, rdx
            #   0x0c: call [rax + slot]   <-- SKIP THIS CALL to block in-game audio!
            #   0x12: mov rcx, [rbx]      <-- Epilogue starts here (shared_ptr cleanup & return)
            # By simulating push rbx, sub rsp 0x20, mov rbx rdx and jumping directly to +0x12:
            # 1. The in-game audio/queue action is COMPLETELY BLOCKED.
            # 2. The event shared_ptr in rdx is properly decremented & destroyed.
            # 3. Stack and rbx are safely restored when epilogue executes ret.
            if bp.kind in (BreakpointKind.BUTTON_PLAY_PAUSE, BreakpointKind.BUTTON_NEXT, BreakpointKind.BUTTON_PREV):
                self._bypass_button_action(tid, regs, bp.address)
                return

        # Clear DR6 status register
        try:
            self._ptrace(PTRACE_POKEUSER, tid, DR_OFFSETS[6], 0)
        except Exception:
            pass

        # Resume thread with RF (Resume Flag, bit 16 in EFLAGS = 0x10000)
        # This tells the CPU to execute the current instruction without re-triggering #DB!
        try:
            regs.eflags |= 0x10000  # Set Resume Flag (RF)
            self._ptrace(PTRACE_SETREGS, tid, 0, ctypes.addressof(regs))
            self._ptrace(PTRACE_CONT, tid, 0, 0)
        except Exception as e:
            logger.debug("Failed to resume thread %d: %s", tid, e)

    def _bypass_button_action(self, tid: int, regs: UserRegsStruct, bp_address: int) -> None:
        """Bypass the in-game virtual call and jump directly to the shared_ptr cleanup epilogue.

        Bypasses the game's internal audio action while maintaining 100% ABI and stack/heap integrity.
        """
        try:
            # 1. Simulate: push rbx (save caller's rbx at [rsp - 8])
            new_rsp = regs.rsp - 8
            self.write_bytes(new_rsp, struct.pack("<Q", regs.rbx))

            # 2. Simulate: sub rsp, 0x20 (MSVC x64 shadow space)
            new_rsp -= 0x20
            regs.rsp = new_rsp

            # 3. Simulate: mov rbx, rdx (store event shared_ptr pointer in rbx)
            regs.rbx = regs.rdx

            # 4. Redirect RIP to offset +0x12 (right after call [rax + slot])
            regs.rip = bp_address + 0x12

            # 5. Clear DR6 status register
            try:
                self._ptrace(PTRACE_POKEUSER, tid, DR_OFFSETS[6], 0)
            except Exception:
                pass

            # 6. Apply modified registers and resume thread
            # Resume flag is not needed since RIP has advanced past the breakpoint address
            regs.eflags &= ~0x10000
            self._ptrace(PTRACE_SETREGS, tid, 0, ctypes.addressof(regs))
            self._ptrace(PTRACE_CONT, tid, 0, 0)
            logger.debug("Bypassed in-game button handler on tid %d (redirected RIP to 0x%x)", tid, regs.rip)
        except Exception as e:
            logger.error("Failed to bypass button action for tid %d: %s", tid, e)
            # Fallback: resume normally with RF
            try:
                regs.eflags |= 0x10000
                self._ptrace(PTRACE_SETREGS, tid, 0, ctypes.addressof(regs))
                self._ptrace(PTRACE_CONT, tid, 0, 0)
            except Exception:
                pass
