"""Forked process self-test verifying hardware execution breakpoints (DR0-DR3)."""

import os
import signal
import sys
import time
import unittest

from edmedia.core.types import AnchorReport, BreakpointKind, ButtonKind
from edmedia.debug.linux_ptrace import DR_OFFSETS, LinuxPtraceTracer, WALL_FLAG


class TestExecBreakpoint(unittest.TestCase):
    def test_hardware_breakpoint_and_suppression(self):
        if sys.platform != "linux":
            self.skipTest("ptrace DR0 test is only supported on Linux")

        # Spawn a small child process that executes a target loop
        # We use a child process executing a simple executable or python script
        pipe_r, pipe_w = os.pipe()

        pid = os.fork()
        if pid == 0:
            # Child process
            os.close(pipe_r)
            # Write child PID so parent is ready
            os.write(pipe_w, b"READY\n")
            os.close(pipe_w)

            # Spin in a loop waiting for signal or exit
            for _ in range(50):
                time.sleep(0.1)
            os._exit(0)

        # Parent process
        os.close(pipe_w)
        os.read(pipe_r, 6)
        os.close(pipe_r)

        try:
            report = AnchorReport()
            tracer = LinuxPtraceTracer(pid, report)

            # Test attaching
            self.assertTrue(tracer.attach())
            self.assertIn(pid, tracer._attached_threads)

            # Verify DR7 can be armed
            dummy_target_va = 0x400000
            tracer.arm_breakpoint(0, dummy_target_va, BreakpointKind.BUTTON_PLAY_PAUSE)

            # Stop child thread briefly to read hardware debug registers via PEEKUSER
            os.kill(pid, signal.SIGSTOP)
            os.waitpid(pid, WALL_FLAG)

            dr0_val = tracer._ptrace(3, pid, DR_OFFSETS[0], 0)  # PTRACE_PEEKUSER
            dr7_val = tracer._ptrace(3, pid, DR_OFFSETS[7], 0)

            self.assertEqual(dr0_val, dummy_target_va)
            # DR7 should have local enable (bit 0) and global enable (bit 1) and base bit 10 set
            self.assertTrue(dr7_val & 0x1)  # Bit 0 (L0)
            self.assertTrue(dr7_val & 0x400)  # Bit 10 (reserved 1)

            # Resume tracee
            tracer._ptrace(7, pid, 0, 0)

            # Disarm breakpoint
            tracer.disarm_breakpoint(0)

            os.kill(pid, signal.SIGSTOP)
            os.waitpid(pid, WALL_FLAG)
            dr7_disarmed = tracer._ptrace(3, pid, DR_OFFSETS[7], 0)
            tracer._ptrace(7, pid, 0, 0)
            self.assertFalse(dr7_disarmed & 0x1)

            # Clean detach
            tracer.detach()
            self.assertFalse(tracer.is_attached)

        finally:
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except Exception:
                pass

    def test_bypass_button_action(self):
        """Verify _bypass_button_action sets up stack frame, moves rbx, and redirects rip to +0x12."""
        if sys.platform != "linux":
            self.skipTest("Linux only")

        from edmedia.debug.linux_ptrace import UserRegsStruct
        import struct

        report = AnchorReport()
        tracer = LinuxPtraceTracer(12345, report)

        # Mock write_bytes and ptrace calls
        written_memory = {}
        tracer.write_bytes = lambda addr, data: written_memory.update({addr: data}) or True
        tracer._ptrace = lambda *args: 0

        regs = UserRegsStruct()
        regs.rsp = 0x7FFF0000
        regs.rbx = 0xDEADBEEFCAFE1234
        regs.rdx = 0x1122334455667788  # Event shared_ptr
        regs.rip = 0x1444F9380
        regs.eflags = 0x10202  # RF set

        bp_addr = 0x1444F9380
        tracer._bypass_button_action(12345, regs, bp_addr)

        # 1. Shadow space + rbx pushed: 0x20 + 0x08 = 0x28
        self.assertEqual(regs.rsp, 0x7FFF0000 - 0x28)

        # 2. Caller's rbx written to [original_rsp - 8]
        saved_rbx_bytes = written_memory.get(0x7FFF0000 - 8)
        self.assertIsNotNone(saved_rbx_bytes)
        self.assertEqual(struct.unpack("<Q", saved_rbx_bytes)[0], 0xDEADBEEFCAFE1234)

        # 3. rbx receives rdx (shared_ptr pointer)
        self.assertEqual(regs.rbx, 0x1122334455667788)

        # 4. rip redirected past call [rax + slot] to +0x12 (epilogue start)
        self.assertEqual(regs.rip, bp_addr + 0x12)

        # 5. RF flag cleared
        self.assertEqual(regs.eflags & 0x10000, 0)


if __name__ == "__main__":
    unittest.main()
