"""Base Tracer and Hardware Breakpoint Interface."""

from __future__ import annotations

import logging
import threading
from abc import ABC, abstractmethod
from typing import Callable, Dict, Optional

from edmedia.core.types import (
    AnchorReport,
    Breakpoint,
    BreakpointKind,
    ButtonKind,
)

logger = logging.getLogger(__name__)


class BaseTracer(ABC):
    """Abstract debugger and hardware execution breakpoint engine."""

    def __init__(self, pid: int, anchor_report: AnchorReport):
        self.pid = pid
        self.anchor_report = anchor_report
        self.breakpoints: Dict[int, Breakpoint] = {}  # dr_index -> Breakpoint
        self.is_attached = False
        self.runtime_base: int = anchor_report.image_base
        self.aslr_shift: int = 0
        self.pending_ui_refresh = False

        # Callbacks
        self.on_button_pressed: Optional[Callable[[ButtonKind, int, int], None]] = None
        self.on_ui_refresh: Optional[Callable[[int], None]] = None

    def calculate_aslr_shift(self, detected_base: int) -> None:
        """Calculate relocation difference between preferred image base and runtime base."""
        self.runtime_base = detected_base
        self.aslr_shift = detected_base - self.anchor_report.image_base
        logger.info(
            "ASLR Base: 0x%x (shift: 0x%x from preferred 0x%x)",
            self.runtime_base,
            self.aslr_shift,
            self.anchor_report.image_base,
        )

    def to_runtime_va(self, rva: int) -> int:
        """Convert RVA to current runtime virtual address."""
        return self.runtime_base + rva

    @abstractmethod
    def attach(self) -> bool:
        """Attach to target process and prepare thread arming."""
        ...

    @abstractmethod
    def detach(self) -> None:
        """Disarm all breakpoints and detach from process."""
        ...

    @abstractmethod
    def read_bytes(self, address: int, size: int) -> bytes:
        """Read virtual memory from the target process."""
        ...

    @abstractmethod
    def write_bytes(self, address: int, data: bytes) -> bool:
        """Write virtual memory to the target process."""
        ...

    @abstractmethod
    def arm_breakpoint(self, dr_index: int, address: int, kind: BreakpointKind) -> bool:
        """Set a hardware execute breakpoint in DR0-DR3."""
        ...

    @abstractmethod
    def disarm_breakpoint(self, dr_index: int) -> bool:
        """Disarm a hardware breakpoint in DR0-DR3."""
        ...

    @abstractmethod
    def run_event_loop(self, stop_event: threading.Event) -> None:
        """Listen for debug traps and dispatch actions until stopped."""
        ...

    def request_ui_refresh(self) -> None:
        """Signal that the cockpit UI should execute an in-engine refresh on next frame."""
        self.pending_ui_refresh = True
        logger.debug("Requested UI refresh on next available frame hook")

    def setup_default_hooks(self) -> None:
        """Arm DR0 (Play/Pause), DR1 (Next), and DR2 (Previous) from the anchor report."""
        handlers = self.anchor_report.handlers

        # DR0: Play/Pause
        if "AudioPlayerOnPlayPauseToggle" in handlers and handlers["AudioPlayerOnPlayPauseToggle"].confidence > 0:
            target = handlers["AudioPlayerOnPlayPauseToggle"]
            va = self.to_runtime_va(target.rva)
            self.arm_breakpoint(0, va, BreakpointKind.BUTTON_PLAY_PAUSE)

        # DR1: Next
        if "AudioPlayerOnNext" in handlers and handlers["AudioPlayerOnNext"].confidence > 0:
            target = handlers["AudioPlayerOnNext"]
            va = self.to_runtime_va(target.rva)
            self.arm_breakpoint(1, va, BreakpointKind.BUTTON_NEXT)

        # DR2: Previous
        if "AudioPlayerOnPrevious" in handlers and handlers["AudioPlayerOnPrevious"].confidence > 0:
            target = handlers["AudioPlayerOnPrevious"]
            va = self.to_runtime_va(target.rva)
            self.arm_breakpoint(2, va, BreakpointKind.BUTTON_PREV)
