"""Core emulator components.

Main emulator class, context, and exception hierarchy.
"""
from __future__ import annotations
from .emulator import DumbEmu
from .context import Context
from .exceptions import (
    EmuError, LoaderError, FormatError, MemoryError,
    ExecutionError, EmuLimitError, SegFaultError,
    StubError, ArgumentError
)

__all__ = [
    "DumbEmu", "Context",
    "EmuError", "LoaderError", "FormatError", "MemoryError",
    "ExecutionError", "EmuLimitError", "SegFaultError",
    "StubError", "ArgumentError"
]
