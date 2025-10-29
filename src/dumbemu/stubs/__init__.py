"""Stub management package for import hooking.

Provides core stub functionality and optional built-in stubs
for Windows and Linux platforms.
"""
from __future__ import annotations
from .core import (
    Stubs, Proto, Symbol, Callback,
    IAT, IATStubs, PLT, PLTStubs  # Compatibility aliases
)
from .win32 import register_win32_stubs, get_builtin_win32_stubs
from .posix import register_posix_stubs, get_builtin_posix_stubs

__all__ = [
    # Core
    "Stubs", "Proto", "Symbol", "Callback",
    # Compatibility
    "IAT", "IATStubs", "PLT", "PLTStubs",
    # Built-in stubs
    "register_win32_stubs", "get_builtin_win32_stubs",
    "register_posix_stubs", "get_builtin_posix_stubs",
]
