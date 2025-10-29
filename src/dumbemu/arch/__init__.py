"""CPU architecture implementations.

Provides x86/x64 register access and calling conventions.
"""
from __future__ import annotations
from .regs import Registers
from .args import Args
from .base import Arch
from .x86 import X86
from .x64 import X64

# Compatibility alias
Regs = Registers  # Keep for backward compatibility

__all__ = ["Registers", "Regs", "Args", "Arch", "X86", "X64"]
