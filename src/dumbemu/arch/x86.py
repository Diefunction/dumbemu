"""x86 32-bit architecture implementation."""
from __future__ import annotations
from typing import Tuple, Any
from ..utils.constants import RegID
from .base import Arch
from .args import Args

class X86(Arch):
    """x86 32-bit CPU architecture.
    
    Implements register access and calling convention
    for 32-bit x86 processors.
    """
    @property
    def sp(self) -> int:
        return RegID.X86["esp"]

    @property
    def ip(self) -> int:
        return RegID.X86["eip"]

    @property
    def ret(self) -> int:
        return RegID.X86["eax"]

    def prep(self, mem: "Mem", sp: int, args: Tuple[Any, ...], shadow: bool = False) -> int:
        """x86 stdcall/cdecl: push args right-to-left."""
        ah = Args(self.ctx)
        sp, _, _ = ah.prep(mem, sp, args, shadow)
        return sp
