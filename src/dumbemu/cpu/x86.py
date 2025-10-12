"""x86 32-bit architecture implementation."""
from typing import Tuple, Any
from ..utils.constants import Regs
from .base import Arch
from .args import Args

class X86(Arch):
    @property
    def sp(self) -> int:
        return Regs.X86["esp"]

    @property
    def ip(self) -> int:
        return Regs.X86["eip"]

    @property
    def ret(self) -> int:
        return Regs.X86["eax"]

    def prep(self, mem: "Mem", sp: int, args: Tuple[Any, ...], shadow: bool = False) -> int:
        """x86 stdcall/cdecl: push args right-to-left."""
        ah = Args(self.ctx)
        sp, _, _ = ah.prep(mem, sp, args, shadow)
        return sp
