"""x64 64-bit architecture implementation."""
from typing import Tuple, Any
from ..utils.constants import Regs
from .base import Arch
from .args import Args

class X64(Arch):
    @property
    def sp(self) -> int:
        return Regs.X64["rsp"]

    @property
    def ip(self) -> int:
        return Regs.X64["rip"]

    @property
    def ret(self) -> int:
        return Regs.X64["rax"]

    def prep(self, mem: "Mem", sp: int, args: Tuple[Any, ...], shadow: bool = False) -> int:
        """Win64 ABI: RCX,RDX,R8,R9 + optional shadow space."""
        ah = Args(self.ctx)
        sp, regs, _ = ah.prep(mem, sp, args, shadow)
        
        # Set register args
        for name, val in zip(Args.WIN64_REGS[:len(regs)], regs):
            self.write(name, int(val))
        
        return sp
