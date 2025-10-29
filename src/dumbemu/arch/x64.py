"""x64 64-bit architecture implementation."""
from __future__ import annotations
from typing import Tuple, Any
from ..utils.constants import RegID, ABI
from .base import Arch
from .args import Args

class X64(Arch):
    """x64 64-bit CPU architecture.
    
    Implements register access and calling convention
    for 64-bit x86-64/AMD64 processors.
    """
    @property
    def sp(self) -> int:
        return RegID.X64["rsp"]

    @property
    def ip(self) -> int:
        return RegID.X64["rip"]

    @property
    def ret(self) -> int:
        return RegID.X64["rax"]

    def prep(self, mem: "Mem", sp: int, args: Tuple[Any, ...], shadow: bool = False) -> int:
        """Setup args based on calling convention: Win64 or SysV x64."""
        ah = Args(self.ctx)
        conv = self.ctx.conv
        sp, regs, _ = ah.prep(mem, sp, args, shadow, conv)
        
        # Set register args based on convention
        if conv == 'sysv64':
            reg_names = ABI.SYSV64[:len(regs)]
        else:  # win64
            reg_names = ABI.WIN64[:len(regs)]
        
        # Mask values to 64 bits before writing
        mask = (1 << 64) - 1
        for name, val in zip(reg_names, regs):
            self.write(name, int(val) & mask)
        
        return sp
