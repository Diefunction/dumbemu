"""CPU state and register management."""
from __future__ import annotations
from typing import Union
from .base import Arch
from .x86 import X86
from .x64 import X64

class Regs:
    """Register access and calling convention setup."""
    
    def __init__(self, ctx):
        self.ctx = ctx
        self.arch: Arch = X64(ctx) if ctx.is_64 else X86(ctx)

    def read(self, reg: Union[int, str]) -> int:
        """Read register value."""
        return self.arch.read(reg)

    def write(self, reg: Union[int, str], value: int) -> None:
        """Write register value."""
        self.arch.write(reg, value)

    @property
    def sp(self) -> int:
        """Stack pointer register ID."""
        return self.arch.sp

    @property
    def ip(self) -> int:
        """Instruction pointer register ID."""
        return self.arch.ip

    @property
    def ret(self) -> int:
        """Return value register ID."""
        return self.arch.ret

    def prep(self, mem: "Mem", sp: int, args, shadow: bool = False) -> int:
        """Setup stack/registers for function call per ABI."""
        return self.arch.prep(mem, sp, args, shadow)

    def retval(self) -> int:
        """Get function return value."""
        return self.read(self.ret)
