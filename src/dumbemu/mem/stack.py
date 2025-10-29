"""Stack memory management for function calls."""
from __future__ import annotations
from typing import Any, Tuple
from ..utils.constants import STACK_32, STACK_64
from ..utils.logger import log


class Stack:
    """Stack memory manager.
    
    Handles stack initialization, push/pop operations,
    and argument passing for function calls.
    """
    
    def __init__(self, ctx):
        self.base = ctx.stack
        self.size = STACK_64 if ctx.is_64 else STACK_32
        self.width = ctx.width
        self.bits = ctx.bits
        self._mapped = False
        
    def init(self, mem: "Mem", regs: "Regs") -> int:
        """Initialize stack memory and set SP register."""
        if not self._mapped:
            log.debug(f"Stack.init: mapping stack at 0x{self.base-self.size:08X}-0x{self.base:08X}")
            mem.map(self.base - self.size, self.size)
            regs.write(regs.sp, self.base)
            self._mapped = True
            log.debug(f"Stack.init: SP set to 0x{self.base:08X}")
        return regs.read(regs.sp)
    
    def push(self, mem: "Mem", sp: int, value: int) -> int:
        """Push value onto stack, return new SP."""
        sp -= self.width
        mem.pack(sp, value, bits=self.bits)
        return sp
    
    def pop(self, mem: "Mem", sp: int) -> Tuple[int, int]:
        """Pop value from stack, return (value, sp)."""
        value = mem.unpack(sp, self.width)
        return value, sp + self.width
    
    def args(self, mem: "Mem", sp: int, args: Tuple[Any, ...]) -> int:
        """Push arguments onto stack (right-to-left), return new SP."""
        for arg in reversed(args):
            sp = self.push(mem, sp, int(arg))
        return sp
    
    def read(self, mem: "Mem", sp: int, offset: int = 0) -> int:
        """Read value at SP + offset without modifying SP."""
        return mem.unpack(sp + offset, self.width)
    
    def write(self, mem: "Mem", sp: int, value: int, offset: int = 0) -> None:
        """Write value at SP + offset without modifying SP."""
        mem.pack(sp + offset, value, bits=self.bits)
    
    def align(self, sp: int, alignment: int = 16) -> int:
        """Align stack pointer to boundary."""
        return sp & ~(alignment - 1)
