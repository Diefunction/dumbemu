"""Argument handling abstraction for function calls."""
from __future__ import annotations
from typing import Any, List, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from ..context import Context
    from ..mem.memory import Mem

class Args:
    """Abstracts argument preparation and reading for different calling conventions."""
    
    # Win64 register order
    WIN64_REGS = ['rcx', 'rdx', 'r8', 'r9']
    
    def __init__(self, ctx: Context):
        self.ctx = ctx
        
    def prep(self, mem: Mem, sp: int, args: Tuple[Any, ...], shadow: bool = False) -> Tuple[int, List[Any], List[Any]]:
        """
        Prepare arguments for function call.
        Returns: (sp, regs, stack)
        """
        width = self.ctx.width
        bits = self.ctx.bits
        
        if self.ctx.is_64:
            # Win64: First 4 args in registers
            regs = list(args[:4])
            stack = list(args[4:])
            
            # Push stack args right-to-left
            for arg in reversed(stack):
                sp -= width
                mem.pack(sp, int(arg), bits=bits)
            
            # Reserve shadow space if needed
            if shadow:
                sp -= 32
                
            # Push return address
            sp -= width
            mem.pack(sp, self.ctx.fakeret, bits=bits)
            
            # Align stack if shadow space used
            # Win64 requires RSP to be 16-byte aligned before CALL (which pushes 8 bytes)
            # So after pushing return address, RSP should be (RSP & 0xF) == 8
            if shadow and (sp & 0xF) != 8:
                sp -= 8
                
            return sp, regs, stack
        else:
            # x86: All args on stack
            regs = []
            stack = list(args)
            
            # Push args right-to-left
            for arg in reversed(stack):
                sp -= width
                mem.pack(sp, int(arg), bits=bits)
                
            # Push return address
            sp -= width
            mem.pack(sp, self.ctx.fakeret, bits=bits)
            
            return sp, regs, stack
    
    def stack(self, mem: Mem, sp: int, count: int, sizes: List[int] = None) -> List[int]:
        """Read arguments from stack."""
        args = []
        if self.ctx.is_64:
            # Skip return address
            cur = sp + 8
            for i in range(count):
                args.append(mem.unpack(cur, 8))
                cur += 8
        else:
            # Skip return address
            cur = sp + 4
            for i in range(count):
                size = sizes[i] if sizes and i < len(sizes) else 4
                if size == 8:
                    args.append(mem.unpack(cur, 8))
                    cur += 8
                else:
                    args.append(mem.unpack(cur, 4))
                    cur += 4
        return args
    
    def regs(self, regs) -> List[int]:
        """Read register arguments (Win64 only)."""
        if not self.ctx.is_64:
            return []
        
        return [regs.read(name) for name in self.WIN64_REGS]
    
    def read(self, mem: Mem, regs, sp: int, sizes: List[int]) -> Tuple[int, ...]:
        """Read all arguments based on calling convention."""
        if self.ctx.is_64:
            # Win64: First 4 from registers, rest from stack
            args = []
            vals = self.regs(regs)
            
            for i, size in enumerate(sizes):
                if i < 4:
                    # From register
                    args.append(vals[i] if i < len(vals) else 0)
                else:
                    # From stack (skip return address + 32 bytes shadow space for args 1-4)
                    off = 8 + 32 + (i - 4) * 8
                    args.append(mem.unpack(sp + off, 8))
            
            return tuple(args)
        else:
            # x86: All from stack
            return tuple(self.stack(mem, sp, len(sizes), sizes))
    
    def cleanup(self, sp: int, proto) -> int:
        """Calculate new SP after function return based on calling convention."""
        if self.ctx.is_64:
            # Win64: Caller cleans up
            return sp + 8  # Pop return address only
        else:
            # x86: stdcall = callee cleans, cdecl = caller cleans
            if proto.conv == 'stdcall':
                # Callee cleans: pop return + args
                total = sum(max(4, s) for s in proto.args)
                return sp + 4 + total
            else:
                # Caller cleans: pop return only
                return sp + 4
