"""Function argument handling for different calling conventions."""
from __future__ import annotations
from typing import Any, List, Tuple, TYPE_CHECKING
from ..utils.constants import ABI

if TYPE_CHECKING:
    from ..core.context import Context
    from ..mem.memory import Mem

class Args:
    """Calling convention argument handler.
    
    Manages argument preparation and reading for different ABIs
    including Win64, stdcall, SysV x64, and cdecl.
    """
    
    # Use ABI constants
    WIN64_REGS = ABI.WIN64
    SYSV64_REGS = ABI.SYSV64
    
    def __init__(self, ctx: Context):
        self.ctx = ctx
        
    def prep(self, mem: Mem, sp: int, args: Tuple[Any, ...], shadow: bool = False, conv: str = None) -> Tuple[int, List[Any], List[Any]]:
        """
        Prepare arguments for function call.
        
        Stack alignment rules:
        - SysV x64: RSP must be 16-byte aligned before CALL
        - Win64: Requires 32 bytes shadow space for first 4 args
        - x86: No specific alignment required by ABI
        
        Returns: (sp, regs, stack)
        """
        width = self.ctx.width
        bits = self.ctx.bits
        conv = conv or self.ctx.conv
        
        if self.ctx.is_64:
            if conv == 'win64':
                # Win64: First 4 args in registers
                regs = list(args[:4])
                stack = list(args[4:])
            elif conv == 'sysv64':
                # SysV x64: First 6 args in registers
                regs = list(args[:6])
                stack = list(args[6:])
            else:
                regs = list(args[:4])  # Default
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
    
    def regs(self, registers, conv: str = None) -> List[int]:
        """Read register arguments based on calling convention."""
        if not self.ctx.is_64:
            return []
        
        conv = conv or self.ctx.conv
        if conv == 'sysv64':
            return [registers.read(name) for name in self.SYSV64_REGS]
        else:  # win64 or default
            return [registers.read(name) for name in self.WIN64_REGS]
    
    def read(self, mem: Mem, regs, sp: int, sizes: List[int], conv: str = None) -> Tuple[int, ...]:
        """Read all arguments based on calling convention."""
        conv = conv or self.ctx.conv
        
        if self.ctx.is_64:
            args = []
            vals = self.regs(regs, conv)
            
            if conv == 'sysv64':
                # SysV x64: First 6 from registers, rest from stack
                for i, size in enumerate(sizes):
                    if i < 6:
                        args.append(vals[i] if i < len(vals) else 0)
                    else:
                        # From stack (skip return address only)
                        off = 8 + (i - 6) * 8
                        args.append(mem.unpack(sp + off, 8))
            else:  # win64
                # Win64: First 4 from registers, rest from stack
                for i, size in enumerate(sizes):
                    if i < 4:
                        args.append(vals[i] if i < len(vals) else 0)
                    else:
                        # From stack (skip return address + 32 bytes shadow space)
                        off = 8 + 32 + (i - 4) * 8
                        args.append(mem.unpack(sp + off, 8))
            
            return tuple(args)
        else:
            # x86: All from stack
            return tuple(self.stack(mem, sp, len(sizes), sizes))
    
    def cleanup(self, sp: int, proto) -> int:
        """Calculate new SP after function return based on calling convention."""
        if self.ctx.is_64:
            # Both Win64 and SysV x64: Caller cleans up
            return sp + 8  # Pop return address only
        else:
            # x86: stdcall = callee cleans, cdecl = caller cleans
            if proto.conv == 'stdcall':
                # Callee cleans: pop return + args
                # Ensure all args are integer byte sizes (min 4 bytes for x86 stack slots)
                total = sum(max(4, int(s) if not isinstance(s, int) else s) for s in proto.args)
                return sp + 4 + total
            else:
                # cdecl: Caller cleans (pop return only)
                return sp + 4
