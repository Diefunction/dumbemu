from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple, Any, TYPE_CHECKING
from ..utils.constants import UC_PROT_READ, UC_PROT_EXEC, align_down
from ..utils.logger import log
from ..cpu.args import Args
from ..data.strings import Strings

if TYPE_CHECKING:
    from unicorn import Uc

# ---- Prototypes & conventions ----

@dataclass
class Proto:
    name: str
    conv: str  # 'win64', 'stdcall', 'cdecl'
    args: List[int]  # arg sizes in bytes

Callback = Callable[['IATStubs', Any, Tuple[int, ...]], int]

class IATStubs:
    """Import Address Table stub manager."""
    
    def __init__(self, ctx, mem, regs) -> None:
        self.ctx = ctx
        self.mem = mem
        self.regs = regs
        self.strings = Strings(mem)  # String helper

        self._next = ctx.tramp  # Next trampoline address
        self._stubs: Dict[Tuple[str,str], int] = {}  # (module,name) -> VA
        self._hooks: Dict[int, Tuple[Proto, Callback]] = {}  # VA -> (proto, callback)
        self._err = 0  # Last error code
        self.mods: Dict[str, int] = {}  # Module name -> handle
        self._base = ctx.alloc + 0x400000  # Module handle base

    def register(self, module: str, name: str, proto: Proto, cb: Callback) -> int:
        """Register a stub handler for an imported function.
        
        Args:
            module: DLL module name (e.g., 'kernel32.dll')
            name: Function name (e.g., 'GetProcAddress')
            proto: Function prototype with calling convention and arg sizes
            cb: Callback to execute when stub is called
            
        Returns:
            Virtual address of the created stub
        """
        key = (module.lower(), name)
        va = self._tramp()
        self._stubs[key] = va
        self._hooks[va] = (proto, cb)
        return va

    def get_va(self, module: str, name: str) -> Optional[int]:
        """Get the virtual address of a registered stub.
        
        Args:
            module: DLL module name
            name: Function name
            
        Returns:
            Virtual address if stub exists, None otherwise
        """
        return self._stubs.get((module.lower(), name))

    def attach(self, imports: List) -> None:
        """Overwrite IAT entries with stub addresses.
        
        Args:
            imports: List of Import objects from PE file
        """
        for item in imports:
            key = (item.module.lower(), item.name)
            if va := self._stubs.get(key):
                # overwrite IAT slot
                self.mem.pack(item.iat_va, va, bits=self.ctx.bits)

    def wire(self, add) -> None:
        """Connect stub trampolines to the hook system.
        
        Args:
            add: Hook registration function (typically Hooks.add)
        """
        for va in self._hooks:
            add(va, self._enter)

    def _tramp(self) -> int:
        """Create a new trampoline stub with RET instruction.
        
        Returns:
            Virtual address of the trampoline
        """
        va = self._next
        self._next += 0x100
        # Map page and write RET instruction
        page = align_down(va)
        try:
            self.mem.map(page, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
        except Exception:
            pass
        self.mem.write(va, b"\xC3")  # RET
        return va


    def _finish(self, proto: Proto, ret: int, sp: int) -> None:
        """Clean up after stub execution and return to caller.
        
        Args:
            proto: Function prototype for cleanup convention
            ret: Return value to set in return register
            sp: Current stack pointer
        """
        # Pop return address
        w = self.ctx.width
        addr = self.mem.unpack(sp, w)
        
        # Set return value
        self.regs.write(self.regs.ret, ret)
        
        # Use Args to calculate new SP
        ah = Args(self.ctx)
        sp = ah.cleanup(sp, proto)
        self.regs.write(self.regs.sp, sp)
        
        self.regs.write(self.regs.ip, addr)

    def _enter(self, uc: Any, addr: int) -> None:
        """Entry point when a stub is called.
        
        Args:
            uc: Unicorn instance
            addr: Address of the stub being executed
        """
        log.debug(f"IAT._enter: stub called at 0x{addr:08X}")
        if addr not in self._hooks:
            # Unknown stub called - shouldn't happen but be safe
            log.warn(f"IAT._enter: no hook for 0x{addr:08X}")
            return
        proto, cb = self._hooks[addr]
        log.debug(f"IAT._enter: {proto.name} with {len(proto.args)} args")
        sp = self.regs.read(self.regs.sp)
        
        # Use Args abstraction to read arguments
        ah = Args(self.ctx)
        args = ah.read(self.mem, self.regs, sp, proto.args)
        log.debug(f"IAT._enter: args={args}")
        
        try:
            ret = cb(self, uc, args) or 0
            log.debug(f"IAT._enter: callback returned {ret}")
        except Exception as e:
            log.error(f"IAT._enter: callback error: {e}")
            ret = 0
            
        self._finish(proto, int(ret), sp)
        # Skip the RET instruction at the stub address
        # by advancing IP past it
        ip = self.regs.read(self.regs.ip)
        self.regs.write(self.regs.ip, ip + 1)
        log.debug(f"IAT._enter: finished, IP=0x{ip+1:08X}")

    def _str(self, ptr: int) -> str:
        """Read null-terminated ASCII string from memory.
        
        Args:
            ptr: Pointer to string
            
        Returns:
            Decoded ASCII string
        """
        return self.strings.cstring(ptr)

    def _wstr(self, ptr: int) -> str:
        """Read null-terminated UTF-16 wide string from memory.
        
        Args:
            ptr: Pointer to wide string
            
        Returns:
            Decoded UTF-16 string
        """
        return self.strings.wstring(ptr)

    def set_err(self, code: int) -> None:
        """Set last error code (like SetLastError).
        
        Args:
            code: Error code to set
        """
        self._err = code

    def get_err(self) -> int:
        """Get last error code (like GetLastError).
        
        Returns:
            Last set error code
        """
        return self._err

    def _handle(self, name: str) -> int:
        """Get or create a fake module handle.
        
        Args:
            name: Module name
            
        Returns:
            Fake handle value for the module
        """
        key = name.lower()
        if h := self.mods.get(key):
            return h
        h = self._base
        self.mods[key] = h
        self._base += 0x10000
        return h
