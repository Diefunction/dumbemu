from __future__ import annotations
from typing import Optional, Callable, Any, List, Tuple
from unicorn import UcError

from .utils.constants import (
    PAGE, MAX_STR, align_down,
    UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_HOOK_CODE
)
from .utils.logger import log
from .pe.loader import PE
from .context import Context
from .mem.memory import Mem
from .mem.alloc import Alloc
from .win.tebpeb import TebPeb
from .win.iat import IATStubs, Proto
from .cpu.regs import Regs
from .mem.stack import Stack
from .mem.hooks import Hooks
from .data.structs import Struct
from .data.strings import Strings
from .debug.tracer import Tracer

class DumbEmu:
    """PE function emulator."""
    
    def __init__(self, path: str, verbose: bool = False):
        """Initialize PE emulator with all components.
        
        Args:
            path: Path to PE file to load
            verbose: Enable verbose debug logging
        """
        # Set up logging
        log.set_verbose(verbose)
        log.info(f"Initializing DumbEmu with {path}")
        
        self.pe = PE(path)
        log.debug(f"PE loaded: base=0x{self.pe.base:08X}, is_64={self.pe.is_64}")
        
        self.ctx = Context(self.pe)
        self.uc = self.ctx.uc  # Keep for compatibility
        log.debug(f"Context created: {'x64' if self.ctx.is_64 else 'x86'}")

        # Core components
        self.mem = Mem(self.ctx)
        self.regs = Regs(self.ctx)
        self.stack = Stack(self.ctx)
        self.hooks = Hooks(self.ctx)
        self._alloc = Alloc(self.ctx, self.mem)
        log.debug("Core components initialized")
        
        # Extended components
        self.struct = Struct(self.mem)
        self.string = Strings(self.mem)
        self.tracer = Tracer(self.ctx)
        
        # Windows environment
        self.tebpeb = TebPeb(self.ctx, self.mem)
        self.iat = IATStubs(self.ctx, self.mem, self.regs)
        
        # Expose allocator for backward compatibility
        self.alloc = self._alloc
        
        # Setup execution environment
        self._setup_environment()

    def _load_image(self) -> None:
        """Load PE sections into memory with proper protections."""
        base = self.pe.base
        size = self.pe.size
        self.mem.map(base, size, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)

        # Write section data and apply per-section protections
        for va, vsize, prot, data in self.pe.sections():
            # Write section data (truncated to vsize)
            if data:
                self.mem.write(va, data[:vsize])
                written = len(data[:vsize])
            else:
                written = 0
            
            # Zero-fill remainder if needed
            if written < vsize:
                self.mem.write(va + written, b"\x00" * (vsize - written))
            # Apply section protection
            pages = self.mem.page_count(vsize)
            self.mem.protect(va, pages * PAGE, prot)
    
    def _setup_environment(self) -> None:
        """Setup complete execution environment including PE, TEB/PEB, and IAT."""
        # Map fake return address for stopping execution
        self.mem.map(align_down(self.ctx.fakeret), PAGE, UC_PROT_READ | UC_PROT_EXEC)
        
        # Load PE image
        self._load_image()
        
        # Initialize Windows structures
        self.tebpeb.seed(self.pe.base)
        
        # Setup IAT hooks
        self._setup_iat()

    def hook(self, addr: int, callback: Callable[[Any, int], None]) -> None:
        """Add a code hook at specific address.
        
        Args:
            addr: Address to hook
            callback: Function to call when address is executed
        """
        self.hooks.add(addr, callback)

    def write(self, addr: int, data: bytes) -> None:
        """Write bytes to memory."""
        self.mem.write(addr, data)

    def read(self, addr: int, size: int) -> bytes:
        """Read bytes from memory."""
        return self.mem.read(addr, size)

    def malloc(self, size: int, prot: int = UC_PROT_READ | UC_PROT_WRITE) -> int:
        """Allocate memory region.
        
        Args:
            size: Size in bytes (will be rounded up to page size)
            prot: Memory protection flags (default: RW)
            
        Returns:
            Base address of allocated region
        """
        return self._alloc.alloc(size, prot)
    
    def free(self, addr: int) -> bool:
        """Free allocated memory region.
        
        Args:
            addr: Base address of the allocation
            
        Returns:
            True if freed successfully, False if not found
        """
        return self._alloc.free(addr)
    
    # String operations delegated to string component
    # Use: emu.string.cstring(addr) or emu.string.wstring(addr)

    def execute(self, addr: int, until: Optional[int] = None, count: Optional[int] = None) -> None:
        """Execute code at address without function call setup.
        
        Args:
            addr: Start address for execution
            until: Optional address to stop at (breakpoint)
            count: Optional instruction count limit (no default limit)
        """
        log.debug(f"execute: addr=0x{addr:08X}, until={f'0x{until:08X}' if until else 'None'}, count={count}")
        self._run(addr, until or 0, None, count)
        log.debug(f"execute: finished")

    def call(self, addr: int, breakpoint: Optional[int] = None, *args: Any, 
             max_insns: int = 1000000) -> int:
        """Call a function at given address with arguments.
        
        Args:
            addr: Function address to call
            breakpoint: Optional address to stop execution
            *args: Function arguments
            max_insns: Maximum instructions to execute (default: 1M, prevents infinite loops)
            
        Returns:
            Function return value
        """
        log.debug(f"call: addr=0x{addr:08X}, args={args}, breakpoint={f'0x{breakpoint:08X}' if breakpoint else 'None'}")
        sp = self.stack.init(self.mem, self.regs)
        sp = self.regs.prep(self.mem, sp, args, shadow=self.ctx.is_64)
        self.regs.write(self.regs.sp, sp)
        log.debug(f"call: SP set to 0x{sp:08X}")
        self._run(addr, self.ctx.fakeret, breakpoint, max_insns)
        ret = self.regs.retval()
        log.debug(f"call: returned 0x{ret:08X}")
        return ret

    def _run(self, addr: int, retaddr: int, breakpoint: Optional[int], count: Optional[int]) -> None:
        """Execute emulation until stop condition.
        
        Args:
            addr: Start address
            retaddr: Address to stop execution at
            breakpoint: Optional breakpoint address
            count: Optional instruction count limit
        """
        log.debug(f"_run: start=0x{addr:08X}, retaddr=0x{retaddr:08X}, count={count}")
        stops = {retaddr}  # Always stop at this address
        if breakpoint:
            stops.add(breakpoint)
            log.debug(f"_run: added breakpoint at 0x{breakpoint:08X}")
            
        def _stop(uc, addr, size, _):
            if addr in stops:
                log.debug(f"_run: stopping at 0x{addr:08X}")
                uc.emu_stop()
                
        h = self.uc.hook_add(UC_HOOK_CODE, _stop)
        try:
            kwargs = {'count': count} if count else {}
            log.debug(f"_run: starting emulation")
            self.uc.emu_start(addr, 0, **kwargs)
            log.debug(f"_run: emulation ended")
        except UcError as e:
            log.debug(f"_run: UcError: {e}")
        finally:
            try:
                self.uc.hook_del(h)
            except Exception:
                pass

    def stub(self, module: str, name: str, proto: Proto, cb: Callable) -> int:
        """Register a stub handler for an imported function.
        
        Args:
            module: DLL module name
            name: Function name
            proto: Function prototype
            cb: Callback to execute when stub is called
            
        Returns:
            Virtual address of the stub
        """
        va = self.iat.register(module, name, proto, cb)
        self._setup_iat()
        return va

    def invoke(self, module: str, name: str, *args) -> int:
        """Call an imported function by name.
        
        Args:
            module: DLL module name
            name: Function name
            *args: Function arguments
            
        Returns:
            Function return value
        """
        if va := self.iat.get_va(module, name):
            return self.call(va, None, *args)
        
        # Auto-create stub
        proto = Proto(name, self.ctx.conv, [])
        va = self.iat.register(module, name, proto, lambda s, uc, a: 0)
        self._setup_iat()
        return self.call(va, None, *args)

    def _setup_iat(self) -> None:
        """Attach and wire IAT stubs."""
        try:
            imports = self.pe.imports()
            self.iat.attach(imports)
        except Exception:
            pass
        self.iat.wire(self.hooks.add)
    
    def trace(self, addr: int, stop: Optional[int] = None, 
              count: Optional[int] = None) -> Tuple[List[int], int]:
        """Trace execution and collect executed addresses.
        
        Args:
            addr: Start address
            stop: Optional stop address
            count: Optional max instructions to execute
            
        Returns:
            Tuple of (addresses_list, instruction_count)
        
        Example:
            addrs, total = emu.trace(entry_point, count=100)
            print(f"Executed {total} instructions")
            for a in addrs[:10]:
                print(f"  0x{a:08X}")
        """
        return self.tracer.run(addr, stop, count)