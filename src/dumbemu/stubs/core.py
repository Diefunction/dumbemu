"""Core stub management for import hooking."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple, Any, TYPE_CHECKING
from ..utils.constants import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, align_down, MODULE_HANDLE_OFFSET, MAX_STR, Platform
from ..utils.logger import log
from ..arch.args import Args
from ..data.strings import Strings

if TYPE_CHECKING:
    from unicorn import Uc

# ---- Function prototypes ----

@dataclass
class Proto:
    """Function prototype for both Windows and Linux."""
    name: str
    conv: str  # 'win64', 'stdcall', 'cdecl', 'sysv64'
    args: List[int]  # arg sizes in bytes
    
    def __post_init__(self):
        """Normalize args to ensure they are all integer byte sizes."""
        # Convert any non-integer args to integers
        self.args = [int(a) if not isinstance(a, int) else a for a in self.args]

# Aliases for compatibility
Symbol = Proto  # Linux uses Symbol name

Callback = Callable[['Stubs', Any, Tuple[int, ...]], int]

class Stubs:
    """Unified import stub manager for Windows PE and Linux ELF.
    
    Manages dynamic API/symbol stubs for imported functions,
    allowing interception and emulation of DLL/shared library calls.
    Automatically tightens trampoline page permissions from RWX to RX after
    writing RET instructions to prevent accidental modification.
    """
    
    def __init__(self, ctx, mem, regs) -> None:
        self.ctx = ctx
        self.mem = mem
        self.regs = regs
        self.strings = Strings(mem)
        
        self._next = ctx.tramp  # Next trampoline address
        self._stubs: Dict[Tuple[str,str], int] = {}  # (module,name) -> VA
        self._hooks: Dict[int, Tuple[Proto, Callback]] = {}  # VA -> (proto, callback)
        self._last_error = 0  # Last error code (SetLastError/errno)
        self.libs: Dict[str, int] = {}  # Module/library name -> handle
        self._base = ctx.alloc + MODULE_HANDLE_OFFSET  # Module handle base
        self._tramp_pages = set()  # Track mapped trampoline pages
        self._tightened_pages = set()  # Pages already tightened to RX
        self._registry: Dict[str, Callback] = {}  # Registry for pluggable stubs
    
    def register_plugin(self, name: str, callback: Callback) -> None:
        """Register a pluggable stub handler.
        
        Args:
            name: Unique name for the plugin
            callback: Callback function for the stub
        """
        self._registry[name] = callback
        log.debug(f"Stubs: Registered plugin '{name}'")
    
    def get_plugin(self, name: str) -> Optional[Callback]:
        """Get a registered plugin by name.
        
        Args:
            name: Plugin name
            
        Returns:
            Callback if found, None otherwise
        """
        return self._registry.get(name)
    
    def register(self, module: str, name: str, proto: Proto, callback: Callback) -> int:
        """Register a stub handler for an imported function.
        
        Args:
            module: Module/library name (e.g., 'kernel32.dll', 'libc.so.6')
            name: Function/symbol name (e.g., 'GetProcAddress', 'printf')
            proto: Function prototype with calling convention and arg sizes
            callback: Callback to execute when stub is called
            
        Returns:
            Virtual address of the created stub
        """
        key = (module.lower(), name)
        va = self._tramp()
        self._stubs[key] = va
        self._hooks[va] = (proto, callback)
        return va
    
    def get_va(self, module: str, name: str) -> Optional[int]:
        """Get the virtual address of a registered stub.
        
        Args:
            module: Module/library name
            name: Function/symbol name
            
        Returns:
            Virtual address if stub exists, None otherwise
        """
        return self._stubs.get((module.lower(), name))
    
    def attach(self, imports: List) -> None:
        """Overwrite import entries with stub addresses.
        
        Args:
            imports: List of Import objects from PE/ELF file
        """
        for item in imports:
            # Handle both old Import class and new Import dataclass
            if hasattr(item, 'iat_va'):
                # Old Import class (legacy)
                key = (item.module.lower(), item.name)
                va_ptr = item.iat_va
            else:
                # New Import dataclass
                key = (item.module.lower(), item.name)
                va_ptr = item.va
                
            if va := self._stubs.get(key):
                # Overwrite IAT/GOT slot
                self.mem.pack(va_ptr, va, bits=self.ctx.bits)
    
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
        self._next += 8  # Only need 1 byte for RET, but align to 8 bytes
        
        # Only map page if not already mapped
        page = align_down(va)
        if page not in self._tramp_pages:
            try:
                # Map RWX while emitting trampoline bytes
                self.mem.map(page, 0x1000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
                self._tramp_pages.add(page)
                log.debug(f"Stubs._tramp: Mapped trampoline page at 0x{page:08X}")
            except Exception as e:
                log.debug(f"Stubs._tramp: Failed to map page 0x{page:08X}: {e}")
        
        self.mem.write(va, b"\xC3")  # RET (same for x86/x64)
        
        # Tighten permissions to RX after write (prevent accidental writes during emulation)
        if page not in self._tightened_pages:
            try:
                self.mem.protect(page, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
                self._tightened_pages.add(page)
                log.debug(f"Stubs._tramp: Tightened page 0x{page:08X} to RX")
            except Exception as e:
                log.debug(f"Stubs._tramp: Failed to tighten permissions: {e}")
        
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
        
        # Set return value (mask to pointer width)
        mask = (1 << (self.ctx.width * 8)) - 1
        self.regs.write(self.regs.ret, ret & mask)
        
        # Platform-specific cleanup
        if self.ctx.platform == Platform.WINDOWS and not self.ctx.is_64:
            # Windows x86: Check calling convention
            if proto.conv == 'stdcall':
                # Callee cleans up
                ah = Args(self.ctx)
                sp = ah.cleanup(sp, proto)
            else:
                # cdecl: Caller cleans up
                sp += w
        else:
            # Win64, Linux x64, Linux x86: Caller always cleans up
            sp += w
        
        self.regs.write(self.regs.sp, sp)
        self.regs.write(self.regs.ip, addr)
    
    def _enter(self, uc: Any, addr: int) -> None:
        """Entry point when a stub is called.
        
        Args:
            uc: Unicorn instance
            addr: Address of the stub being executed
        """
        log.debug(f"Stubs._enter: stub called at 0x{addr:08X}")
        if addr not in self._hooks:
            log.warning(f"Stubs._enter: no hook for 0x{addr:08X}")
            return
            
        proto, callback = self._hooks[addr]
        log.debug(f"Stubs._enter: {proto.name} with {len(proto.args)} args")
        sp = self.regs.read(self.regs.sp)
        
        # Read arguments based on platform ABI
        args = self._read_args(proto, sp)
        log.debug(f"Stubs._enter: args={args}")
        
        try:
            ret_raw = callback(self, uc, args)
            # Validate and convert return value
            try:
                ret = int(ret_raw) if ret_raw is not None else 0
            except (TypeError, ValueError):
                log.warning(f"Stub returned non-int {type(ret_raw).__name__}; coerced to 0")
                ret = 0
            log.debug(f"Stubs._enter: callback returned {ret}")
        except Exception as e:
            log.error(f"Stubs._enter: callback error: {e}")
            ret = 0
            
        self._finish(proto, int(ret), sp)
        # IP already set to return address by _finish()
        log.debug(f"Stubs._enter: finished, IP=0x{self.regs.read(self.regs.ip):08X}")
    
    def _read_args(self, proto: Proto, sp: int) -> Tuple[int, ...]:
        """Read arguments based on calling convention.
        
        Args:
            proto: Function prototype with convention info
            sp: Stack pointer
            
        Returns:
            Tuple of argument values
        """
        # Use centralized Args for all platforms
        ah = Args(self.ctx)
        return ah.read(self.mem, self.regs, sp, proto.args, proto.conv)
    
    def _str(self, ptr: int) -> str:
        """Read null-terminated ASCII string from memory."""
        return self.strings.cstring(ptr)
    
    def _wstr(self, ptr: int) -> str:
        """Read null-terminated wide string from memory."""
        if self.ctx.platform == Platform.LINUX:
            # Linux uses UTF-32 for wchar_t
            return self.strings.wstring32(ptr)
        else:
            # Windows uses UTF-16
            return self.strings.wstring(ptr)
    
    def set_last_error(self, code: int) -> None:
        """Set last error code (Windows SetLastError / Linux errno).
        
        Args:
            code: Error code to set
        """
        self._last_error = code
    
    def get_last_error(self) -> int:
        """Get last error code (Windows GetLastError / Linux errno).
        
        Returns:
            Last set error code
        """
        return self._last_error
    
    # Keep these for backward compatibility - many tests/code use them
    def set_err(self, code: int) -> None:
        """Set error (compatibility alias for set_last_error)."""
        self.set_last_error(code)
    
    def get_err(self) -> int:
        """Get error (compatibility alias for get_last_error)."""
        return self.get_last_error()
    
    def _handle(self, name: str) -> int:
        """Get or create a fake module/library handle.
        
        Args:
            name: Module/library name
            
        Returns:
            Fake handle value
        """
        key = name.lower()
        if h := self.libs.get(key):
            return h
        h = self._base
        self.libs[key] = h
        self._base += 0x10000
        return h


def register_builtins(stubs, builtins: dict, selection: list[str] | None = None):
    """Register built-in stubs from a dictionary.
    
    Args:
        stubs: Stubs manager instance
        builtins: Dictionary mapping (module, name) to (proto_or_symbol, callback)
        selection: Optional list of function names to register.
                  If None, registers all available stubs.
    """
    for (module, name), (proto_or_symbol, callback) in builtins.items():
        if selection is None or name in selection:
            stubs.register(module, name, proto_or_symbol, callback)


# Compatibility aliases for backward compatibility
IAT = Stubs  # Windows code can still use IAT
IATStubs = Stubs  # Alternative Windows name
PLT = Stubs  # Linux code can still use PLT
PLTStubs = Stubs  # Alternative Linux name
