"""Main emulator module for Windows PE and Linux ELF executables."""
from __future__ import annotations
from typing import Optional, Callable, Any, List, Tuple, Union
from ..types import Addr, Size, Prot, InsnCount, BreakAddr, CodeCage, HookCallback
from unicorn import UcError, UC_ERR_FETCH_UNMAPPED, UC_ERR_INSN_INVALID, UC_ERR_OK

from ..utils.constants import (
    PAGE, MAX_STR, align_down, Platform, DEFAULT_MAX_INSNS,
    UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_HOOK_CODE,
    STACK_32, STACK_64
)
from ..utils.logger import log
from ..formats.factory import Factory
from ..formats.base import Loader
from .context import Context
from .exceptions import ExecutionError, EmuLimitError, SegFaultError
from ..mem.memory import Mem
from ..mem.alloc import Alloc
from ..arch.regs import Registers
from ..mem.stack import Stack
from ..mem.hooks import Hooks
from ..data.structs import Struct
from ..data.strings import Strings
from ..debug.tracer import Tracer

# Platform-specific imports
from ..platforms.windows import TebPeb
from ..platforms.linux import AuxV
from ..stubs import Stubs, Proto, Symbol  # Unified stub manager


class DumbEmu:
    """Main emulator class for x86/x64 malware analysis.
    
    Supports Windows PE and Linux ELF executables with automatic
    format detection, dynamic import stubbing, and execution tracing.
    """
    
    def __init__(self, path: str, verbose: bool = False):
        """Initialize cross-platform emulator with automatic format detection.
        
        Args:
            path: Path to executable file (PE or ELF)
            verbose: Enable verbose debug logging
        """
        # Set up logging
        log.set_verbose(verbose)
        log.info(f"Initializing DumbEmu with {path}")
        
        # Load executable with appropriate loader
        self.loader = Factory.create(path)
        log.debug(f"Loader: {self.loader.format}, base=0x{self.loader.base:08X}, is_64={self.loader.is_64}")
        
        # Keep backward compatibility for Windows-only code
        if self.loader.format == "PE":
            self.pe = self.loader  # Alias for backward compatibility
        
        # Create context (now handles all platforms)
        self.ctx = Context(self.loader)
        self.uc = self.ctx.uc  # Keep for compatibility with existing code
        log.debug(f"Context created: {'x64' if self.ctx.is_64 else 'x86'}, platform={self.ctx.platform}")
        
        # Core components (platform-agnostic)
        self.mem = Mem(self.ctx)
        self.regs = Registers(self.ctx)
        self.stack = Stack(self.ctx)
        self.hooks = Hooks(self.ctx)
        self.alloc = Alloc(self.ctx, self.mem)
        log.debug("Core components initialized")
        
        # Extended components
        self.struct = Struct(self.mem)
        self.string = Strings(self.mem)
        self.tracer = Tracer(self.ctx)
        
        # Unified stub manager
        self.stubs = Stubs(self.ctx, self.mem, self.regs)
        
        # Platform-specific environment
        if self.ctx.platform == Platform.WINDOWS:
            self.tebpeb = TebPeb(self.ctx, self.mem)
            self.iat = self.stubs  # Compatibility alias
        elif self.ctx.platform == Platform.LINUX:
            self.auxv = AuxV(self.ctx, self.mem)
            self.plt = self.stubs  # Compatibility alias
        
        # Setup execution environment
        self._setup_environment()
    
    def _load_image(self) -> None:
        """Load executable sections into memory with proper protections."""
        # First, map each section individually with proper alignment
        for va, vsize, prot, data in self.loader.sections():
            # Map the section memory first
            self.mem.map(va, vsize, prot)
            
            # Write section data
            if data:
                self.mem.write(va, data[:vsize])
    
    def _setup_environment(self) -> None:
        """Setup complete execution environment based on platform."""
        # Map fake return address for stopping execution
        self.mem.map(align_down(self.ctx.fakeret), PAGE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        # Write a RET instruction at the fake return address
        self.mem.write(self.ctx.fakeret, b'\xC3')
        
        # Load executable image
        self._load_image()
        
        # Initialize platform-specific structures
        if self.ctx.platform == Platform.WINDOWS:
            self.tebpeb.seed(self.loader.base)
        elif self.ctx.platform == Platform.LINUX:
            sp = self.auxv.seed(self.loader.base, self.loader.entry_point)
            # Set the stack pointer
            self.regs.write(self.regs.sp, sp)
        
        # Setup import stubs for both platforms
        self._setup_stubs()
    
    def _setup_stubs(self) -> None:
        """Setup import stubs for Windows IAT or Linux PLT/GOT."""
        try:
            imports = self.loader.imports()
            self.stubs.attach(imports)
        except Exception as e:
            log.debug(f"No imports to stub or error loading imports: {e}")
        self.stubs.wire(self.hooks.add)
    
    def hook(self, addr: Addr, callback: HookCallback) -> None:
        """Add a code hook at specific address.
        
        Args:
            addr: Address to hook
            callback: Function to call when address is executed
        """
        self.hooks.add(addr, callback)
    
    def malloc(self, size: Size, prot: Prot = UC_PROT_READ | UC_PROT_WRITE) -> Addr:
        """Allocate memory region.
        
        Args:
            size: Size in bytes to allocate
            prot: Memory protection flags (default: RW)
            
        Returns:
            Base address of allocated region
        """
        return self.alloc.alloc(size, prot)
    
    def free(self, addr: Addr) -> bool:
        """Free allocated memory region.
        
        Args:
            addr: Base address of the allocation
            
        Returns:
            True if freed successfully, False if not found
        """
        return self.alloc.free(addr)
    
    def execute(self, addr: Addr, until: BreakAddr = None, count: Optional[InsnCount] = None,
                stack_guard: bool = False, code_cage: CodeCage = None) -> None:
        """Execute code at address without function call setup.
        
        Args:
            addr: Start address for execution
            until: Optional address to stop at (breakpoint)
            count: Optional instruction count limit (no default limit)
            stack_guard: Enable stack-depth watchdog
            code_cage: Optional (min_addr, max_addr) to restrict execution [min_addr, max_addr)
        """
        log.debug(f"execute: addr=0x{addr:08X}, until={f'0x{until:08X}' if until else 'None'}, count={count}")
        self._run(addr, until or 0, None, count, stack_guard, code_cage)
        log.debug(f"execute: finished")
    
    def call(self, addr: Addr, breakpoint: BreakAddr = None, *args: Any, 
             max_insns: InsnCount = DEFAULT_MAX_INSNS, stack_guard: bool = True,
             code_cage: CodeCage = None) -> int:
        """Call a function at given address with arguments.
        
        Args:
            addr: Function address to call
            breakpoint: Optional address to stop execution
            *args: Function arguments
            max_insns: Maximum instructions to execute (default: 1M, prevents infinite loops)
            stack_guard: Enable stack-depth watchdog
            code_cage: Optional (min_addr, max_addr) to restrict execution [min_addr, max_addr)
            
        Returns:
            Function return value
        """
        log.debug(f"call: addr=0x{addr:08X}, args={args}, breakpoint={f'0x{breakpoint:08X}' if breakpoint else 'None'}")
        sp = self.stack.init(self.mem, self.regs)
        sp = self.regs.prep(self.mem, sp, args, shadow=(self.ctx.platform == Platform.WINDOWS and self.ctx.is_64))
        self.regs.write(self.regs.sp, sp)
        
        # Verify SysV x64 alignment requirement
        if self.ctx.is_64 and self.ctx.conv == 'sysv64':
            assert (sp & 0xF) == 0, f"SysV x64: SP must be 16-byte aligned, got 0x{sp:08X}"
        
        log.debug(f"call: SP set to 0x{sp:08X}")
        self._run(addr, self.ctx.fakeret, breakpoint, max_insns, stack_guard, code_cage)
        ret = self.regs.retval()
        log.debug(f"call: returned 0x{ret:08X}")
        return ret
    
    def _stop_hook(self, uc, addr: int, size: int, user_data) -> None:
        """Hook callback for instruction-level stop conditions.
        
        Checks code cage bounds, stack limits, and breakpoints.
        Uses _run_state dict for context passed from _run.
        """
        self._run_state['insn_count'] += 1
        
        # Check code cage (half-open interval [min_addr, max_addr))
        code_cage = self._run_state.get('code_cage')
        if code_cage:
            min_addr, max_addr = code_cage
            if addr < min_addr or addr >= max_addr:
                log.warning(f"_run: Code cage violation at 0x{addr:08X} (cage: [0x{min_addr:08X}, 0x{max_addr:08X}))")
                raise EmuLimitError("code_cage", addr)
        
        # Check stack depth (half-open interval [stack_low, stack_high))
        if self._run_state.get('stack_guard'):
            stack_low = self._run_state.get('stack_low')
            stack_high = self._run_state.get('stack_high')
            if stack_low is not None:
                sp = self.regs.read(self.regs.sp)
                if not (stack_low <= sp < stack_high):
                    log.warning(f"_run: Stack depth violation: SP=0x{sp:08X} outside bounds [0x{stack_low:08X}, 0x{stack_high:08X})")
                    raise EmuLimitError("stack_depth", sp)
        
        # Check breakpoints
        stops = self._run_state.get('stops', set())
        if addr in stops:
            log.debug(f"_run: stopping at 0x{addr:08X}")
            uc.emu_stop()
    
    def _run(self, addr: int, retaddr: int, breakpoint: Optional[int], count: Optional[int],
             stack_guard: bool = True, code_cage: Optional[Tuple[int, int]] = None) -> None:
        """Execute emulation until stop condition.
        
        Args:
            addr: Start address
            retaddr: Address to stop execution at
            breakpoint: Optional breakpoint address
            count: Optional instruction count limit
            stack_guard: Enable stack-depth watchdog (stop if SP leaves stack region)
            code_cage: Optional (min_addr, max_addr) to cage execution [min_addr, max_addr)
            
        Raises:
            EmuLimitError: If instruction limit reached or stack/code bounds violated
            SegFaultError: If memory access violation occurs
            ExecutionError: For other execution errors
        """
        log.debug(f"_run: start=0x{addr:08X}, retaddr=0x{retaddr:08X}, count={count}")
        stops = set()  # Don't add retaddr here, will use as end address
        if breakpoint:
            stops.add(breakpoint)
            log.debug(f"_run: added breakpoint at 0x{breakpoint:08X}")
        
        # Initialize run state for hook method
        self._run_state = {
            'insn_count': 0,
            'stops': stops,
            'code_cage': code_cage,
            'stack_guard': stack_guard,
            'stack_low': None,
            'stack_high': None
        }
        
        # Get initial stack bounds for stack-depth watchdog
        if stack_guard:
            initial_sp = self.regs.read(self.regs.sp)
            # Stack grows down, so bounds are below initial SP
            stack_size = STACK_64 if self.ctx.is_64 else STACK_32
            stack_high = self.ctx.stack  # Stack top
            stack_low = stack_high - stack_size  # Stack bottom
            self._run_state['stack_low'] = stack_low
            self._run_state['stack_high'] = stack_high
            log.debug(f"_run: Stack guard enabled: SP=0x{initial_sp:08X}, bounds=0x{stack_low:08X}-0x{stack_high:08X}")
        
        h = self.uc.hook_add(UC_HOOK_CODE, self._stop_hook)
        try:
            kwargs = {'count': count} if count else {}
            log.debug(f"_run: starting emulation")
            # Use retaddr as the end address so emulation stops there
            self.uc.emu_start(addr, retaddr, **kwargs)
            log.debug(f"_run: emulation ended normally")
            
            # Only raise if we tried to execute MORE than count instructions
            # If we executed exactly count instructions and stopped, that's success
            if count and self._run_state['insn_count'] > count:
                raise EmuLimitError("instruction_count", count)
                
        except UcError as e:
            log.debug(f"_run: UcError: {e}")
            # Convert Unicorn errors to our exceptions
            if e.errno == UC_ERR_FETCH_UNMAPPED:
                ip = self.regs.read(self.regs.ip)
                raise SegFaultError(ip)
            else:
                raise ExecutionError(f"Emulation error: {e}")
        finally:
            try:
                self.uc.hook_del(h)
            except Exception:
                pass
            # Clean up run state
            self._run_state = None
    
    def stub(self, module: str, name: str, proto: Union[Proto, Symbol], cb: Callable) -> int:
        """Register a stub handler for an imported function.
        
        Args:
            module: Module/library name
            name: Function/symbol name
            proto: Function prototype (Proto for Windows, Symbol for Linux)
            cb: Callback to execute when stub is called
            
        Returns:
            Virtual address of the stub
        """
        va = self.stubs.register(module, name, proto, cb)
        self._setup_stubs()
        
        if self.ctx.platform not in (Platform.WINDOWS, Platform.LINUX):
            raise NotImplementedError(f"Stubbing not supported for platform: {self.ctx.platform}")
        
        return va
    
    def invoke(self, module: str, name: str, *args) -> int:
        """Call an imported function by name.
        
        Args:
            module: Module/library name
            name: Function/symbol name
            *args: Function arguments
            
        Returns:
            Function return value
        """
        if va := self.stubs.get_va(module, name):
            return self.call(va, None, *args)
        
        # Auto-create stub
        proto = Proto(name, self.ctx.conv, [])
        va = self.stubs.register(module, name, proto, lambda s, uc, a: 0)
        self._setup_stubs()
        
        if self.ctx.platform not in (Platform.WINDOWS, Platform.LINUX):
            raise NotImplementedError(f"Invoke not supported for platform: {self.ctx.platform}")
        
        return self.call(va, None, *args)
    
    def trace(self, addr: int, stop: Optional[int] = None, 
              count: Optional[int] = None) -> Tuple[List[int], int]:
        """Trace execution and collect executed addresses.
        
        Args:
            addr: Start address
            stop: Optional stop address
            count: Optional max instructions to execute
            
        Returns:
            Tuple of (addresses_list, instruction_count)
        """
        return self.tracer.run(addr, stop, count)
