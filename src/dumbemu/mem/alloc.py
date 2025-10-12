"""Virtual memory allocator for dynamic memory management."""
from __future__ import annotations
from typing import Dict
from ..utils.constants import PAGE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from ..utils.logger import log
from .memory import Mem

class Alloc:
    """Simple page-aligned memory allocator."""
    
    def __init__(self, ctx, mem: Mem):
        self.mem = mem
        self.base = ctx.alloc
        self.cursor = self.base
        self.allocs: Dict[int, int] = {}  # addr -> size

    def alloc(self, size: int, prot: int = UC_PROT_READ | UC_PROT_WRITE) -> int:
        """Allocate a page-aligned memory region.
        
        Args:
            size: Size in bytes (will be rounded up to page size)
            prot: Memory protection flags (default: RW)
            
        Returns:
            Base address of allocated region
        """
        if size <= 0:
            size = PAGE
        
        # Use Mem's page calculation helper
        pages = self.mem.page_count(size)
        sz = pages * PAGE
        addr = self.cursor
        
        self.mem.map(addr, sz, prot)
        self.allocs[addr] = sz
        self.cursor += sz
        log.debug(f"Alloc: 0x{addr:08X} ({sz:#x} bytes)")
        return addr

    def protect(self, addr: int, size: int, prot: int) -> bool:
        """Change memory protection of an allocated region.
        
        Args:
            addr: Address within the allocated region
            size: Size of region to protect
            prot: New protection flags
            
        Returns:
            True if region found and protected, False otherwise
        """
        for base, sz in self.allocs.items():
            if base <= addr < base + sz:
                end = min(addr + size, base + sz)
                self.mem.protect(addr, end - addr, prot)
                return True
        return False

    def free(self, addr: int) -> bool:
        """Free a previously allocated memory region.
        
        Args:
            addr: Base address of the allocation
            
        Returns:
            True if freed successfully, False if not found
        """
        if sz := self.allocs.pop(addr, None):
            self.mem.unmap(addr, sz)
            log.debug(f"Alloc.free: 0x{addr:08X} ({sz:#x} bytes)")
            return True
        log.warn(f"Alloc.free: 0x{addr:08X} not found")
        return False
