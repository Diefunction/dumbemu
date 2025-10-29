"""Memory mapping utilities for section loading.

Provides helpers for common mapping patterns without
redundant zero-fill operations.
"""
from __future__ import annotations
from typing import Optional, TYPE_CHECKING
from ..utils.constants import PAGE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, align_down, align_up
from ..utils.logger import log

if TYPE_CHECKING:
    from .memory import Mem
    from ..types import Addr, Size, Prot, Data
    

class MappingHelper:
    """Helper utilities for memory mapping operations.
    
    Encapsulates common patterns for mapping and loading
    sections into memory efficiently.
    """
    
    def __init__(self, mem: "Mem"):
        """Initialize mapping helper.
        
        Args:
            mem: Memory manager instance
        """
        self.mem = mem
        
    def map_and_write(self, base: Addr, size: Size, prot: Prot, data: Optional[Data] = None) -> None:
        """Map memory region and optionally write data.
        
        Maps pages as needed and writes data if provided.
        No redundant zero-filling since Unicorn zeros mapped memory.
        
        Args:
            base: Base address to map
            size: Size of region in bytes
            prot: Protection flags
            data: Optional data to write
        """
        # Map the region
        self.mem.map(base, size, prot)
        
        # Write data if provided (no zero-fill needed)
        if data:
            write_size = min(len(data), size)
            self.mem.write(base, data[:write_size])
            log.debug(f"MappingHelper: Wrote {write_size} bytes to 0x{base:08X}")
    
    def map_section(self, va: Addr, vsize: Size, file_size: Size, prot: Prot, data: Optional[Data] = None) -> None:
        """Map a section with virtual and file sizes.
        
        Common pattern for PE/ELF sections where virtual size
        may exceed file size (e.g., .bss sections).
        
        Args:
            va: Virtual address  
            vsize: Virtual size (memory size)
            file_size: File size (data size)
            prot: Protection flags
            data: Optional section data
        """
        # Map full virtual size
        self.mem.map(va, vsize, prot)
        
        # Write available data (Unicorn already zeroed the rest)
        if data and file_size > 0:
            write_size = min(len(data), file_size, vsize)
            self.mem.write(va, data[:write_size])
            log.debug(f"MappingHelper: Section at 0x{va:08X}: wrote {write_size}/{vsize} bytes")
    
    def map_pages_exact(self, base: Addr, pages: int, prot: Prot = UC_PROT_READ | UC_PROT_WRITE) -> None:
        """Map exact number of pages.
        
        Args:
            base: Base address (will be aligned down)
            pages: Number of pages to map
            prot: Protection flags
        """
        aligned_base = align_down(base)
        size = pages * PAGE
        self.mem.map(aligned_base, size, prot)
        log.debug(f"MappingHelper: Mapped {pages} pages at 0x{aligned_base:08X}")
    
    def ensure_mapped(self, addr: Addr, size: Size, prot: Prot = UC_PROT_READ | UC_PROT_WRITE) -> bool:
        """Ensure a region is mapped, map if not.
        
        Args:
            addr: Address to check
            size: Size of region
            prot: Protection if mapping needed
            
        Returns:
            True if newly mapped, False if already mapped
        """
        start = align_down(addr)
        end = align_up(addr + size)
        
        # Check if any pages need mapping (avoid touching Mem internals)
        newly_mapped = False
        for page in range(start, end, PAGE):
            if not self.mem.is_mapped(page):
                self.mem.map(page, PAGE, prot)
                newly_mapped = True
                
        return newly_mapped
    
    def copy_region(self, src: Addr, dst: Addr, size: Size) -> None:
        """Copy memory region to another location.
        
        Args:
            src: Source address
            dst: Destination address  
            size: Number of bytes to copy
        """
        data = self.mem.read(src, size)
        self.mem.write(dst, data)
        log.debug(f"MappingHelper: Copied {size} bytes from 0x{src:08X} to 0x{dst:08X}")
    
    def fill_region(self, base: Addr, size: Size, value: int = 0) -> None:
        """Fill memory region with a value.
        
        Args:
            base: Base address
            size: Size in bytes
            value: Byte value to fill (0-255)
        """
        data = bytes([value & 0xFF]) * size
        self.mem.write(base, data)
        log.debug(f"MappingHelper: Filled {size} bytes at 0x{base:08X} with 0x{value:02X}")


def map_zeroed(mem: "Mem", base: Addr, size: Size, prot: Prot = UC_PROT_READ | UC_PROT_WRITE) -> None:
    """Map zeroed memory region (convenience function).
    
    Args:
        mem: Memory manager
        base: Base address
        size: Size in bytes
        prot: Protection flags
    """
    # Unicorn already zeros mapped memory
    mem.map(base, size, prot)


def map_and_load(mem: "Mem", base: Addr, data: Data, prot: Prot = UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC) -> None:
    """Map memory and load data (convenience function).
    
    Args:
        mem: Memory manager
        base: Base address
        data: Data to load
        prot: Protection flags
    """
    mem.map(base, len(data), prot)
    mem.write(base, data)
