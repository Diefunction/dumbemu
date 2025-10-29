"""Memory management abstraction for Unicorn emulator."""
from __future__ import annotations
import struct
from typing import Dict
from ..utils.logger import log
from ..utils.constants import PAGE, MAX_STR, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, align_down, align_up

# Cache struct.Struct objects for performance
_STRUCT_CACHE = {
    8: struct.Struct("<B"),
    16: struct.Struct("<H"),
    32: struct.Struct("<I"),
    64: struct.Struct("<Q"),
}

class Mem:
    """Memory manager with automatic page alignment.
    
    Handles memory mapping, protection, and read/write operations
    with automatic page boundary alignment.
    """
    
    def __init__(self, ctx):
        self.uc = ctx.uc
        self._pages: Dict[int, int] = {}  # page -> prot
    
    @staticmethod
    def page_count(size: int) -> int:
        """Calculate number of pages needed for size."""
        return (size + PAGE - 1) // PAGE

    def is_mapped(self, addr: int) -> bool:
        """Return True if the page containing addr is currently mapped."""
        return align_down(addr) in self._pages

    def map(self, addr: int, size: int, prot: int = UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC) -> None:
        """Map memory region with automatic page alignment."""
        start = align_down(addr)
        end = align_up(addr + size)
        sz = max(PAGE, end - start)
        
        # Fast path: check if all pages are unmapped
        pages = list(range(start, start + sz, PAGE))
        unmapped = [p for p in pages if p not in self._pages]
        
        if len(unmapped) == len(pages):
            # All unmapped - do bulk mapping
            self.uc.mem_map(start, sz, prot)
            for p in pages:
                self._pages[p] = prot
            log.debug(f"Mem.map: 0x{start:08X}-0x{start+sz:08X} ({len(pages)} pages, {self._prot_str(prot)})")
            return
        
        # Slow path: some pages already mapped
        mapped_pages = []
        updated_pages = []
        for page in pages:
            if page not in self._pages:
                # New page - map it
                self.uc.mem_map(page, PAGE, prot)
                self._pages[page] = prot
                mapped_pages.append(page)
            elif self._pages[page] != prot:
                # Existing page with different perms - update protection
                self.uc.mem_protect(page, PAGE, prot)
                self._pages[page] = prot
                updated_pages.append(page)
        
        # Clean logging based on what was actually mapped/updated
        prot_str = self._prot_str(prot)
        if mapped_pages:
            if len(mapped_pages) == 1:
                log.debug(f"Mem.map: 0x{mapped_pages[0]:08X} ({prot_str})")
            elif len(mapped_pages) <= 4:
                for page in mapped_pages:
                    log.debug(f"Mem.map: 0x{page:08X} ({prot_str})")
            else:
                # For large mappings, show range summary
                log.debug(f"Mem.map: 0x{start:08X}-0x{start+sz:08X} ({len(mapped_pages)} pages, {prot_str})")
        
        if updated_pages:
            log.debug(f"Mem.map: Updated {len(updated_pages)} pages to {prot_str}")

    def _prot_str(self, prot: int) -> str:
        """Convert protection flags to readable string."""
        perms = []
        if prot & UC_PROT_READ:
            perms.append('R')
        if prot & UC_PROT_WRITE:
            perms.append('W')
        if prot & UC_PROT_EXEC:
            perms.append('X')
        return ''.join(perms) if perms else 'NONE'
    
    def protect(self, addr: int, size: int, prot: int) -> None:
        """Change memory protection flags."""
        start = align_down(addr)
        end = align_up(addr + size)
        aligned_size = end - start
        
        # Track unmapped pages for warning
        unmapped_pages = []
        for page in range(start, start + aligned_size, PAGE):
            if page not in self._pages:
                unmapped_pages.append(page)
        
        if unmapped_pages:
            log.warning(f"Mem.protect: Attempted to protect {len(unmapped_pages)} unmapped pages")
            # Only protect mapped pages
            for page in range(start, start + aligned_size, PAGE):
                if page in self._pages:
                    self.uc.mem_protect(page, PAGE, prot)
                    self._pages[page] = prot
        else:
            # All pages are mapped, can do bulk protect
            self.uc.mem_protect(start, aligned_size, prot)
            # Update internal tracking
            for page in range(start, start + aligned_size, PAGE):
                self._pages[page] = prot
        
        log.debug(f"Mem.protect: 0x{start:08X}-0x{start+aligned_size:08X} -> {self._prot_str(prot)}")

    def unmap(self, addr: int, size: int) -> None:
        """Unmap memory region."""
        start = align_down(addr)
        end = align_up(addr + size)
        sz = max(PAGE, end - start)
        
        for page in range(start, start + sz, PAGE):
            if page in self._pages:
                try:
                    self.uc.mem_unmap(page, PAGE)
                    del self._pages[page]
                except Exception:
                    pass

    def write(self, addr: int, data: bytes) -> None:
        """Write bytes to memory."""
        self.uc.mem_write(addr, data)

    def read(self, addr: int, size: int) -> bytes:
        """Read bytes from memory."""
        return self.uc.mem_read(addr, size)

    def pack(self, addr: int, value: int, bits: int = 32) -> None:
        """Pack value into memory (treats value as unsigned two's complement)."""
        # Mask to width to handle negative values properly
        mask = (1 << bits) - 1
        value = value & mask
        
        # Use cached struct objects for performance
        if bits in _STRUCT_CACHE:
            data = _STRUCT_CACHE[bits].pack(value)
        else:
            raise ValueError(f"Unsupported bit size: {bits}")
        self.write(addr, data)
    
    def unpack(self, addr: int, size: int) -> int:
        """Unpack value from memory."""
        data = self.read(addr, size)
        # Convert size to bits for cache lookup
        bits = size * 8
        if bits in _STRUCT_CACHE:
            return _STRUCT_CACHE[bits].unpack(data)[0]
        else:
            raise ValueError(f"Unsupported size for unpack: {size}")

    # String operations moved to Strings class to avoid duplication
