"""Memory abstraction layer for Unicorn emulator."""
from __future__ import annotations
import struct
from typing import Dict
from ..utils.logger import log
from ..utils.constants import PAGE, MAX_STR, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, align_down, align_up

class Mem:
    """Memory manager with automatic page alignment and tracking."""
    
    def __init__(self, ctx):
        self.uc = ctx.uc
        self._pages: Dict[int, int] = {}  # page -> prot
    
    # Use align_down and align_up from constants module
    align_down = staticmethod(align_down)
    align_up = staticmethod(align_up)
    
    @staticmethod
    def page_count(size: int) -> int:
        """Calculate number of pages needed for size."""
        return (size + PAGE - 1) // PAGE

    def map(self, addr: int, size: int, prot: int = UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC) -> None:
        """Map memory region with automatic page alignment."""
        start = self.align_down(addr)
        end = self.align_up(addr + size)
        sz = max(PAGE, end - start)
        
        mapped_pages = []
        for page in range(start, start + sz, PAGE):
            if page not in self._pages:
                self.uc.mem_map(page, PAGE, prot)
                self._pages[page] = prot
                mapped_pages.append(page)
        
        # Clean logging based on what was actually mapped
        if mapped_pages:
            prot_str = self._prot_str(prot)
            if len(mapped_pages) == 1:
                log.debug(f"Mem.map: 0x{mapped_pages[0]:08X} ({prot_str})")
            elif len(mapped_pages) <= 4:
                for page in mapped_pages:
                    log.debug(f"Mem.map: 0x{page:08X} ({prot_str})")
            else:
                # For large mappings, show range summary
                log.debug(f"Mem.map: 0x{start:08X}-0x{start+sz:08X} ({len(mapped_pages)} pages, {prot_str})")

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
        start = self.align_down(addr)
        end = self.align_up(addr + size)
        aligned_size = end - start
        self.uc.mem_protect(start, aligned_size, prot)
        log.debug(f"Mem.protect: 0x{start:08X}-0x{start+aligned_size:08X} -> {self._prot_str(prot)}")

    def unmap(self, addr: int, size: int) -> None:
        """Unmap memory region."""
        start = self.align_down(addr)
        end = self.align_up(addr + size)
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
        """Pack value into memory."""
        if bits == 64:
            data = struct.pack("<Q", value)
        elif bits == 32:
            data = struct.pack("<I", value)
        elif bits == 16:
            data = struct.pack("<H", value)
        elif bits == 8:
            data = struct.pack("<B", value)
        else:
            raise ValueError(f"Unsupported bit size: {bits}")
        self.write(addr, data)
    
    def unpack(self, addr: int, size: int) -> int:
        """Unpack value from memory."""
        data = self.read(addr, size)
        if size == 8:
            return struct.unpack("<Q", data)[0]
        elif size == 4:
            return struct.unpack("<I", data)[0]
        elif size == 2:
            return struct.unpack("<H", data)[0]
        elif size == 1:
            return struct.unpack("<B", data)[0]
        else:
            raise ValueError(f"Unsupported size for unpack: {size}")

    # String operations moved to Strings class to avoid duplication
