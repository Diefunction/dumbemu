"""Windows TEB/PEB structure initialization."""
from __future__ import annotations
from ...formats.utils import map_env, write_ptr_array
from ...utils.constants import UC_X86_REG_GS_BASE, UC_X86_REG_FS_BASE
from ...utils.logger import log

class TebPeb:
    """Windows Thread and Process Environment Block structures.
    
    Initializes minimal TEB/PEB structures required for
    Windows PE executables to detect their environment.
    """
    
    def __init__(self, ctx, mem) -> None:
        self.ctx = ctx
        self.uc = ctx.uc
        self.mem = mem
        self.teb = ctx.teb
        self.peb = ctx.peb

    def seed(self, base: int) -> None:
        """Initialize Windows TEB/PEB structures in memory.
        
        Args:
            base: Image base address to store in PEB
        """
        # Map TEB and PEB pages
        map_env(self.mem, self.teb, 2)
        map_env(self.mem, self.peb, 2)
        
        # Write BeingDebugged flag
        self.mem.write(self.peb + 2, b'\x00')
        
        if self.ctx.is_64:
            # 64-bit layout
            self._write(0x30, 0x60, 0x10, base, UC_X86_REG_GS_BASE)
        else:
            # 32-bit layout  
            self._write(0x18, 0x30, 0x08, base, UC_X86_REG_FS_BASE)
    
    def _write(self, teb_self: int, teb_peb: int, peb_base: int, image_base: int, seg: int) -> None:
        """Helper to write TEB/PEB structures and set segment register.
        
        Args:
            teb_self: TEB offset for self-pointer
            teb_peb: TEB offset for PEB pointer
            peb_base: PEB offset for ImageBase
            image_base: Image base address
            seg: Segment register to set (FS/GS)
        """
        bits = self.ctx.bits
        
        # Write TEB and PEB pointers
        write_ptr_array(self.mem, [
            (self.teb + teb_self, self.teb),     # TEB self-pointer
            (self.teb + teb_peb, self.peb),      # PEB pointer
            (self.peb + peb_base, image_base),   # ImageBase
        ], bits)
        
        # Try to set segment base register if available
        if seg is not None:
            try:
                self.uc.reg_write(seg, self.teb)
                log.debug(f"TebPeb: Set segment base register to 0x{self.teb:08X}")
            except Exception as e:
                log.debug(f"TebPeb: Failed to set segment base: {e}")
                # Fallback behavior
                self._low_page(teb_self, teb_peb)
        else:
            # Segment registers not available in this Unicorn build
            log.warning("TebPeb: FS/GS base registers not available in this Unicorn build")
            self._low_page(teb_self, teb_peb)

    def _low_page(self, teb_self: int, teb_peb: int) -> None:
        """Fallback method when segment registers cannot be set directly.
        
        No longer maps page 0 to avoid hiding null pointer bugs.
        
        Args:
            teb_self: Offset for TEB self-pointer (unused)
            teb_peb: Offset for PEB pointer in TEB (unused)
        """
        # Don't map page 0 - it hides null pointer bugs
        log.debug("TebPeb._low_page: Segment registers not available, TEB/PEB access may fail")
