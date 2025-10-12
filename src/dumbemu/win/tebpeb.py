"""Windows TEB/PEB structure seeding."""
from __future__ import annotations
from ..utils.constants import PAGE, UC_X86_REG_GS_BASE, UC_X86_REG_FS_BASE, UC_PROT_READ, UC_PROT_WRITE, align_down

class TebPeb:
    """Minimal Windows Thread/Process Environment Block."""
    
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
        self.mem.map(align_down(self.teb), PAGE * 2, UC_PROT_READ | UC_PROT_WRITE)
        self.mem.map(align_down(self.peb), PAGE * 2, UC_PROT_READ | UC_PROT_WRITE)
        
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
        self.mem.pack(self.teb + teb_self, self.teb, bits=bits)  # TEB self-pointer
        self.mem.pack(self.teb + teb_peb, self.peb, bits=bits)   # PEB pointer
        self.mem.pack(self.peb + peb_base, image_base, bits=bits)  # ImageBase
        
        # Try to set segment base register
        if seg is not None:
            try:
                self.uc.reg_write(seg, self.teb)
            except Exception:
                pass
        else:
            # Fallback: plant at page 0
            self._low_page(teb_self, teb_peb)

    def _low_page(self, teb_self: int, teb_peb: int) -> None:
        """Fallback method to plant TEB/PEB pointers at page 0.
        
        Used when segment registers cannot be set directly.
        
        Args:
            teb_self: Offset for TEB self-pointer
            teb_peb: Offset for PEB pointer in TEB
        """
        try:
            self.mem.map(0, PAGE, UC_PROT_READ | UC_PROT_WRITE)
        except Exception:
            pass
        
        bits = self.ctx.bits
        self.mem.pack(teb_self, self.teb, bits=bits)
        self.mem.pack(teb_peb, self.peb, bits=bits)
