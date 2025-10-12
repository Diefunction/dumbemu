"""Emulation context that encapsulates architecture-specific state."""
from __future__ import annotations
from typing import TYPE_CHECKING
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64
from .utils.constants import Addr

if TYPE_CHECKING:
    from .pe.loader import PE


class Context:
    """Encapsulates architecture-specific emulation context."""
    
    def __init__(self, pe: PE):
        self.is_64 = pe.is_64
        self.mode = UC_MODE_64 if self.is_64 else UC_MODE_32
        self.uc = Uc(UC_ARCH_X86, self.mode)
        
        # Store PE for reference
        self.pe = pe
    
    @property
    def fakeret(self) -> int:
        """Fake return address for stopping execution."""
        return Addr.FAKE_RET_64 if self.is_64 else Addr.FAKE_RET_32
    
    @property
    def conv(self) -> str:
        """Get calling convention for current architecture."""
        return 'win64' if self.is_64 else 'stdcall'
    
    @property
    def width(self) -> int:
        """Pointer width in bytes."""
        return 8 if self.is_64 else 4
    
    @property
    def bits(self) -> int:
        """Pointer width in bits."""
        return 64 if self.is_64 else 32
    
    @property
    def stack(self) -> int:
        """Stack base address."""
        return Addr.STACK_64 if self.is_64 else Addr.STACK_32
    
    @property
    def alloc(self) -> int:
        """Allocator base address."""
        return Addr.ALLOC_64 if self.is_64 else Addr.ALLOC_32
    
    @property
    def tramp(self) -> int:
        """Trampoline base address."""
        return Addr.TRAMPOLINE_64 if self.is_64 else Addr.TRAMPOLINE_32
    
    @property
    def teb(self) -> int:
        """TEB address."""
        return Addr.TEB_64 if self.is_64 else Addr.TEB_32
    
    @property
    def peb(self) -> int:
        """PEB address."""
        return Addr.PEB_64 if self.is_64 else Addr.PEB_32
