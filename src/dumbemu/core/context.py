"""Emulation context that encapsulates architecture-specific state."""
from __future__ import annotations
from typing import TYPE_CHECKING
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64
from ..utils.constants import Addr, Platform

if TYPE_CHECKING:
    from ..formats.base import Loader


class Context:
    """Architecture-specific emulation context.
    
    Manages CPU mode, calling conventions, and memory layout
    for the target architecture (x86/x64) and platform.
    """
    
    def __init__(self, loader: 'Loader'):
        self.is_64 = loader.is_64
        self.mode = UC_MODE_64 if self.is_64 else UC_MODE_32
        self.uc = Uc(UC_ARCH_X86, self.mode)
        
        # Store loader for reference
        self.loader = loader
        self.platform = self._detect_platform()
    
    @property
    def fakeret(self) -> int:
        """Fake return address for stopping execution.
        
        Returns:
            Magic address that triggers emulation stop.
        """
        return Addr.FAKE_RET_64 if self.is_64 else Addr.FAKE_RET_32
    
    def _detect_platform(self) -> str:
        """Detect platform from loader type."""
        fmt = self.loader.format.upper()
        if fmt == "PE":
            return Platform.WINDOWS
        elif fmt == "ELF":
            return Platform.LINUX
        else:
            return Platform.UNKNOWN
    
    @property
    def conv(self) -> str:
        """Get calling convention for current architecture."""
        if self.platform == Platform.WINDOWS:
            return 'win64' if self.is_64 else 'stdcall'
        else:
            return 'sysv64' if self.is_64 else 'cdecl'
    
    @property
    def ptr_size(self) -> int:
        """Pointer size in bytes."""
        return 8 if self.is_64 else 4
    
    @property
    def width(self) -> int:
        """Pointer width in bytes (deprecated, use ptr_size)."""
        return self.ptr_size
    
    @property
    def ptr_bits(self) -> int:
        """Pointer size in bits."""
        return 64 if self.is_64 else 32
    
    @property
    def bits(self) -> int:
        """Pointer width in bits (deprecated, use ptr_bits)."""
        return self.ptr_bits
    
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
        """TEB address (Windows only)."""
        if self.platform == Platform.WINDOWS:
            return Addr.TEB_64 if self.is_64 else Addr.TEB_32
        return 0
    
    @property
    def peb(self) -> int:
        """PEB address (Windows only)."""
        if self.platform == Platform.WINDOWS:
            return Addr.PEB_64 if self.is_64 else Addr.PEB_32
        return 0
    
    @property
    def has_teb(self) -> bool:
        """Check if platform has TEB/PEB structures."""
        return self.platform == Platform.WINDOWS
