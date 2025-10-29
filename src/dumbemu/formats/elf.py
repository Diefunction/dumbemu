"""Linux ELF file parsing and loading."""
from __future__ import annotations
import lief
from typing import List, Tuple, Optional
from .base import Loader, Import
from .utils import elf_is_64, elf_prot, norm_mod
from ..utils.constants import Addr
from ..utils.logger import log


class ELF(Loader):
    """Linux Executable and Linkable Format (ELF) loader.
    
    Parses ELF files and provides access to segments,
    dynamic symbols, and relocation information.
    """
    
    def __init__(self, path: str):
        """Initialize ELF loader.
        
        Args:
            path: Path to ELF file
        """
        super().__init__(path)
        self.bin = None
        
    def parse(self) -> None:
        """Parse ELF file format."""
        log.debug(f"ELF: Loading {self.path}")
        self.bin = lief.ELF.parse(self.path)
        
        # Detect bitness
        self.is_64 = elf_is_64(self.bin)
        
        # Determine base address (PIE vs non-PIE)
        if self.bin.is_pie:
            self.base = Addr.PIE_BASE_64 if self.is_64 else Addr.PIE_BASE_32
        else:
            # Use the lowest segment address
            # PT_LOAD has value 1
            segs = [s for s in self.bin.segments if s.type == 1]
            if segs:
                self.base = min(int(s.virtual_address) for s in segs)
            else:
                self.base = Addr.ELF_BASE_64 if self.is_64 else Addr.ELF_BASE_32
        
        # Calculate size from segments
        if segs := [s for s in self.bin.segments if s.type == 1]:
            max_addr = max(int(s.virtual_address + s.virtual_size) for s in segs)
            self.size = max_addr - self.base
        else:
            self.size = 0x100000  # Default size (1MB)
        
        # Entry point
        self.entry_point = self.base + int(self.bin.header.entrypoint)
        
        log.debug(f"ELF: base=0x{self.base:08X}, size=0x{self.size:X}, is_64={self.is_64}")
    
    def sections(self) -> List[Tuple[int, int, int, bytes]]:
        """Get ELF segment information.
        
        Returns:
            List of tuples containing:
            - va: Virtual address
            - size: Section size
            - prot: Protection flags
            - data: Section raw data
        """
        result = []
        for seg in self.bin.segments:
            if seg.type != 1:  # PT_LOAD = 1
                continue
                
            va = self.base + int(seg.virtual_address)
            size = int(seg.virtual_size)
            data = bytes(seg.content) if seg.content else b""
            
            # Convert ELF flags to unicorn protection
            flags = int(seg.flags) if hasattr(seg, 'flags') else 7
            prot = elf_prot(flags)
            
            result.append((va, size, prot, data))
        return result
    
    def imports(self) -> List[Import]:
        """Get import table entries from ELF.
        
        Returns:
            List of Import objects for each imported function
        """
        result = []
        
        # Process dynamic symbols (imports from shared libraries)
        for sym in self.bin.dynamic_symbols:
            if sym.is_imported and sym.name:
                # Get library name from version info or use default
                module = "libc.so.6"  # Default library
                if sym.has_version:
                    ver = sym.symbol_version
                    if ver and hasattr(ver, 'symbol_version_auxiliary'):
                        aux = ver.symbol_version_auxiliary
                        if aux and aux.name:
                            module = aux.name
                
                module = norm_mod(module)
                
                # Calculate PLT/GOT address
                got_addr = 0
                if hasattr(sym, 'got_address'):
                    got_addr = self.base + int(sym.got_address)
                elif self.bin.has_section('.got.plt'):
                    # Estimate GOT entry based on symbol index
                    got_plt = self.bin.get_section('.got.plt')
                    if got_plt:
                        idx = sym.symbol_index if hasattr(sym, 'symbol_index') else 0
                        got_addr = self.base + int(got_plt.virtual_address) + (idx * 8)
                
                result.append(Import(
                    module=module,
                    name=sym.name,
                    ordinal=None,
                    va=got_addr
                ))
        
        return result
    
    def exports(self) -> List[Tuple[str, int]]:
        """Get export table entries from ELF.
        
        Returns:
            List of (name, address) tuples for exported functions
        """
        result = []
        
        # Process exported dynamic symbols
        for sym in self.bin.dynamic_symbols:
            if sym.is_exported and sym.name and sym.value:
                addr = self.base + int(sym.value)
                result.append((sym.name, addr))
        
        # Also check static symbols if available
        for sym in self.bin.static_symbols:
            if sym.is_function and sym.name and sym.value:
                addr = self.base + int(sym.value)
                result.append((sym.name, addr))
        
        return result
    
    def relocations(self) -> List[Tuple[int, str, int]]:
        """Get relocation entries.
        
        Returns:
            List of (address, type, symbol) tuples
        """
        result = []
        for reloc in self.bin.relocations:
            addr = self.base + int(reloc.address)
            rtype = str(reloc.type)
            symbol = reloc.symbol.name if reloc.has_symbol else ""
            result.append((addr, rtype, symbol))
        return result


# Aliases for compatibility
ELFLoader = ELF  # Keep long name available
