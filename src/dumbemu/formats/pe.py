"""Windows PE file parsing and loading."""
from __future__ import annotations
import lief
from typing import List, Tuple
from .base import Loader, Import
from .utils import pe_is_64, norm_mod, ord_name
from ..utils.constants import to_prot
from ..utils.logger import log


class PE(Loader):
    """Windows Portable Executable (PE) loader.
    
    Parses PE files and provides access to sections,
    imports, exports, and metadata.
    """
    
    def __init__(self, path: str):
        """Initialize PE loader.
        
        Args:
            path: Path to PE file
        """
        super().__init__(path)
        self.bin = None
        
    def parse(self) -> None:
        """Parse PE file format."""
        log.debug(f"PE: Loading {self.path}")
        self.bin = lief.PE.parse(self.path)
        
        self.base = int(self.bin.optional_header.imagebase)
        self.size = int(self.bin.optional_header.sizeof_image)
        self.entry_point = self.base + int(self.bin.optional_header.addressof_entrypoint)
        
        # Detect bitness
        self.is_64 = pe_is_64(self.bin)
        
        log.debug(f"PE: base=0x{self.base:08X}, size=0x{self.size:X}, is_64={self.is_64}")
    
    def sections(self) -> List[Tuple[int, int, int, bytes]]:
        """Get PE section information.
        
        Returns:
            List of tuples containing:
            - va: Virtual address
            - size: Section size
            - prot: Protection flags
            - data: Section raw data
        """
        result = []
        for s in self.bin.sections:
            va = self.base + int(s.virtual_address)
            vsize = int(s.virtual_size or len(s.content))
            size = max(vsize, len(s.content))
            data = bytes(s.content) if s.content else b""
            prot = to_prot(int(s.characteristics))
            result.append((va, size, prot, data))
        return result
    
    def imports(self) -> List[Import]:
        """Get import table entries from PE.
        
        Returns:
            List of Import objects for each imported function
        """
        result = []
        try:
            for lib in self.bin.imports:
                module = norm_mod(lib.name or '')
                for entry in lib.entries:
                    iat_rva = int(entry.iat_address or 0)
                    iat_va = self.base + iat_rva
                    
                    if entry.is_ordinal:
                        ordinal = int(entry.ordinal)
                        name = ord_name(ordinal)
                    else:
                        ordinal = None
                        name = entry.name or 'unknown'
                    
                    result.append(Import(module, name, ordinal, iat_va))
        except (AttributeError, RuntimeError) as e:
            # LIEF may not have imports or they may be malformed
            log.debug(f"PE.imports: Could not parse imports: {e}")
        return result
    
    def exports(self) -> List[Tuple[str, int]]:
        """Get export table entries from PE.
        
        Returns:
            List of (name, address) tuples for exported functions
        """
        result = []
        try:
            for exp in self.bin.exports:
                if exp.name:
                    addr = self.base + int(exp.address)
                    result.append((exp.name, addr))
        except (AttributeError, RuntimeError) as e:
            # LIEF may not have exports or they may be malformed
            log.debug(f"PE.exports: Could not parse exports: {e}")
        return result


# Alias for compatibility
PELoader = PE  # Keep long name available
