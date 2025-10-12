"""PE file parsing and loading."""
import lief
from typing import List, Tuple
from ..utils.constants import to_prot
from ..utils.logger import log


class PE:
    """Portable Executable parser."""
    
    def __init__(self, path: str):
        """Load and parse PE file.
        
        Args:
            path: Path to PE file
        """
        self.path = path
        log.debug(f"PE: Loading {path}")
        self.bin = lief.PE.parse(path)
        self.base = int(self.bin.optional_header.imagebase)
        self.size = int(self.bin.optional_header.sizeof_image)
        
        # Detect bitness
        try:
            self.is_64 = (self.bin.optional_header.magic == lief.PE.PE_TYPE.PE32_PLUS)
        except Exception:
            self.is_64 = (self.bin.header.machine == lief.PE.MACHINE_TYPES.AMD64)
        
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
    
    def imports(self) -> List['Import']:
        """Get import table entries from PE.
        
        Returns:
            List of Import objects for each imported function
        """
        result = []
        try:
            for lib in self.bin.imports:
                mod = (lib.name or '').lower()
                for entry in lib.entries:
                    iat_rva = int(entry.iat_address or 0)
                    iat_va = self.base + iat_rva
                    
                    if entry.is_ordinal:
                        ordinal = int(entry.ordinal)
                        name = f"ord{ordinal}"
                    else:
                        ordinal = None
                        name = entry.name or 'unknown'
                    
                    result.append(Import(mod, name, iat_va, ordinal))
        except Exception:
            pass
        return result


class Import:
    """Import table entry."""
    
    def __init__(self, module: str, name: str, iat_va: int, ordinal: int | None = None):
        """Initialize import entry.
        
        Args:
            module: DLL module name
            name: Function name or ordinal string
            iat_va: IAT virtual address
            ordinal: Optional ordinal number
        """
        self.module = module
        self.name = name
        self.ordinal = ordinal
        self.iat_va = iat_va
