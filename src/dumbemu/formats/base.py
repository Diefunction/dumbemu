"""Abstract base class for executable loaders."""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Tuple, Optional


@dataclass
class Import:
    """Represents an imported function/symbol.
    
    Attributes:
        module: Module/library name (e.g., 'kernel32.dll', 'libc.so.6')
        name: Symbol/function name (e.g., 'GetProcAddress', 'printf')
        ordinal: Optional ordinal number for PE exports
        va: Virtual address of import entry (IAT/GOT slot)
    """
    module: str           # Module/library name
    name: str             # Symbol name
    ordinal: Optional[int]  # Optional ordinal number
    va: int               # Virtual address of import entry


class Loader(ABC):
    """Abstract base class for executable file loaders."""
    
    def __init__(self, path: str):
        """Initialize loader with file path.
        
        Args:
            path: Path to executable file
        """
        self.path = path
        self.base = 0
        self.size = 0
        self.is_64 = False
        self.entry_point = 0
    
    @abstractmethod
    def parse(self) -> None:
        """Parse the executable file format."""
        ...
    
    @abstractmethod
    def sections(self) -> List[Tuple[int, int, int, bytes]]:
        """Get section information.
        
        Returns:
            List of tuples containing:
            - va: Virtual address
            - size: Section size  
            - prot: Protection flags
            - data: Section raw data
        """
        ...
    
    @abstractmethod
    def imports(self) -> List[Import]:
        """Get import table entries.
        
        Returns:
            List of Import objects for each imported function
        """
        ...
    
    @abstractmethod
    def exports(self) -> List[Tuple[str, int]]:
        """Get export table entries.
        
        Returns:
            List of (name, address) tuples for exported functions
        """
        ...
    
    @property
    def format(self) -> str:
        """Get executable format name (PE, ELF, etc)."""
        return self.__class__.__name__.replace("Loader", "")
