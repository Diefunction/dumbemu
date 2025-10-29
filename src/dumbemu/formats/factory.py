"""Factory for creating executable loaders based on file format."""
from __future__ import annotations
import os
import struct
from typing import Optional, Literal
from .base import Loader


class Factory:
    """Factory for automatic executable format detection and loader creation.
    
    Detects PE/ELF format and instantiates the appropriate loader.
    """
    
    @staticmethod
    def create(path: str) -> Loader:
        """Create appropriate loader based on file format detection.
        
        Args:
            path: Path to executable file
            
        Returns:
            Appropriate loader instance
            
        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file format is not supported
        """
        fmt = Factory.detect(path)
        
        if fmt == "PE":
            from .pe import PE
            loader = PE(path)
        elif fmt == "ELF":
            from .elf import ELF
            loader = ELF(path)
        elif fmt is None:
            raise ValueError(f"Unknown executable format for file: {path}")
        else:
            raise ValueError(f"Unsupported executable format: {fmt}")
        
        loader.parse()
        return loader
    
    @staticmethod
    def detect(path: str) -> Optional[Literal["PE", "ELF"]]:
        """Detect executable file format.
        
        Args:
            path: Path to executable file
            
        Returns:
            "PE" or "ELF" if recognized, None if unknown
        
        Raises:
            FileNotFoundError: If file doesn't exist
        """
        if not os.path.exists(path):
            raise FileNotFoundError(f"File not found: {path}")
        
        with open(path, 'rb') as f:
            magic = f.read(4)
            
            # Check for ELF magic
            if magic == b'\x7fELF':
                return "ELF"
            
            # Check for PE/DOS MZ header
            if magic[:2] == b'MZ':
                # Read PE offset
                f.seek(0x3C)
                pe_offset = struct.unpack('<I', f.read(4))[0]
                
                # Check PE signature
                f.seek(pe_offset)
                if f.read(4) == b'PE\x00\x00':
                    return "PE"
                    
        return None
