"""Structure packing and unpacking operations."""
from __future__ import annotations
import struct as _struct
from typing import Tuple, Any, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from ..mem.memory import Mem

from .strings import Strings

class Struct:
    """Handle structured data in memory."""
    
    def __init__(self, mem: Mem):
        """Initialize with memory manager.
        
        Args:
            mem: Memory manager instance
        """
        self.mem = mem
        self.strings = Strings(mem)
    
    def pack(self, addr: int, *fields: Tuple[int, Any, str]) -> None:
        """Write structured data to memory.
        
        Args:
            addr: Base address
            *fields: Tuples of (offset, value, fmt)
                    fmt: 'B'=uint8, 'H'=uint16, 'I'=uint32, 'Q'=uint64
                         's'=string, 'ws'=wide string
        
        Example:
            struct.pack(addr,
                (0x00, 0x1234, 'H'),     # uint16 at offset 0
                (0x04, 0xDEADBEEF, 'I'), # uint32 at offset 4
                (0x08, b'test\\x00', 's') # string at offset 8
            )
        """
        for off, val, fmt in fields:
            target_addr = addr + off
            if fmt == 's':
                # ASCII string - use Strings class for consistency
                if isinstance(val, str):
                    self.strings.ascii(target_addr, val, null=False)
                elif isinstance(val, bytes):
                    self.mem.write(target_addr, val)
            elif fmt == 'ws':
                # Wide string - use Strings class for consistency
                if isinstance(val, str):
                    self.strings.wide(target_addr, val, null=False)
                elif isinstance(val, bytes):
                    self.mem.write(target_addr, val)
            else:
                # Numeric types
                self.mem.write(target_addr, _struct.pack(f'<{fmt}', val))
    
    def unpack(self, addr: int, *fields: Tuple[int, str]) -> Dict[int, Any]:
        """Read structured data from memory.
        
        Args:
            addr: Base address
            *fields: Tuples of (offset, fmt)
                    fmt: 'B'=uint8, 'H'=uint16, 'I'=uint32, 'Q'=uint64
                         's'=string, 'ws'=wide string
        
        Returns:
            Dictionary with offset as key
        
        Example:
            data = struct.unpack(addr,
                (0x00, 'H'),  # uint16 at offset 0
                (0x04, 'I'),  # uint32 at offset 4
                (0x08, 's')   # string at offset 8
            )
        """
        result = {}
        for off, fmt in fields:
            target_addr = addr + off
            if fmt == 's':
                # ASCII string
                result[off] = self.strings.cstring(target_addr)
            elif fmt == 'ws':
                # Wide string
                result[off] = self.strings.wstring(target_addr)
            else:
                # Numeric types
                size = _struct.calcsize(fmt)
                data = self.mem.read(target_addr, size)
                result[off] = _struct.unpack(f'<{fmt}', data)[0]
        return result
    
    def write(self, addr: int, fmt: str, *values: Any) -> int:
        """Write values in format to memory.
        
        Args:
            addr: Target address
            fmt: Struct format string (e.g., 'IHH' for uint32, uint16, uint16)
            *values: Values to write
            
        Returns:
            Number of bytes written
            
        Example:
            struct.write(addr, 'IHH', 0x1234, 0x56, 0x78)
        """
        data = _struct.pack(f'<{fmt}', *values)
        self.mem.write(addr, data)
        return len(data)
    
    def read(self, addr: int, fmt: str) -> Tuple[Any, ...]:
        """Read values in format from memory.
        
        Args:
            addr: Source address
            fmt: Struct format string
            
        Returns:
            Tuple of unpacked values
            
        Example:
            val1, val2, val3 = struct.read(addr, 'IHH')
        """
        size = _struct.calcsize(f'<{fmt}')
        data = self.mem.read(addr, size)
        return _struct.unpack(f'<{fmt}', data)
    
    def size(self, fmt: str) -> int:
        """Get size of struct format.
        
        Args:
            fmt: Struct format string
            
        Returns:
            Size in bytes
        """
        return _struct.calcsize(fmt)
    
    def iter(self, addr: int, fmt: str, count: int) -> list:
        """Read array of structs from memory.
        
        Args:
            addr: Start address
            fmt: Struct format for each element
            count: Number of elements
            
        Returns:
            List of unpacked tuples
            
        Example:
            # Read 10 DWORDs
            values = struct.iter(addr, 'I', 10)
        """
        size = _struct.calcsize(fmt)
        result = []
        for i in range(count):
            data = self.mem.read(addr + i * size, size)
            result.append(_struct.unpack(f'<{fmt}', data))
        return result
