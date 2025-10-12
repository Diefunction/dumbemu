"""String operations for memory."""
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..mem.memory import Mem


class Strings:
    """Handle string operations in memory."""
    
    def __init__(self, mem: Mem):
        """Initialize with memory manager.
        
        Args:
            mem: Memory manager instance
        """
        self.mem = mem
    
    def read(self, addr: int, max_len: int = 4096, wide: bool = False) -> str:
        """Read null-terminated string from memory.
        
        Args:
            addr: String address
            max_len: Maximum characters to read
            wide: If True, read UTF-16, else ASCII
            
        Returns:
            Decoded string
        """
        if wide:
            return self.wstring(addr, max_len)
        else:
            return self.cstring(addr, max_len)
    
    def write(self, addr: int, text: str, wide: bool = False, 
              null: bool = True) -> int:
        """Write string to memory.
        
        Args:
            addr: Target address
            text: String to write
            wide: If True, write UTF-16, else ASCII
            null: If True, add null terminator
            
        Returns:
            Number of bytes written
        """
        if wide:
            return self.wide(addr, text, null)
        else:
            return self.ascii(addr, text, null)
    
    def cstring(self, addr: int, max_len: int = 4096) -> str:
        """Read null-terminated ASCII string.
        
        Args:
            addr: String address
            max_len: Maximum characters to read
            
        Returns:
            Decoded ASCII string
        """
        return self._read(addr, max_len, 1, "ascii")
    
    def wstring(self, addr: int, max_len: int = 4096) -> str:
        """Read null-terminated UTF-16 wide string.
        
        Args:
            addr: String address
            max_len: Maximum characters to read
            
        Returns:
            Decoded UTF-16 string
        """
        return self._read(addr, max_len, 2, "utf-16le")
    
    def _read(self, addr: int, max_len: int, width: int, encoding: str) -> str:
        """Generic string reading helper.
        
        Args:
            addr: String address
            max_len: Maximum characters to read
            width: Character width in bytes (1 for ASCII, 2 for UTF-16)
            encoding: Text encoding to use
            
        Returns:
            Decoded string
        """
        if max_len <= 0:
            return ""
        
        term = b"\x00" * width
        out = bytearray()
        
        for _ in range(max_len):
            ch = self.mem.read(addr, width)
            if ch == term:
                break
            out += ch
            addr += width
        
        return out.decode(encoding, errors="replace")
    
    def ascii(self, addr: int, text: str, null: bool = True) -> int:
        """Write ASCII string to memory.
        
        Args:
            addr: Target address
            text: String to write
            null: If True, add null terminator
            
        Returns:
            Number of bytes written
        """
        data = text.encode('ascii', errors='replace')
        if null:
            data += b'\x00'
        self.mem.write(addr, data)
        return len(data)
    
    def wide(self, addr: int, text: str, null: bool = True) -> int:
        """Write UTF-16 wide string to memory.
        
        Args:
            addr: Target address
            text: String to write
            null: If True, add null terminator
            
        Returns:
            Number of bytes written
        """
        data = text.encode('utf-16le')
        if null:
            data += b'\x00\x00'
        self.mem.write(addr, data)
        return len(data)
