"""String read/write operations for memory."""
from __future__ import annotations
from typing import TYPE_CHECKING
from ..utils.constants import MAX_STR
from ..utils.logger import log

if TYPE_CHECKING:
    from ..mem.memory import Mem


class Strings:
    """String operations for reading/writing ASCII and Unicode strings.
    
    Handles null-terminated C strings and UTF-16 wide strings
    commonly found in Windows and Linux executables.
    """
    
    def __init__(self, mem: Mem):
        """Initialize with memory manager.
        
        Args:
            mem: Memory manager instance
        """
        self.mem = mem
    
    def read(self, addr: int, max_len: int = MAX_STR, wide: bool = False) -> str:
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
    
    def cstring(self, addr: int, max_len: int = MAX_STR) -> str:
        """Read null-terminated ASCII string.
        
        Args:
            addr: String address
            max_len: Maximum characters to read
            
        Returns:
            Decoded ASCII string
        """
        return self._read(addr, max_len, 1, "ascii")
    
    def wstring(self, addr: int, max_len: int = MAX_STR) -> str:
        """Read null-terminated UTF-16 wide string.
        
        Args:
            addr: String address
            max_len: Maximum characters to read
            
        Returns:
            Decoded UTF-16 string
        """
        return self._read(addr, max_len, 2, "utf-16le")

    def wstring32(self, addr: int, max_len: int = MAX_STR) -> str:
        """Read null-terminated UTF-32 little-endian wide string (Linux wchar_t).
        
        Args:
            addr: String address
            max_len: Maximum characters to read
        
        Returns:
            Decoded UTF-32 string
        """
        return self._read(addr, max_len, 4, "utf-32le")
    
    def _read(self, addr: int, max_len: int, width: int, encoding: str) -> str:
        """Generic string reading helper with chunked reads for performance.
        
        Args:
            addr: String address
            max_len: Maximum characters to read
            width: Character width in bytes (1 for ASCII, 2 for UTF-16, 4 for UTF-32)
            encoding: Text encoding to use
            
        Returns:
            Decoded string (truncated to MAX_STR if needed)
        """
        if max_len <= 0:
            return ""
        
        # Enforce MAX_STR limit
        max_len = min(max_len, MAX_STR)
        
        term = b"\x00" * width
        out = bytearray()
        
        # Chunked reading for performance (read PAGE-sized chunks when possible)
        from ..utils.constants import PAGE
        chunk_size = min(PAGE, max_len * width)  # Read up to a page at a time
        
        while len(out) < max_len * width:
            remaining = (max_len * width) - len(out)
            to_read = min(chunk_size, remaining)
            
            try:
                # Read a chunk
                chunk = self.mem.read(addr, to_read)
                
                # Find terminator in chunk
                for i in range(0, len(chunk), width):
                    if chunk[i:i+width] == term:
                        # Found terminator
                        out += chunk[:i]
                        return out.decode(encoding, errors="replace")
                
                # No terminator found, add entire chunk
                out += chunk
                addr += to_read
                
                # Safety check
                if len(out) >= MAX_STR * width:
                    log.debug(f"String read truncated at {MAX_STR} characters")
                    break
                    
            except Exception as e:
                # Fall back to byte-by-byte on error (e.g., unmapped memory)
                if not out:
                    # Complete failure on first read
                    log.error(f"String read failed at 0x{addr:08X}: {e}")
                    raise
                # Partial read succeeded, return what we have
                break
        
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
