"""Common type aliases for DumbEmu.

Provides consistent type hints across the codebase.
"""
from __future__ import annotations
from typing import Callable, Any, Optional, Union, Tuple, List, Dict

# Memory addresses and sizes
Addr = int  # Memory address
Size = int  # Size in bytes  
Prot = int  # Memory protection flags

# Register types
RegName = str  # Register name like 'rax', 'eax'
RegValue = int  # Register value
RegID = int  # Unicorn register ID

# Binary data
Bytes = bytes
Data = Union[bytes, bytearray]

# Callback types for hooks and stubs
HookCallback = Callable[[Any, int], None]  # (uc, address) -> None
StubCallback = Callable[[Any, Any, Tuple[int, ...]], int]  # (stubs, uc, args) -> retval

# Import/Export types
ModuleName = str  # Module/library name
SymbolName = str  # Function/symbol name
Ordinal = Optional[int]  # Optional ordinal number

# Execution types
InsnCount = int  # Instruction count
BreakAddr = Optional[int]  # Optional breakpoint address

# Format types
FileFormat = Union["PE", "ELF"]  # Loader format types
BinaryPath = str  # Path to executable file

# Collections
AddrList = List[int]  # List of addresses
HookDict = Dict[int, List[HookCallback]]  # addr -> callbacks
ImportList = List["Import"]  # List of imports
ExportList = List[Tuple[str, int]]  # List of (name, addr)

# Emulation limits
CodeCage = Optional[Tuple[int, int]]  # Optional (min_addr, max_addr)

__all__ = [
    "Addr", "Size", "Prot",
    "RegName", "RegValue", "RegID",
    "Bytes", "Data",
    "HookCallback", "StubCallback",
    "ModuleName", "SymbolName", "Ordinal",
    "InsnCount", "BreakAddr",
    "FileFormat", "BinaryPath",
    "AddrList", "HookDict", "ImportList", "ExportList",
    "CodeCage"
]
