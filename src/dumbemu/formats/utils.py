"""Loader utility functions for PE/ELF processing."""
from __future__ import annotations
from typing import Optional, List, Tuple
from ..utils.constants import PAGE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, align_down
from ..utils.logger import log


def pe_is_64(bin) -> bool:
    """Detect if PE file is 64-bit.
    
    Args:
        bin: LIEF PE binary object
        
    Returns:
        True if 64-bit, False if 32-bit
    """
    import lief
    try:
        return bin.optional_header.magic == lief.PE.PE_TYPE.PE32_PLUS
    except (AttributeError, RuntimeError):
        try:
            return bin.header.machine == lief.PE.MACHINE_TYPES.AMD64
        except (AttributeError, RuntimeError):
            return False


def elf_is_64(bin) -> bool:
    """Detect if ELF file is 64-bit.
    
    Args:
        bin: LIEF ELF binary object
        
    Returns:
        True if 64-bit, False if 32-bit
    """
    try:
        return str(bin.header.identity_class) == "CLASS.ELF64"
    except (AttributeError, RuntimeError):
        try:
            return int(bin.header.identity_class) == 2
        except (AttributeError, RuntimeError):
            return False


def elf_prot(flags: int) -> int:
    """Convert ELF segment flags to Unicorn protection.
    
    Args:
        flags: ELF segment flags (PF_R=4, PF_W=2, PF_X=1)
        
    Returns:
        Unicorn protection flags
    """
    prot = 0
    if flags & 4:  # PF_R
        prot |= UC_PROT_READ
    if flags & 2:  # PF_W
        prot |= UC_PROT_WRITE
    if flags & 1:  # PF_X
        prot |= UC_PROT_EXEC
    
    # Handle edge cases
    if prot == 0:
        # No permissions set, default to READ
        prot = UC_PROT_READ
    elif (prot & UC_PROT_WRITE) and (prot & UC_PROT_EXEC):
        # W^X detected, make it RWX for compatibility (some packers need this)
        prot |= UC_PROT_READ
        log.debug(f"elf_prot: W^X flags detected, using RWX for compatibility")
    
    return prot


def norm_mod(name: str) -> str:
    """Normalize module/library name for comparison.
    
    Args:
        name: Module or library name
        
    Returns:
        Normalized lowercase name without path
    """
    if not name:
        return ""
    # Strip path components
    name = name.split('/')[-1].split('\\')[-1]
    return name.lower()


def ord_name(ordinal: int) -> str:
    """Format ordinal number as import name.
    
    Args:
        ordinal: Ordinal number
        
    Returns:
        Formatted string like 'ord123'
    """
    return f"ord{ordinal}"


def map_env(mem, base: int, pages: int = 2) -> None:
    """Map memory pages for environment structures.
    
    Args:
        mem: Memory manager instance
        base: Base address to map
        pages: Number of pages to map (default: 2)
    """
    mem.map(align_down(base), PAGE * pages, UC_PROT_READ | UC_PROT_WRITE)


def write_ptr_array(mem, ptrs: List[Tuple[int, int]], bits: int) -> None:
    """Write array of pointers to memory.
    
    Args:
        mem: Memory manager instance
        ptrs: List of (address, value) tuples
        bits: Pointer size in bits (32 or 64)
    """
    for addr, val in ptrs:
        mem.pack(addr, val, bits=bits)


