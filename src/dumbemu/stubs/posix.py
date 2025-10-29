"""Optional built-in POSIX/Linux libc stubs."""
from __future__ import annotations
from .core import Symbol, Callback
from ..utils.logger import log


def get_builtin_posix_stubs() -> dict[tuple[str, str], tuple[Symbol, Callback]]:
    """Get dictionary of built-in POSIX/Linux stubs.
    
    Returns:
        Dictionary mapping (module, name) to (symbol, callback)
    """
    stubs = {}
    
    # Example: printf stub
    def printf(stubs, uc, args) -> int:
        """printf(format, ...)"""
        fmt_ptr = args[0]
        if fmt_ptr:
            fmt = stubs._str(fmt_ptr)
            log.info(f"[printf] {fmt}")
        return len(args) - 1  # Return number of chars printed (simplified)
    
    stubs[("libc.so.6", "printf")] = (
        Symbol("printf", "cdecl", [8]),  # Format ptr
        printf
    )
    
    # Example: malloc stub
    def malloc(stubs, uc, args) -> int:
        """malloc(size)"""
        size = args[0]
        from ..mem.alloc import Alloc
        from ..utils.constants import UC_PROT_READ, UC_PROT_WRITE
        alloc = Alloc(stubs.ctx, stubs.mem)
        addr = alloc.alloc(size, UC_PROT_READ | UC_PROT_WRITE)
        log.info(f"[malloc] size={size:#x} -> {addr:#x}")
        return addr
    
    stubs[("libc.so.6", "malloc")] = (
        Symbol("malloc", "cdecl", [8]),  # Will be fixed at registration time
        malloc
    )
    
    # Example: free stub
    def free(stubs, uc, args) -> int:
        """free(ptr)"""
        ptr = args[0]
        log.info(f"[free] ptr={ptr:#x}")
        # In a real implementation, would track and free
        return 0
    
    stubs[("libc.so.6", "free")] = (
        Symbol("free", "cdecl", [8]),  # Will be fixed at registration time
        free
    )
    
    # Example: puts stub
    def puts(stubs, uc, args) -> int:
        """puts(str)"""
        str_ptr = args[0]
        if str_ptr:
            text = stubs._str(str_ptr)
            log.info(f"[puts] {text}")
            return len(text)
        return -1
    
    stubs[("libc.so.6", "puts")] = (
        Symbol("puts", "cdecl", [8]),  # Will be fixed at registration time
        puts
    )
    
    # Example: strlen stub
    def strlen(stubs, uc, args) -> int:
        """strlen(str)"""
        str_ptr = args[0]
        if str_ptr:
            text = stubs._str(str_ptr)
            return len(text)
        return 0
    
    stubs[("libc.so.6", "strlen")] = (
        Symbol("strlen", "cdecl", [8]),  # Will be fixed at registration time
        strlen
    )
    
    # Example: strcmp stub
    def strcmp(stubs, uc, args) -> int:
        """strcmp(s1, s2)"""
        s1_ptr = args[0]
        s2_ptr = args[1]
        if s1_ptr and s2_ptr:
            s1 = stubs._str(s1_ptr)
            s2 = stubs._str(s2_ptr)
            if s1 < s2:
                return -1
            elif s1 > s2:
                return 1
        return 0
    
    stubs[("libc.so.6", "strcmp")] = (
        Symbol("strcmp", "cdecl", [8, 8]),  # Will be fixed at registration time
        strcmp
    )
    
    return stubs


def register_posix_stubs(stubs, selection: list[str] = None):
    """Register built-in POSIX/Linux stubs.
    
    Args:
        stubs: Stubs manager instance
        selection: Optional list of function names to register.
                  If None, registers all available stubs.
    """
    from .core import register_builtins
    register_builtins(stubs, get_builtin_posix_stubs(), selection)
