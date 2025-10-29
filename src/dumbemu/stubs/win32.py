"""Optional built-in Windows API stubs."""
from __future__ import annotations
from .core import Proto, Callback
from ..utils.logger import log


def get_builtin_win32_stubs() -> dict[tuple[str, str], tuple[Proto, Callback]]:
    """Get dictionary of built-in Windows API stubs.
    
    Returns:
        Dictionary mapping (module, name) to (proto, callback)
    """
    stubs = {}
    
    # Example: GetProcAddress stub
    def GetProcAddress(stubs, uc, args) -> int:
        """GetProcAddress(hModule, lpProcName)"""
        proc_name_ptr = args[1]
        if proc_name_ptr:
            proc_name = stubs._str(proc_name_ptr)
            log.info(f"[GetProcAddress] {proc_name}")
        return 0x12345678  # Fake address
    
    stubs[("kernel32.dll", "GetProcAddress")] = (
        Proto("GetProcAddress", "stdcall", [4, 4]),
        GetProcAddress
    )
    
    # Example: LoadLibraryA stub
    def LoadLibraryA(stubs, uc, args) -> int:
        """LoadLibraryA(lpLibFileName)"""
        lib_name_ptr = args[0]
        if lib_name_ptr:
            lib_name = stubs._str(lib_name_ptr)
            log.info(f"[LoadLibraryA] {lib_name}")
            return stubs._handle(lib_name)
        return 0
    
    stubs[("kernel32.dll", "LoadLibraryA")] = (
        Proto("LoadLibraryA", "stdcall", [4]),
        LoadLibraryA
    )
    
    # Example: MessageBoxA stub
    def MessageBoxA(stubs, uc, args) -> int:
        """MessageBoxA(hWnd, lpText, lpCaption, uType)"""
        text_ptr = args[1]
        caption_ptr = args[2]
        text = stubs._str(text_ptr) if text_ptr else ""
        caption = stubs._str(caption_ptr) if caption_ptr else ""
        log.info(f"[MessageBoxA] Caption: {caption}, Text: {text}")
        return 1  # IDOK
    
    stubs[("user32.dll", "MessageBoxA")] = (
        Proto("MessageBoxA", "stdcall", [4, 4, 4, 4]),
        MessageBoxA
    )
    
    # Example: GetLastError stub
    def GetLastError(stubs, uc, args) -> int:
        """GetLastError()"""
        return stubs.get_last_error()
    
    stubs[("kernel32.dll", "GetLastError")] = (
        Proto("GetLastError", "stdcall", []),
        GetLastError
    )
    
    # Example: SetLastError stub
    def SetLastError(stubs, uc, args) -> int:
        """SetLastError(dwErrCode)"""
        stubs.set_last_error(args[0])
        return 0
    
    stubs[("kernel32.dll", "SetLastError")] = (
        Proto("SetLastError", "stdcall", [4]),
        SetLastError
    )
    
    return stubs


def register_win32_stubs(stubs, selection: list[str] = None):
    """Register built-in Windows API stubs.
    
    Args:
        stubs: Stubs manager instance
        selection: Optional list of function names to register.
                  If None, registers all available stubs.
    """
    from .core import register_builtins
    register_builtins(stubs, get_builtin_win32_stubs(), selection)
