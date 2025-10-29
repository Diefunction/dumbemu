"""Custom exception classes for DumbEmu."""
from __future__ import annotations


class EmuError(Exception):
    """Base class for all emulator exceptions."""
    pass


class LoaderError(EmuError):
    """Raised when loading or parsing executables fails."""
    pass


class FormatError(LoaderError):
    """Raised when executable format is invalid or unsupported."""
    pass


class MemoryError(EmuError):
    """Raised when memory operations fail."""
    pass


class ExecutionError(EmuError):
    """Raised when code execution encounters an error."""
    pass


class EmuLimitError(ExecutionError):
    """Raised when execution limits are reached."""
    def __init__(self, limit_type: str, value: int):
        self.limit_type = limit_type
        self.value = value
        super().__init__(f"Execution limit reached: {limit_type}={value}")


class SegFaultError(ExecutionError):
    """Raised when a segmentation fault occurs."""
    def __init__(self, address: int):
        self.address = address
        super().__init__(f"Segmentation fault at 0x{address:08X}")


class StubError(EmuError):
    """Raised when stub operations fail."""
    pass


class ArgumentError(EmuError):
    """Raised when function arguments are invalid."""
    pass
