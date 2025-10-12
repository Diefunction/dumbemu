"""
DumbEmu (fixed minimal edition)
A lightweight PE function emulator on top of Unicorn.
This edition focuses on correctness and a small, dependency-light core.
"""
from .emulator import DumbEmu
__all__ = ["DumbEmu"]
