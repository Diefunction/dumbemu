"""Linux ELF emulation components.

Provides ELF loader and auxiliary vector setup.
"""
from __future__ import annotations
from ...formats.elf import ELF, ELFLoader  # ELF is short, ELFLoader for compatibility
from .auxv import AuxV, AuxVector  # AuxV is short, AuxVector for compatibility

# Import from unified stubs module for compatibility
from ...stubs import Stubs as PLT, Stubs as PLTStubs, Symbol

__all__ = ["ELF", "ELFLoader", "PLT", "PLTStubs", "Symbol", "AuxV", "AuxVector"]
