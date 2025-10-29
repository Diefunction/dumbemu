"""Windows PE emulation components.

Provides PE loader and TEB/PEB structures.
"""
from __future__ import annotations
from ...formats.pe import PE, PELoader  # PE is short, PELoader for compatibility
from .tebpeb import TebPeb  # Already concise name

# Import from unified stubs module for compatibility
from ...stubs import Stubs as IAT, Stubs as IATStubs, Proto

__all__ = ["PE", "PELoader", "IAT", "IATStubs", "Proto", "TebPeb"]
