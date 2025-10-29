"""Platform-specific runtime environment components.

OS-specific structures and initialization routines.
"""
from __future__ import annotations
from .windows import TebPeb
from .linux import AuxV, AuxVector

__all__ = ["TebPeb", "AuxV", "AuxVector"]
