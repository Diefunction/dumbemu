

from math import isfinite
from typing import List, Tuple
from const import PAGE_SIZE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn import UcError
import lief

class Parser:
    """Handler for PE file loading and processing"""

    def __init__(self, path: str) -> None:
        """Initialize with PE file path"""
        self.binary = lief.parse(path)
        self.header = self.binary.header
        self.path = path
        self.base = self.binary.imagebase
        self.size = self._align(self.binary.virtual_size)

        if isinstance(self.binary, lief.PE.Binary):
            self.file_type = "pe"

        elif isinstance(self.binary, lief.ELF.Binary):
            self.file_type = "elf"

        else:
            raise RuntimeError(f"File Format Not Supported")

        self.arch = self._arch()
        self.is_64bit = self._check()

    def _arch(self) -> str:
        if self.file_type == "pe" and self.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64:
            return "amd64"
        elif self.file_type == "elf" and self.header.machine_type == lief.ELF.ARCH.X86_64:
            return "amd64"
        else:
            return "unknwon"

    def _check(self) -> bool:
        """Check if PE is 64-bit or 32-bit"""
        return self.arch == "amd64"

    def _align(self, val: int, align: int = PAGE_SIZE) -> int:
        """Align memory address to boundary"""
        return (val + align - 1) & ~(align - 1)

    def sections(self) -> List[Tuple[int, bytes, int]]:
        """Get list of (address, data, permissions) for each section"""
        result = []
        for section in self.binary.sections:
           add = self.base + section.virtual_address
           data = bytearray(section.content)
           if self.file_type == "elf":
               perm = UC_PROT_READ
               perm |= UC_PROT_EXEC if section.has(lief._lief.ELF.Section.FLAGS.EXECINSTR) else 0
               perm |= UC_PROT_WRITE if section.has(lief._lief.ELF.Section.FLAGS.WRITE) else 0
           elif self.file_type == "pe":
               perm = UC_PROT_READ
               perm |= UC_PROT_EXEC if section.has(lief._lief.PE.Section.FLAGS.EXECINSTR) else 0
               perm |= UC_PROT_WRITE if section.has(lief._lief.PE.Section.FLAGS.WRITE) else 0
           result.append((add,data,perm))
       return result

    def relocs(self, new_base: int): #-> List[Tuple[int, int, int]]:
        """Get relocations as (address, size, value_delta)"""
        pass

    def __str__(self) -> str:
        return f"""
        File: {self.path}
        Base: {self.base:x}
        Size: {self.size:x}
        format: {self.file_type}
        arch: {self.arch}
        x64: {self.is_64bit}
        sections:
        self.sections()

        relocs:
        self.relocs() // not tested yet
        """
