"""Linux auxiliary vector and process environment setup."""
from __future__ import annotations
from ...formats.utils import map_env
from ...utils.constants import PAGE, Addr, STACK_32, STACK_64
from ...utils.logger import log


class AuxV:
    """Linux auxiliary vector and initial stack setup.
    
    Initializes the process environment including argv, envp,
    and the auxiliary vector as expected by Linux ELF executables.
    """
    
    # Auxiliary vector types
    AT_NULL = 0      # End of vector
    AT_PHDR = 3      # Program headers
    AT_PHENT = 4     # Size of program header entry
    AT_PHNUM = 5     # Number of program headers
    AT_PAGESZ = 6    # System page size
    AT_BASE = 7      # Base address of interpreter
    AT_ENTRY = 9     # Entry point of program
    AT_UID = 11      # Real user ID
    AT_EUID = 12     # Effective user ID
    AT_GID = 13      # Real group ID
    AT_EGID = 14     # Effective group ID
    AT_RANDOM = 25   # Address of 16 random bytes
    AT_EXECFN = 31   # Filename of program
    
    def __init__(self, ctx, mem) -> None:
        self.ctx = ctx
        self.uc = ctx.uc
        self.mem = mem
        
        # Base addresses (similar to Windows TEB/PEB structure)
        self.base = ctx.stack  # Stack is our base for Linux
        self.auxv = Addr.AUXV_64 if ctx.is_64 else Addr.AUXV_32
        self.envp = 0  # Environment pointer array
        self.argv = 0  # Argument pointer array
    
    def seed(self, base: int, entry: int, filename: str = "/tmp/program") -> int:
        """Initialize Linux process environment on stack.
        
        Args:
            base: Program base address
            entry: Entry point address
            filename: Program filename
            
        Returns:
            Stack pointer value to use
        """
        # Map stack pages
        stack_size = STACK_64 if self.ctx.is_64 else STACK_32
        stack_base = self.base - stack_size
        map_env(self.mem, stack_base, stack_size // PAGE)
        
        # Start building stack from top
        sp = self.base
        
        if self.ctx.is_64:
            return self._seed_64(sp, base, entry, filename)
        else:
            return self._seed_32(sp, base, entry, filename)
    
    def _seed_64(self, sp: int, base: int, entry: int, filename: str) -> int:
        """Setup 64-bit Linux process stack layout.
        
        Stack layout (top to bottom):
        - Random data (for AT_RANDOM)
        - Filename string
        - Environment strings
        - Argument strings
        - Auxiliary vector
        - Environment pointers
        - Argument pointers
        - Argument count
        
        Returns:
            Final stack pointer value
        """
        # Write strings at top of stack
        sp -= 16
        random_addr = sp
        self.mem.write(random_addr, b'\x41' * 16)  # Random data
        
        sp -= len(filename) + 1
        filename_addr = sp
        self.mem.write(filename_addr, filename.encode() + b'\x00')
        
        # Write environment variables
        sp -= 32
        env1_addr = sp
        self.mem.write(env1_addr, b'PATH=/usr/bin:/bin\x00')
        
        # Write argv[0] (program name)
        sp -= len(filename) + 1
        argv0_addr = sp
        self.mem.write(argv0_addr, filename.encode() + b'\x00')
        
        # Align stack to 16 bytes
        sp &= ~0xF  # Align to 16 bytes
        
        # Write auxiliary vector
        auxv = [
            (self.AT_PAGESZ, PAGE),
            (self.AT_BASE, base),
            (self.AT_ENTRY, entry),
            (self.AT_UID, 1000),
            (self.AT_EUID, 1000),
            (self.AT_GID, 1000),
            (self.AT_EGID, 1000),
            (self.AT_RANDOM, random_addr),
            (self.AT_EXECFN, filename_addr),
            (self.AT_NULL, 0)
        ]
        
        sp -= len(auxv) * 16
        self.auxv = sp
        for i, (tag, val) in enumerate(auxv):
            self.mem.pack(sp + i*16, tag, bits=64)
            self.mem.pack(sp + i*16 + 8, val, bits=64)
        
        # Write environment pointers
        sp -= 16
        self.envp = sp
        self.mem.pack(sp, env1_addr, bits=64)  # env[0]
        self.mem.pack(sp + 8, 0, bits=64)      # NULL terminator
        
        # Write argv pointers
        sp -= 16
        self.argv = sp
        self.mem.pack(sp, argv0_addr, bits=64)  # argv[0]
        self.mem.pack(sp + 8, 0, bits=64)       # NULL terminator
        
        # Write argc
        sp -= 8
        self.mem.pack(sp, 1, bits=64)  # argc = 1
        
        log.debug(f"AuxV: Stack initialized at 0x{sp:016X}")
        return sp
    
    def _seed_32(self, sp: int, base: int, entry: int, filename: str) -> int:
        """Setup 32-bit Linux process stack layout.
        
        Similar to 64-bit but with 32-bit pointers.
        
        Returns:
            Final stack pointer value
        """
        # Write strings at top of stack
        sp -= 16
        random_addr = sp
        self.mem.write(random_addr, b'\x41' * 16)  # Random data
        
        sp -= len(filename) + 1
        filename_addr = sp
        self.mem.write(filename_addr, filename.encode() + b'\x00')
        
        # Write environment variables
        sp -= 32
        env1_addr = sp
        self.mem.write(env1_addr, b'PATH=/usr/bin:/bin\x00')
        
        # Write argv[0]
        sp -= len(filename) + 1
        argv0_addr = sp
        self.mem.write(argv0_addr, filename.encode() + b'\x00')
        
        # Align stack to 16 bytes
        sp &= ~0xF  # Align to 16 bytes
        
        # Write auxiliary vector
        auxv = [
            (self.AT_PAGESZ, PAGE),
            (self.AT_BASE, base),
            (self.AT_ENTRY, entry),
            (self.AT_UID, 1000),
            (self.AT_EUID, 1000),
            (self.AT_GID, 1000),
            (self.AT_EGID, 1000),
            (self.AT_RANDOM, random_addr),
            (self.AT_EXECFN, filename_addr),
            (self.AT_NULL, 0)
        ]
        
        sp -= len(auxv) * 8
        self.auxv = sp
        for i, (tag, val) in enumerate(auxv):
            self.mem.pack(sp + i*8, tag, bits=32)
            self.mem.pack(sp + i*8 + 4, val, bits=32)
        
        # Write environment pointers
        sp -= 8
        self.envp = sp
        self.mem.pack(sp, env1_addr, bits=32)  # env[0]
        self.mem.pack(sp + 4, 0, bits=32)      # NULL terminator
        
        # Write argv pointers
        sp -= 8
        self.argv = sp
        self.mem.pack(sp, argv0_addr, bits=32)  # argv[0]
        self.mem.pack(sp + 4, 0, bits=32)       # NULL terminator
        
        # Write argc
        sp -= 4
        self.mem.pack(sp, 1, bits=32)  # argc = 1
        
        log.debug(f"AuxV: Stack initialized at 0x{sp:08X}")
        return sp


# Alias for compatibility  
AuxVector = AuxV  # Keep long name available
