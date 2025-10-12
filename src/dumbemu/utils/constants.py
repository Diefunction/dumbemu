"""Constants, addresses, and register mappings for x86/x64 emulation."""
from unicorn import UC_ARCH_X86, UC_MODE_32, UC_MODE_64, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP,
    UC_X86_REG_EIP, UC_X86_REG_EFLAGS,
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, 
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
    UC_X86_REG_RIP,
    UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_FS, UC_X86_REG_GS, UC_X86_REG_SS
)

# Optional segment base registers
try:
    from unicorn.x86_const import UC_X86_REG_GS_BASE, UC_X86_REG_FS_BASE
except ImportError:
    UC_X86_REG_GS_BASE = None
    UC_X86_REG_FS_BASE = None

# Memory sizes
PAGE = 0x1000
STACK_32 = 0x200000
STACK_64 = 0x400000
MAX_STR = 4096

def align_down(addr: int) -> int:
    """Align address down to page boundary."""
    return addr & ~(PAGE - 1)

def align_up(addr: int) -> int:
    """Align address up to page boundary."""
    return (addr + PAGE - 1) & ~(PAGE - 1)

# Base addresses (avoid PE image bases)
class Addr:
    """Memory layout addresses."""
    # Stack
    STACK_32 = 0x10000000
    STACK_64 = 0x70000000
    # Fake returns for stopping execution
    FAKE_RET_32 = 0xDEADBEEF
    FAKE_RET_64 = 0xDEADBEEF_F00DBA5E
    # Allocator region
    ALLOC_32 = 0x18000000
    ALLOC_64 = 0x60000000
    # Import trampolines
    TRAMPOLINE_32 = 0x0E100000
    TRAMPOLINE_64 = 0x7E000000
    # TEB/PEB
    TEB_32 = 0x7FFDE000
    PEB_32 = 0x7FFDF000
    TEB_64 = 0x7FFE0000
    PEB_64 = 0x7FFD0000

# Win64 ABI registers are defined in Args.WIN64_REGS as string names

class Regs:
    """Register name mappings."""
    X86 = {
        # General purpose 32-bit
        "eax": UC_X86_REG_EAX, "ebx": UC_X86_REG_EBX, "ecx": UC_X86_REG_ECX, "edx": UC_X86_REG_EDX,
        "esi": UC_X86_REG_ESI, "edi": UC_X86_REG_EDI, "ebp": UC_X86_REG_EBP, "esp": UC_X86_REG_ESP,
        # 16-bit registers
        "ax": UC_X86_REG_EAX, "bx": UC_X86_REG_EBX, "cx": UC_X86_REG_ECX, "dx": UC_X86_REG_EDX,
        "si": UC_X86_REG_ESI, "di": UC_X86_REG_EDI, "bp": UC_X86_REG_EBP, "sp": UC_X86_REG_ESP,
        # 8-bit registers (using full register IDs as Unicorn doesn't have separate 8-bit IDs)
        "al": UC_X86_REG_EAX, "bl": UC_X86_REG_EBX, "cl": UC_X86_REG_ECX, "dl": UC_X86_REG_EDX,
        "ah": UC_X86_REG_EAX, "bh": UC_X86_REG_EBX, "ch": UC_X86_REG_ECX, "dh": UC_X86_REG_EDX,
        # Special registers
        "eip": UC_X86_REG_EIP, "eflags": UC_X86_REG_EFLAGS,
        # Segment registers
        "cs": UC_X86_REG_CS, "ds": UC_X86_REG_DS, "es": UC_X86_REG_ES, 
        "fs": UC_X86_REG_FS, "gs": UC_X86_REG_GS, "ss": UC_X86_REG_SS,
    }
    X64 = {
        # 64-bit general purpose
        "rax": UC_X86_REG_RAX, "rbx": UC_X86_REG_RBX, "rcx": UC_X86_REG_RCX, "rdx": UC_X86_REG_RDX,
        "rsi": UC_X86_REG_RSI, "rdi": UC_X86_REG_RDI, "rbp": UC_X86_REG_RBP, "rsp": UC_X86_REG_RSP,
        "r8": UC_X86_REG_R8, "r9": UC_X86_REG_R9, "r10": UC_X86_REG_R10, "r11": UC_X86_REG_R11,
        "r12": UC_X86_REG_R12, "r13": UC_X86_REG_R13, "r14": UC_X86_REG_R14, "r15": UC_X86_REG_R15,
        # 32-bit names (lower 32 bits)
        "eax": UC_X86_REG_RAX, "ebx": UC_X86_REG_RBX, "ecx": UC_X86_REG_RCX, "edx": UC_X86_REG_RDX,
        "esi": UC_X86_REG_RSI, "edi": UC_X86_REG_RDI, "ebp": UC_X86_REG_RBP, "esp": UC_X86_REG_RSP,
        "r8d": UC_X86_REG_R8, "r9d": UC_X86_REG_R9, "r10d": UC_X86_REG_R10, "r11d": UC_X86_REG_R11,
        "r12d": UC_X86_REG_R12, "r13d": UC_X86_REG_R13, "r14d": UC_X86_REG_R14, "r15d": UC_X86_REG_R15,
        # 16-bit names
        "ax": UC_X86_REG_RAX, "bx": UC_X86_REG_RBX, "cx": UC_X86_REG_RCX, "dx": UC_X86_REG_RDX,
        "si": UC_X86_REG_RSI, "di": UC_X86_REG_RDI, "bp": UC_X86_REG_RBP, "sp": UC_X86_REG_RSP,
        "r8w": UC_X86_REG_R8, "r9w": UC_X86_REG_R9, "r10w": UC_X86_REG_R10, "r11w": UC_X86_REG_R11,
        "r12w": UC_X86_REG_R12, "r13w": UC_X86_REG_R13, "r14w": UC_X86_REG_R14, "r15w": UC_X86_REG_R15,
        # 8-bit names
        "al": UC_X86_REG_RAX, "bl": UC_X86_REG_RBX, "cl": UC_X86_REG_RCX, "dl": UC_X86_REG_RDX,
        "ah": UC_X86_REG_RAX, "bh": UC_X86_REG_RBX, "ch": UC_X86_REG_RCX, "dh": UC_X86_REG_RDX,
        "sil": UC_X86_REG_RSI, "dil": UC_X86_REG_RDI, "bpl": UC_X86_REG_RBP, "spl": UC_X86_REG_RSP,
        "r8b": UC_X86_REG_R8, "r9b": UC_X86_REG_R9, "r10b": UC_X86_REG_R10, "r11b": UC_X86_REG_R11,
        "r12b": UC_X86_REG_R12, "r13b": UC_X86_REG_R13, "r14b": UC_X86_REG_R14, "r15b": UC_X86_REG_R15,
        # Special registers
        "rip": UC_X86_REG_RIP, "eip": UC_X86_REG_RIP, "rflags": UC_X86_REG_EFLAGS, "eflags": UC_X86_REG_EFLAGS,
        # Segment registers
        "cs": UC_X86_REG_CS, "ds": UC_X86_REG_DS, "es": UC_X86_REG_ES,
        "fs": UC_X86_REG_FS, "gs": UC_X86_REG_GS, "ss": UC_X86_REG_SS,
    }

# PE section flags
SCN_READ = 0x40000000
SCN_WRITE = 0x80000000
SCN_EXEC = 0x20000000

def to_prot(flags: int) -> int:
    """Convert PE section flags to Unicorn protection flags."""
    prot = 0
    if flags & SCN_READ:
        prot |= UC_PROT_READ
    if flags & SCN_WRITE:
        prot |= UC_PROT_WRITE
    if flags & SCN_EXEC:
        prot |= UC_PROT_EXEC
    return prot or UC_PROT_READ

__all__ = [
    # Unicorn constants
    "UC_ARCH_X86", "UC_MODE_32", "UC_MODE_64", 
    "UC_PROT_READ", "UC_PROT_WRITE", "UC_PROT_EXEC", "UC_HOOK_CODE",
    # Memory
    "PAGE", "STACK_32", "STACK_64", "MAX_STR",
    # Classes
    "Addr", "Regs", 
    # Functions
    "to_prot", "align_down", "align_up",
    # Optional
    "UC_X86_REG_GS_BASE", "UC_X86_REG_FS_BASE"
]
