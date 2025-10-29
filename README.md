# DumbEmu

A lightweight, cross-platform emulator built on Unicorn Engine for Windows PE and Linux ELF executable analysis and function testing.

## Features

### Core Capabilities
- **Cross-Platform Support**: Automatic format detection for both Windows PE and Linux ELF executables
- **Architecture Support**: Automatic detection and support for x86 (32-bit) and x64 (64-bit) binaries
- **Binary Loading**: Complete PE/ELF parsing with proper section mapping and permissions
- **Platform Environments**: 
  - Windows: TEB/PEB structure initialization
  - Linux: Auxiliary vector and process environment setup
- **Import Stubbing**: IAT/PLT hooking with pluggable, customizable function stubs for both platforms

### Memory Management
- **Smart Allocation**: Page-aligned memory allocator with tracking
- **Protection Control**: Fine-grained memory permission management  
- **String Operations**: Native support for ASCII, UTF-16, and UTF-32 strings
- **Struct Operations**: Pack/unpack structured data with format strings
- **Bulk Mapping**: Optimized page-range mapping with automatic alignment

### Execution Control
- **Calling Conventions**: Full support for Win64, SysV x64, stdcall, and cdecl ABIs
- **Function Calling**: Proper argument marshaling and stack alignment
- **Raw Execution**: Direct code execution without function overhead
- **Breakpoints**: Set breakpoints to pause execution at specific addresses
- **Instruction Limits**: Prevent infinite loops with instruction count limits
- **Stack Guards**: Optional stack-depth watchdog to detect stack overflow/underflow
- **Code Caging**: Restrict execution to specific address ranges
- **Execution Tracing**: Record executed addresses with optional ring-buffer mode

### Advanced Features
- **Dynamic Hooks**: Automatic switching between targeted and global hook modes for optimal performance
- **Custom Exceptions**: Granular exception hierarchy (SegFaultError, EmuLimitError, etc.)
- **Register Access**: Full access to all x86/x64 registers including segments
- **Stack Management**: Automatic stack setup with push/pop operations
- **Verbose Logging**: Optional detailed logging for debugging

## Installation

### From PyPI

```bash
pip install dumbemu
```

### From Source

```bash
# Clone the repository
git clone https://github.com/Diefunction/dumbemu
cd dumbemu

# Install in editable mode (recommended for development)
pip install -e .

# Or install directly
pip install .
```

### Requirements

- Python >= 3.8
- unicorn >= 2.0.0
- lief >= 0.13.0

These dependencies will be automatically installed when you install dumbemu.

## Quick Start

### Basic Function Call

```python
from dumbemu import DumbEmu

# Load executable (PE or ELF, architecture auto-detected)
emu = DumbEmu("target.exe")  # or "binary.elf"

# Call function at 0x401000 with three arguments
result = emu.call(0x401000, None, 10, 20, 30)
print(f"Result: 0x{result:08X}")
```

### Memory Operations

```python
# Allocate memory
addr = emu.malloc(0x1000)  # Allocate 4KB

# Write data
emu.write(addr, b"Hello, World!")

# Read data
data = emu.read(addr, 13)

# String operations
emu.string.ascii(addr, "Test String")
text = emu.string.cstring(addr)

# Struct operations
emu.struct.write(addr, "IHH", 0xDEADBEEF, 0x1337, 0x42)
values = emu.struct.read(addr, "IHH")
```

### Import Stubbing (Windows/Linux)

```python
from dumbemu.stubs import Proto, Symbol

# Windows IAT stub example
def get_proc_stub(stubs, uc, args):
    # args = (hModule, lpProcName)
    proc_name_ptr = args[1]
    proc_name = stubs._str(proc_name_ptr)
    print(f"GetProcAddress called for: {proc_name}")
    return 0x12345678  # Return fake address

# Register the stub (Windows)
emu.stub("kernel32.dll", "GetProcAddress", 
         Proto("GetProcAddress", emu.ctx.conv, [4, 4]),
         get_proc_stub)

# Linux PLT stub example
def printf_stub(stubs, uc, args):
    fmt_ptr = args[0]
    fmt = stubs._str(fmt_ptr)
    print(f"[printf] {fmt}")
    return len(fmt)

# Register the stub (Linux)
emu.stub("libc.so.6", "printf",
         Symbol("printf", "cdecl", [8]),
         printf_stub)
```

### Execution Hooks

```python
# Define a hook callback
def on_function_entry(uc, address):
    print(f"Entering function at 0x{address:08X}")
    # Read registers
    eax = emu.regs.read('eax')
    print(f"  EAX = 0x{eax:08X}")

# Install hook
emu.hook(0x401000, on_function_entry)

# Execute - hook will be called
emu.call(0x401000)
```

### Execution Tracing

```python
# Enable tracing
emu.tracer.start()

# Execute code
emu.call(0x401000)

# Get execution trace
executed_addrs = emu.tracer.stop()
print(f"Executed {len(executed_addrs)} unique addresses")

# Get history of all traces
history = emu.tracer.history()
```

### Advanced Execution Control

```python
# Execute with instruction limit (prevent infinite loops)
result = emu.call(0x401000, max_insns=10000)

# Execute with breakpoint
result = emu.call(0x401000, breakpoint=0x401050)

# Enable stack guard (detect stack overflow/underflow)
result = emu.call(0x401000, stack_guard=True)

# Restrict execution to specific address range [min, max)
result = emu.call(0x401000, code_cage=(0x400000, 0x500000))

# Raw execution (no function call setup)
emu.execute(0x401000, count=100)  # Execute 100 instructions

# Execution tracing with ring buffer (memory-efficient)
from dumbemu.debug.tracer import Tracer
tracer = Tracer(emu.ctx, max_history=1000)  # Keep only last 1000 addresses
addresses, count = tracer.run(0x401000, stop=0x401100)
```

### Exception Handling

```python
from dumbemu import DumbEmu, SegFaultError, EmuLimitError, ExecutionError

emu = DumbEmu("target.exe")

try:
    result = emu.call(0x401000, code_cage=(0x400000, 0x402000))
except SegFaultError as e:
    print(f"Segmentation fault at address: 0x{e.address:08X}")
except EmuLimitError as e:
    print(f"Execution limit reached: {e.limit_type} = {e.value}")
except ExecutionError as e:
    print(f"Execution error: {e}")
```

## API Reference

### DumbEmu Class

```python
DumbEmu(path: str, verbose: bool = False)
```

#### Core Methods

- `call(addr, breakpoint=None, *args, max_insns=1000000, stack_guard=True, code_cage=None) -> int`
  - Call function with arguments and calling convention support
  - `stack_guard`: Enable stack-depth watchdog (default: True)
  - `code_cage`: Optional (min_addr, max_addr) to restrict execution [min, max)
  - Returns function return value
  
- `execute(addr, until=None, count=None, stack_guard=False, code_cage=None)`
  - Execute raw code without function call setup
  
- `hook(addr, callback)`
  - Install code hook at address
  
- `stub(module, name, proto, callback) -> int`
  - Register import stub handler (works for both Windows IAT and Linux PLT)
  - Returns virtual address of the stub
  
- `invoke(module, name, *args) -> int`
  - Call imported function by name
  
- `malloc(size, prot=RW) -> int`
  - Allocate memory region
  
- `free(addr) -> bool`
  - Free allocated memory

- `trace(addr, stop=None, count=None) -> (list, int)`
  - Trace execution and collect addresses
  - Returns (addresses_list, instruction_count)

#### Memory Access

- `mem.read(addr, size) -> bytes`
  - Read bytes from memory
  
- `mem.write(addr, data)`
  - Write bytes to memory

- `mem.is_mapped(addr) -> bool`
  - Check if address is mapped

#### Component Access

- `emu.ctx` - Emulation context (platform, bitness, calling convention)
- `emu.mem` - Memory manager
- `emu.regs` - Register access (architecture-agnostic)
- `emu.stack` - Stack operations
- `emu.struct` - Struct pack/unpack
- `emu.string` - String operations (ASCII, UTF-16, UTF-32)
- `emu.tracer` - Execution tracer (with ring-buffer mode)
- `emu.stubs` - Unified stub manager (Windows: emu.iat, Linux: emu.plt)
- `emu.hooks` - Code hook manager (dynamic mode switching)
- `emu.alloc` - Memory allocator

### Memory Manager (emu.mem)

- `map(addr, size, prot)` - Map memory region
- `protect(addr, size, prot)` - Change protection
- `pack(addr, value, bits)` - Pack integer to memory
- `unpack(addr, size) -> int` - Unpack integer from memory

### Register Access (emu.regs)

- `read(name) -> int` - Read register value
- `write(name, value)` - Write register value
- Supports all x86/x64 registers: `eax`, `rax`, `r8-r15`, etc.

### String Operations (emu.string)

- `cstring(addr, max_len=4096) -> str` - Read null-terminated ASCII
- `wstring(addr, max_len=4096) -> str` - Read null-terminated UTF-16 (Windows)
- `wstring32(addr, max_len=4096) -> str` - Read null-terminated UTF-32 (Linux wchar_t)
- `ascii(addr, text, null=True)` - Write ASCII string
- `wide(addr, text, null=True)` - Write UTF-16 string
- Chunked reading for performance (page-sized chunks)

### Struct Operations (emu.struct)

- `write(addr, fmt, *values)` - Pack struct to memory
- `read(addr, fmt) -> tuple` - Unpack struct from memory
- `iter(addr, fmt, count) -> iterator` - Iterate structs
- Format strings follow Python's `struct` module

### Stack Operations (emu.stack)

- `push(mem, sp, value) -> int` - Push value, return new SP
- `pop(mem, sp) -> (value, sp)` - Pop value, return value and new SP
- `read(mem, sp, offset) -> int` - Read from stack
- `write(mem, sp, value, offset)` - Write to stack

## Examples

### CTF Challenge Solver

```python
from dumbemu import DumbEmu

# Load the challenge binary
emu = DumbEmu("crackme.exe")

# Set up input buffer
addr = emu.malloc(256)
emu.string.ascii(addr, "FLAG{TEST}")

# Call validation function
valid = emu.call(0x401000, None, addr)

if valid:
    print("[+] Valid flag!")
else:
    print("[-] Invalid flag")
```

### Cross-Platform Stubbing

```python
from dumbemu import DumbEmu
from dumbemu.stubs import Proto, Symbol

# Windows example
emu_win = DumbEmu("malware.exe", verbose=True)

def MessageBoxA(stubs, uc, args):
    text_ptr = args[1]
    text = stubs._str(text_ptr) if text_ptr else ""
    print(f"[MessageBox] {text}")
    return 1  # IDOK

emu_win.stub("user32.dll", "MessageBoxA",
             Proto("MessageBoxA", "stdcall", [4, 4, 4, 4]),
             MessageBoxA)

# Linux example
emu_linux = DumbEmu("binary.elf", verbose=True)

def printf_stub(stubs, uc, args):
    fmt_ptr = args[0]
    fmt = stubs._str(fmt_ptr)
    print(f"[printf] {fmt}")
    return len(fmt)

emu_linux.stub("libc.so.6", "printf",
               Symbol("printf", "cdecl", [8]),
               printf_stub)

# Execute
emu_win.call(0x401000)
emu_linux.call(0x400580)
```

## Architecture

DumbEmu is organized into logical components:

```
dumbemu/
├── core/            # Core emulator components
│   ├── emulator.py  # Main DumbEmu class
│   ├── context.py   # Emulation context
│   └── exceptions.py # Custom exception hierarchy
├── arch/            # CPU architecture implementations
│   ├── base.py      # Abstract architecture base
│   ├── x86.py       # x86 32-bit implementation
│   ├── x64.py       # x64 64-bit implementation
│   ├── regs.py      # Register access layer
│   └── args.py      # Calling convention argument handling
├── mem/             # Memory management
│   ├── memory.py    # Core memory operations with page tracking
│   ├── stack.py     # Stack management
│   ├── alloc.py     # Memory allocator
│   ├── hooks.py     # Code hooks (dynamic mode switching)
│   └── mapping.py   # Mapping utilities
├── data/            # Data operations
│   ├── strings.py   # String operations (chunked reads)
│   └── structs.py   # Struct pack/unpack
├── stubs/           # Import stubbing (cross-platform)
│   ├── core.py      # Unified stub manager
│   ├── win32.py     # Built-in Windows API stubs
│   └── posix.py     # Built-in POSIX/libc stubs
├── formats/         # Binary format parsers
│   ├── factory.py   # Auto-detection factory
│   ├── base.py      # Abstract loader base
│   ├── pe.py        # Windows PE loader
│   ├── elf.py       # Linux ELF loader
│   └── utils.py     # Shared loader utilities
├── platforms/       # Platform-specific environments
│   ├── windows/     # Windows TEB/PEB
│   │   └── tebpeb.py
│   └── linux/       # Linux AuxV
│       └── auxv.py
├── debug/           # Debugging tools
│   └── tracer.py    # Execution tracer (ring buffer)
└── utils/           # Utilities
    ├── constants.py # Constants, register maps, ABIs
    ├── logger.py    # Logging system
    └── types.py     # Type aliases
```


## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built on [Unicorn Engine](https://www.unicorn-engine.org/)
- PE parsing via [LIEF](https://lief-project.github.io/)