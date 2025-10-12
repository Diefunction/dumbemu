# DumbEmu

A lightweight, performant PE emulator built on Unicorn Engine for Windows executable analysis and function testing.

## Features

### Core Capabilities
- **Architecture Support**: Automatic detection and support for x86 (32-bit) and x64 (64-bit) PE files
- **PE Loading**: Complete PE parsing with proper section mapping and permissions
- **Windows Environment**: TEB/PEB structure initialization for Windows-aware execution
- **IAT Stubbing**: Import Address Table hooking with customizable function stubs

### Memory Management
- **Smart Allocation**: Page-aligned memory allocator with tracking
- **Protection Control**: Fine-grained memory permission management  
- **String Operations**: Native support for ASCII and UTF-16 strings
- **Struct Operations**: Pack/unpack structured data with format strings

### Execution Control
- **Function Calling**: Proper x86/x64 calling convention implementation
- **Raw Execution**: Direct code execution without function overhead
- **Breakpoints**: Set breakpoints to pause execution at specific addresses
- **Instruction Limits**: Prevent infinite loops with instruction count limits
- **Execution Tracing**: Record executed addresses and instruction counts

### Advanced Features
- **Code Hooks**: Install callbacks at specific addresses
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

# Load PE file (architecture auto-detected)
emu = DumbEmu("target.exe")

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

### IAT Stubbing

```python
from dumbemu.win.iat import Proto

# Define a stub for GetProcAddress
def get_proc_stub(iat, uc, args):
    # args = (hModule, lpProcName)
    proc_name_ptr = args[1]
    proc_name = iat.strings.cstring(proc_name_ptr)
    print(f"GetProcAddress called for: {proc_name}")
    return 0x12345678  # Return fake address

# Register the stub
emu.stub("kernel32.dll", "GetProcAddress", 
         Proto("GetProcAddress", emu.ctx.conv, [4, 4]),
         get_proc_stub)

# Now any calls to GetProcAddress will use our stub
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

# Raw execution (no function call setup)
emu.execute(0x401000, count=100)  # Execute 100 instructions
```

## API Reference

### DumbEmu Class

```python
DumbEmu(path: str, verbose: bool = False)
```

#### Core Methods

- `call(addr, breakpoint=None, *args, max_insns=1000000) -> int`
  - Call function with arguments
  - Returns function return value
  
- `execute(addr, until=None, count=None)`
  - Execute raw code without function call setup
  
- `hook(addr, callback)`
  - Install code hook at address
  
- `malloc(size, prot=RW) -> int`
  - Allocate memory region
  
- `free(addr) -> bool`
  - Free allocated memory

#### Memory Access

- `read(addr, size) -> bytes`
  - Read bytes from memory
  
- `write(addr, data)`
  - Write bytes to memory

#### Component Access

- `emu.mem` - Memory manager
- `emu.regs` - Register access
- `emu.stack` - Stack operations
- `emu.struct` - Struct pack/unpack
- `emu.string` - String operations
- `emu.tracer` - Execution tracer
- `emu.iat` - IAT stub manager

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
- `wstring(addr, max_len=4096) -> str` - Read null-terminated UTF-16
- `ascii(addr, text, null=True)` - Write ASCII string
- `wide(addr, text, null=True)` - Write UTF-16 string

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

### Windows API Stubbing

```python
from dumbemu import DumbEmu
from dumbemu.win.iat import Proto

emu = DumbEmu("malware.exe", verbose = True)

# Stub common Windows APIs
def MessageBoxA(iat, uc, args):
    text_ptr = args[1]
    text = iat.strings.cstring(text_ptr) if text_ptr else ""
    print(f"[MessageBox] {text}")
    return 1  # IDOK

emu.stub("user32.dll", "MessageBoxA",
         Proto("MessageBoxA", emu.ctx.conv, [4, 4, 4, 4]),
         MessageBoxA)

# Run malware function
emu.call(0x401000)
```

## Architecture

DumbEmu is organized into logical components:

```
dumbemu/
├── cpu/          # CPU architecture and registers
│   ├── base.py   # Abstract architecture base
│   ├── x86.py    # x86 32-bit implementation
│   ├── x64.py    # x64 64-bit implementation
│   └── regs.py   # Register access layer
├── mem/          # Memory management
│   ├── memory.py # Core memory operations
│   ├── stack.py  # Stack management
│   ├── alloc.py  # Memory allocator
│   └── hooks.py  # Code hooks
├── data/         # Data operations
│   ├── strings.py # String operations
│   └── structs.py # Struct pack/unpack
├── win/          # Windows environment
│   ├── iat.py    # IAT stubbing
│   └── tebpeb.py # TEB/PEB structures
├── debug/        # Debugging tools
│   └── tracer.py # Execution tracer
├── pe/           # PE file handling
│   └── loader.py # PE parser and loader
└── utils/        # Utilities
    ├── constants.py # Constants and mappings
    └── logger.py    # Logging system
```


## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built on [Unicorn Engine](https://www.unicorn-engine.org/)
- PE parsing via [LIEF](https://lief-project.github.io/)