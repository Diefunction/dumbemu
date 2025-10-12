"""Abstract base class for CPU architecture implementations."""
from abc import ABC, abstractmethod
from typing import Any, Tuple, Union, TYPE_CHECKING
from ..utils.constants import Regs

if TYPE_CHECKING:
    from ..context import Context

class Arch(ABC):
    """Abstract base class for CPU architectures."""
    def __init__(self, ctx: 'Context'):
        self.ctx = ctx

    @property
    @abstractmethod
    def sp(self) -> int: ...

    @property
    @abstractmethod
    def ip(self) -> int: ...

    @property
    @abstractmethod
    def ret(self) -> int: ...

    def read(self, reg: Union[int, str]) -> int:
        """Read value from register.
        
        Args:
            reg: Register ID or name
            
        Returns:
            Register value
        """
        id = reg if isinstance(reg, int) else self._to_id(reg)
        return int(self.ctx.uc.reg_read(id))

    def write(self, reg: Union[int, str], value: int) -> None:
        """Write value to register.
        
        Args:
            reg: Register ID or name
            value: Value to write
        """
        id = reg if isinstance(reg, int) else self._to_id(reg)
        self.ctx.uc.reg_write(id, int(value))

    def _to_id(self, name: str) -> int:
        """Convert register name to ID.
        
        Args:
            name: Register name
            
        Returns:
            Register ID
            
        Raises:
            KeyError: If register name unknown
        """
        m = Regs.X64 if self.ctx.is_64 else Regs.X86
        if name not in m:
            raise KeyError(f"Unknown register: {name}")
        return m[name]

    @abstractmethod
    def prep(self, mem: "Mem", sp: int, args: Tuple[Any, ...], shadow: bool = False) -> int:
        """Prepare stack/registers for a function call.
        
        Args:
            mem: Memory manager
            sp: Current stack pointer
            args: Function arguments
            shadow: Whether to reserve shadow space (Win64)
            
        Returns:
            New stack pointer
        """
        ...
