"""Code hook management."""
from typing import Callable, Dict, List, Any
from ..utils.constants import UC_HOOK_CODE
from ..utils.logger import log

class Hooks:
    """Manages address-based code hooks."""
    
    def __init__(self, ctx) -> None:
        self.uc = ctx.uc
        self._hooks: Dict[int, List[Callable[[Any, int], None]]] = {}
        self._handle = self.uc.hook_add(UC_HOOK_CODE, self._code_hook)

    def add(self, addr: int, callback: Callable[[Any, int], None]) -> None:
        """Add hook at address."""
        addr = int(addr)
        if addr not in self._hooks:
            self._hooks[addr] = []
        self._hooks[addr].append(callback)
        log.debug(f"Hooks.add: registered hook at 0x{addr:08X} (total: {len(self._hooks[addr])} hooks)")

    def _code_hook(self, uc, addr: int, size: int, user_data):
        """Internal hook dispatcher."""
        if callbacks := self._hooks.get(addr):
            log.debug(f"Hooks._code_hook: executing {len(callbacks)} hooks at 0x{addr:08X}")
            for cb in callbacks:
                try:
                    cb(uc, addr)
                except Exception as e:
                    log.error(f"Hooks._code_hook: error in hook at 0x{addr:08X}: {e}")
