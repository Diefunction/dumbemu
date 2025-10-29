"""Code execution hook management."""
from __future__ import annotations
from typing import Callable, Dict, List, Any, Optional
from ..utils.constants import UC_HOOK_CODE
from ..utils.logger import log

class Hooks:
    """Address-based code execution hooks with dynamic mode switching.
    
    Manages callbacks for specific addresses to intercept and monitor code execution.
    Automatically switches from targeted hooks (fast for few addresses) to global
    dispatch (efficient for many addresses) when threshold is exceeded.
    """
    
    # Threshold for switching from targeted to global mode
    HOOK_THRESHOLD = 32  # Default threshold for switching to global dispatch
    
    def __init__(self, ctx, targeted: bool = True, threshold: int | None = None) -> None:
        """Initialize hook manager.
        
        Args:
            ctx: Emulation context
            targeted: If True, start with targeted hooks (default)
                     If False, use global hook from the start
            threshold: Optional override for threshold at which to switch to global mode
        """
        self.uc = ctx.uc
        self.targeted = targeted
        self._threshold = int(threshold) if threshold is not None else self.HOOK_THRESHOLD
        self._hooks: Dict[int, List[Callable[[Any, int], None]]] = {}
        self._handles: Dict[int, Any] = {}  # addr -> hook handle for targeted mode
        self._global_handle = None
        # Ensure a sane minimum so threshold=1 allows one targeted addr before switch
        self._effective_threshold = max(2, self._threshold)
        
        # If explicitly requested global mode from start
        if not targeted:
            self._switch_to_global()

    def add(self, addr: int, callback: Callable[[Any, int], None]) -> None:
        """Add hook at address."""
        addr = int(addr)
        if addr not in self._hooks:
            self._hooks[addr] = []
            
            # Check if we should switch to global mode (>= effective threshold)
            if self.targeted and len(self._hooks) >= self._effective_threshold:
                log.debug(
                    f"Hooks: switching to global mode (unique addrs {len(self._hooks)} >= threshold {self._effective_threshold})"
                )
                self._switch_to_global()
            
            # In targeted mode, add a specific hook for this address
            if self.targeted:
                def targeted_hook(uc, hook_addr, size, _):
                    if hook_addr == addr:
                        for cb in self._hooks[addr]:
                            try:
                                cb(uc, addr)
                            except Exception as e:
                                log.error(f"Hooks: error in hook at 0x{addr:08X}: {e}")
                
                # Hook the exact address; use end=addr+1 for robustness across Unicorn builds
                handle = self.uc.hook_add(UC_HOOK_CODE, targeted_hook, begin=addr, end=addr + 1)
                self._handles[addr] = handle
                
        self._hooks[addr].append(callback)
        log.debug(
            f"Hooks.add: registered hook at 0x{addr:08X} "
            f"(total {len(self._hooks[addr])} hooks, {len(self._hooks)} addresses, "
            f"mode: {'targeted' if self.targeted else 'global'})"
        )

    def _switch_to_global(self) -> None:
        """Switch from targeted to global hook mode."""
        # Remove all targeted hooks
        for addr, handle in self._handles.items():
            try:
                self.uc.hook_del(handle)
            except Exception:
                pass
        self._handles.clear()
        
        # Add single global hook
        self._global_handle = self.uc.hook_add(UC_HOOK_CODE, self._code_hook)
        self.targeted = False
    
    def _code_hook(self, uc, addr: int, size: int, user_data):
        """Internal hook dispatcher for global mode."""
        if callbacks := self._hooks.get(addr):
            log.debug(f"Hooks._code_hook: executing {len(callbacks)} hooks at 0x{addr:08X}")
            for cb in callbacks:
                try:
                    cb(uc, addr)
                except Exception as e:
                    log.error(f"Hooks._code_hook: error in hook at 0x{addr:08X}: {e}")
