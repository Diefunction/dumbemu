"""Execution tracing functionality."""
from __future__ import annotations
from typing import List, Optional, Callable, Any, TYPE_CHECKING
from unicorn import UcError
from ..utils.constants import UC_HOOK_CODE

if TYPE_CHECKING:
    from unicorn import Uc
    from ..context import Context


class Tracer:
    """Trace and analyze code execution."""
    
    def __init__(self, ctx: Context):
        """Initialize tracer.
        
        Args:
            ctx: Emulation context
        """
        self.ctx = ctx
        self.uc = ctx.uc
        self._history: List[int] = []
        self.enabled = False
        self._hook = None
    
    def start(self) -> None:
        """Start tracing execution."""
        if not self.enabled:
            self._history.clear()
            self._hook = self.uc.hook_add(UC_HOOK_CODE, self._trace_hook)
            self.enabled = True
    
    def stop(self) -> List[int]:
        """Stop tracing and return history.
        
        Returns:
            List of executed addresses
        """
        if self.enabled and self._hook:
            try:
                self.uc.hook_del(self._hook)
            except Exception:
                pass
            self._hook = None
            self.enabled = False
        return self._history.copy()
    
    def clear(self) -> None:
        """Clear trace history."""
        self._history.clear()
    
    def _trace_hook(self, uc: Any, addr: int, size: int, _) -> None:
        """Internal hook to record executed addresses."""
        self._history.append(addr)
    
    def run(self, start: int, stop: Optional[int] = None, 
            count: Optional[int] = None) -> tuple[List[int], int]:
        """Run emulation with tracing.
        
        Args:
            start: Start address
            stop: Optional stop address
            count: Optional max instructions
            
        Returns:
            Tuple of (addresses_list, instruction_count)
        """
        self.start()
        
        # Set up stop condition
        if stop:
            def stop_hook(uc, addr, size, _):
                if addr == stop:
                    uc.emu_stop()
            stop_handle = self.uc.hook_add(UC_HOOK_CODE, stop_hook)
        else:
            stop_handle = None
        
        try:
            kwargs = {'count': count} if count else {}
            end = stop if stop else self.ctx.fakeret
            self.uc.emu_start(start, end, **kwargs)
        except UcError:
            pass
        finally:
            if stop_handle:
                try:
                    self.uc.hook_del(stop_handle)
                except Exception:
                    pass
        
        addrs = self.stop()
        return addrs, len(addrs)
    
    def history(self, max_len: Optional[int] = None) -> List[int]:
        """Get execution history.
        
        Args:
            max_len: Optional maximum number of addresses to return
            
        Returns:
            List of executed addresses
        """
        if max_len:
            return self._history[-max_len:].copy()
        return self._history.copy()
    
    def analyze(self) -> dict:
        """Analyze trace data.
        
        Returns:
            Dictionary with analysis results
        """
        if not self._history:
            return {
                'total': 0,
                'unique': 0,
                'common': [],
                'entry': None,
                'exit': None
            }
        
        from collections import Counter
        counts = Counter(self._history)
        
        return {
            'total': len(self._history),
            'unique': len(counts),
            'common': counts.most_common(10),
            'entry': self._history[0],
            'exit': self._history[-1]
        }
