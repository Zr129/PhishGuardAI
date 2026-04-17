from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from models.models import URLRequest


@dataclass
class CheckResult:
    """
    Returned by every BaseCheck.run() call.

    - triggered: whether this check fired at all
    - is_block:  True  → immediate BLOCK (Tier 1 hard rules)
                 False → contributes score only
    - score:     heuristic weight added to running total
    - reasons:   human-readable explanation strings
    - tier:      'RULE' | 'HEURISTIC' | 'ML' — shown as badge in popup
    """
    triggered: bool         = False
    is_block:  bool         = False
    score:     int          = 0
    reasons:   List[str]    = field(default_factory=list)
    tier:      Optional[str] = None   # 'RULE' | 'HEURISTIC' | 'ML'

    @classmethod
    def clean(cls) -> "CheckResult":
        """Convenience: check did not fire."""
        return cls(triggered=False)


class BaseCheck(ABC):
    """
    Abstract base for all detection checks.
    OCP: to add a new rule, subclass BaseCheck and implement run().
    """

    @abstractmethod
    def run(self, data: "URLRequest", refined: dict) -> CheckResult:
        ...
