from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, TYPE_CHECKING

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
    """
    triggered: bool = False
    is_block: bool = False
    score: int = 0
    reasons: List[str] = field(default_factory=list)

    @classmethod
    def clean(cls) -> "CheckResult":
        """Convenience: check did not fire."""
        return cls(triggered=False)


class BaseCheck(ABC):
    """
    Abstract base for all detection checks.

    OCP: to add a new rule, subclass BaseCheck and
    implement run() — URLAnalyser never needs editing.
    """

    @abstractmethod
    def run(self, data: "URLRequest", refined: dict) -> CheckResult:
        """
        Evaluate this check against the request and extracted features.

        Args:
            data:    the full URLRequest from the extension
            refined: dict produced by URLFeatureExtractor.extract()

        Returns:
            CheckResult describing whether the check fired and its weight
        """
        ...
