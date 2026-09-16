"""Structured outcomes for deterministic symbol resolution."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from dr_source.core.project_index import SymbolId


class ResolutionStatus(Enum):
    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"
    AMBIGUOUS = "ambiguous"
    UNSUPPORTED = "unsupported"


class ResolutionReason(Enum):
    NONE = "none"
    NO_CANDIDATES = "no_candidates"
    MULTIPLE_CANDIDATES = "multiple_candidates"
    EXPLICIT_TARGET_NOT_FOUND = "explicit_target_not_found"
    UNSUPPORTED_BINDING = "unsupported_binding"
    UNSUPPORTED_CALL_FORM = "unsupported_call_form"


@dataclass(frozen=True)
class Resolution:
    """An immutable decision over an already discovered candidate set."""

    status: ResolutionStatus
    symbol: Optional["SymbolId"]
    candidates: Tuple["SymbolId", ...]
    reason: ResolutionReason

    def __post_init__(self) -> None:
        if not isinstance(self.candidates, tuple):
            raise TypeError("Resolution candidates must be an immutable tuple")
        if self.status is ResolutionStatus.RESOLVED:
            if self.symbol is None or self.reason is not ResolutionReason.NONE:
                raise ValueError("A resolved result requires a symbol and no failure reason")
            if len(self.candidates) != 1 or self.symbol != self.candidates[0]:
                raise ValueError("A resolved result requires exactly one matching candidate")
        elif self.symbol is not None:
            raise ValueError("Only resolved results may contain a symbol")

        if self.status is ResolutionStatus.UNRESOLVED and self.reason not in {
            ResolutionReason.NO_CANDIDATES,
            ResolutionReason.EXPLICIT_TARGET_NOT_FOUND,
        }:
            raise ValueError("Invalid reason for an unresolved result")
        if self.status is ResolutionStatus.AMBIGUOUS:
            if self.reason is not ResolutionReason.MULTIPLE_CANDIDATES or len(self.candidates) < 2:
                raise ValueError("An ambiguous result requires multiple candidates")
        if self.status is ResolutionStatus.UNSUPPORTED and self.reason not in {
            ResolutionReason.UNSUPPORTED_BINDING,
            ResolutionReason.UNSUPPORTED_CALL_FORM,
        }:
            raise ValueError("Invalid reason for an unsupported result")

    @classmethod
    def resolved(cls, symbol: "SymbolId", candidates: Tuple["SymbolId", ...]) -> "Resolution":
        return cls(ResolutionStatus.RESOLVED, symbol, tuple(candidates), ResolutionReason.NONE)

    @classmethod
    def unresolved(
        cls,
        candidates: Tuple["SymbolId", ...] = (),
        reason: ResolutionReason = ResolutionReason.NO_CANDIDATES,
    ) -> "Resolution":
        if reason is ResolutionReason.NO_CANDIDATES and candidates:
            raise ValueError("A no-candidates result cannot contain candidates")
        return cls(ResolutionStatus.UNRESOLVED, None, tuple(candidates), reason)

    @classmethod
    def ambiguous(cls, candidates: Tuple["SymbolId", ...]) -> "Resolution":
        return cls(ResolutionStatus.AMBIGUOUS, None, tuple(candidates), ResolutionReason.MULTIPLE_CANDIDATES)

    @classmethod
    def unsupported(cls, reason: ResolutionReason) -> "Resolution":
        return cls(ResolutionStatus.UNSUPPORTED, None, (), reason)
