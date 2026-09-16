import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from dr_source.core.resolution import Resolution, ResolutionReason, ResolutionStatus

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SymbolId:
    """Identity of a source declaration, not a resolved call target.

    Positions are (one-based line, zero-based UTF-8 byte column). Owner and
    signature remain unknown in Phase 1; positions distinguish declarations
    within one file without inferring either of those semantic facts.
    """

    language: str
    file_path: str
    name: str
    owner: Optional[str] = None
    signature: Optional[str] = None
    declaration_position: Optional[Tuple[int, int]] = None


@dataclass(frozen=True)
class FunctionDefinition:
    name: str
    file_path: str
    node: Any # The AST node (tree-sitter or native AST)
    language: str
    declaration_position: Optional[Tuple[int, int]] = None

    @property
    def symbol_id(self) -> SymbolId:
        return SymbolId(
            language=self.language,
            file_path=os.path.normpath(self.file_path),
            name=self.name,
            declaration_position=self.declaration_position,
        )


class ProjectIndex:
    """
    A global index of all functions and classes discovered across the project.
    Used for inter-file taint analysis.
    """
    def __init__(self, project_root: Optional[str] = None) -> None:
        self.project_root = os.path.normpath(os.path.abspath(project_root)) if project_root else None
        self.functions: Dict[SymbolId, FunctionDefinition] = {}
        # Nested buckets support both (language, name) and legacy name queries.
        self._by_name: Dict[str, Dict[str, Set[SymbolId]]] = {}

    def register_function(
        self,
        name: str,
        file_path: str,
        node: Any,
        language: str,
        *,
        declaration_position: Optional[Tuple[int, int]] = None,
    ) -> None:
        """Retain a declaration and its original parser payload.

        Legacy callers may omit the position for a unique name in a file.
        Repeating the same payload is idempotent. A different payload with the
        same identity is an error, never an overwrite: supply distinct source
        positions for distinct declarations, or a fresh index for changed code.
        """
        definition = FunctionDefinition(name, file_path, node, language, declaration_position)
        symbol_id = definition.symbol_id
        existing = self.functions.get(symbol_id)
        if existing is not None:
            if existing.node is not node:
                raise ValueError(f"Conflicting registration for {symbol_id!r}")
            return
        self.functions[symbol_id] = definition
        self._by_name.setdefault(name, {}).setdefault(language, set()).add(symbol_id)

    def find_candidates(
        self, name: str, language: Optional[str] = None
    ) -> List[FunctionDefinition]:
        """Return every exact-name candidate, optionally restricted by language.

        Results are sorted by source path, declaration position, then language
        and name. This order is for reproducibility, not target preference.
        Even a singleton is only a name candidate, not proof of call binding.
        """
        languages = self._by_name.get(name, {})
        if language is None:
            symbol_ids = {symbol for bucket in languages.values() for symbol in bucket}
        else:
            symbol_ids = languages.get(language, set())
        ordered_ids = sorted(
            symbol_ids,
            key=lambda symbol: (
                symbol.file_path,
                symbol.declaration_position or (0, 0),
                symbol.language,
                symbol.name,
            ),
        )
        return [self.functions[symbol] for symbol in ordered_ids]

    def get_definition(self, symbol_id: SymbolId) -> Optional[FunctionDefinition]:
        """Return the definition retained for a canonical symbol identity."""
        return self.functions.get(symbol_id)

    def resolve_unique(
        self, name: str, language: Optional[str] = None
    ) -> Resolution:
        """Convert deterministic candidate discovery into a unique decision.

        This is deliberately only an index adapter. It does not apply import,
        module, receiver, or other language-specific resolution semantics.
        """
        candidates = self.find_candidates(name, language=language)
        candidate_ids = tuple(candidate.symbol_id for candidate in candidates)
        if not candidates:
            return Resolution.unresolved()
        if len(candidates) > 1:
            return Resolution.ambiguous(candidate_ids)
        return Resolution.resolved(candidate_ids[0], candidate_ids)

    def find_function(
        self, name: str, *, language: Optional[str] = None
    ) -> Optional[FunctionDefinition]:
        """Return only a unique candidate in the requested language, if supplied.

        Omitting language preserves the legacy cross-language lookup semantics.
        Missing names return None. Ambiguous names return None with a warning
        so skipped inter-file simulation cannot masquerade as complete analysis.
        A unique name candidate is not proof of semantic call binding.
        """
        resolution = self.resolve_unique(name, language=language)
        if resolution.status is ResolutionStatus.RESOLVED and resolution.symbol is not None:
            return self.get_definition(resolution.symbol)
        if resolution.status is ResolutionStatus.AMBIGUOUS:
            logger.warning(
                "Ambiguous function %r: %d candidates; language=%s; "
                "inter-file analysis skipped: %s",
                name,
                len(resolution.candidates),
                language if language is not None else "all",
                list(resolution.candidates),
            )
        return None
