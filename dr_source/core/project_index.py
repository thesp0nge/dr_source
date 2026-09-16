import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

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
    def __init__(self) -> None:
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

    def find_function(
        self, name: str, *, language: Optional[str] = None
    ) -> Optional[FunctionDefinition]:
        """Return only a unique candidate in the requested language, if supplied.

        Omitting language preserves the legacy cross-language lookup semantics.
        Missing names return None. Ambiguous names return None with a warning
        so skipped inter-file simulation cannot masquerade as complete analysis.
        A unique name candidate is not proof of semantic call binding.
        """
        candidates = self.find_candidates(name, language=language)
        if len(candidates) == 1:
            return candidates[0]
        if candidates:
            logger.warning(
                "Ambiguous function %r: %d candidates; language=%s; "
                "inter-file analysis skipped: %s",
                name,
                len(candidates),
                language if language is not None else "all",
                [candidate.symbol_id for candidate in candidates],
            )
        return None
