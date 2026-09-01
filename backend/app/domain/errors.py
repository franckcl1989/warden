"""Stable error catalog and domain exception for the API error envelope.

The catalog is built from the GENERATED registry (``app.generated.errors``),
which is itself regenerated from ``contracts/error-codes.json``. The domain
layer must not import FastAPI; ``AppError`` is the transport-agnostic carrier
and the API boundary filters ``details`` to the contract's safe fields.
"""

from __future__ import annotations

from collections.abc import Mapping

from app.domain.contracts import StableError
from app.generated.errors import STABLE_ERRORS


class AppError(Exception):
    """Domain exception carrying a stable contract error code.

    ``details`` may contain anything; the API boundary restricts the keys to
    the code's ``safe_detail_fields`` before anything leaves the process.
    """

    def __init__(self, code: str, message: str, *, details: Mapping[str, object] | None = None) -> None:
        self.code = code
        self.message = message
        self.details: dict[str, object] = dict(details) if details else {}
        super().__init__(f"{code}: {message}")


class StableErrorCatalog:
    """Lookup over the generated stable error registry."""

    def __init__(self, errors: Mapping[str, StableError] | None = None) -> None:
        self._errors: dict[str, StableError] = dict(errors) if errors is not None else dict(STABLE_ERRORS)

    def get(self, code: str) -> StableError | None:
        return self._errors.get(code)

    def http_status_for(self, code: str) -> int:
        error = self.get(code)
        return error.http_status if error is not None else 500

    def filter_details(self, code: str, details: Mapping[str, object]) -> dict[str, object]:
        """Keep only the keys the contract allows for this code."""
        error = self.get(code)
        if error is None:
            return {}
        return {key: value for key, value in details.items() if key in error.safe_detail_fields}


CATALOG = StableErrorCatalog()
