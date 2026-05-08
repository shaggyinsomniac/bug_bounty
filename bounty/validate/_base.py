"""
bounty.validate._base — Abstract base class and registry for token validators.

Usage::

    from bounty.validate._base import Validator, ValidatorRegistry, REGISTRY
    from bounty.secrets.scanner import SecretCandidate
    import httpx

    async with httpx.AsyncClient(timeout=15) as http:
        validator = REGISTRY.get("github")
        if validator:
            result = await validator.validate(candidate, http)

All validators MUST:
- Use the ``http`` client passed to ``validate()`` — never create their own.
- Return ``status="invalid"`` on 401/403.
- Return ``status="error"`` on network failures / 5xx.
- Never log raw secret values (use ``secret_preview``).
- Be purely read-only: no state-mutating API calls.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

import httpx

from bounty.models import ValidationResult
from bounty.secrets.scanner import SecretCandidate


class Validator(ABC):
    """Abstract base for a single-provider token validator."""

    provider: ClassVar[str]
    """Provider slug that matches ``SecretCandidate.provider``."""

    @abstractmethod
    async def validate(
        self,
        candidate: SecretCandidate,
        http: httpx.AsyncClient,
    ) -> ValidationResult:
        """Validate ``candidate`` against the provider's API.

        Args:
            candidate: The secret candidate to validate.
            http: Shared async HTTP client (caller manages lifecycle).

        Returns:
            A :class:`ValidationResult` describing the outcome.
        """
        ...


class ValidatorRegistry:
    """Registry of :class:`Validator` instances keyed by provider slug."""

    def __init__(self) -> None:
        self._validators: dict[str, Validator] = {}

    def register(self, validator: Validator) -> None:
        """Register a validator instance.

        Args:
            validator: The validator to register.
        """
        self._validators[validator.provider] = validator

    def get(self, provider: str) -> Validator | None:
        """Return the validator for *provider*, or ``None`` if not registered.

        Args:
            provider: Provider slug (e.g. ``"aws"``).

        Returns:
            Validator instance or ``None``.
        """
        return self._validators.get(provider)

    def all_providers(self) -> list[str]:
        """Return sorted list of registered provider slugs.

        Returns:
            Sorted list of provider slug strings.
        """
        return sorted(self._validators.keys())


# Module-level singleton — populated by ``bounty.validate.registry``.
REGISTRY = ValidatorRegistry()

