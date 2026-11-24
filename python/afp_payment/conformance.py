"""Hard-S3 interaction-local failure model for AFP §15.7-§15.8."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .quote import PaymentQuoteError

__all__ = ["InteractionLocalFailure"]


@dataclass(frozen=True)
class InteractionLocalFailure:
    """A failed payment affects only that interaction and carries no controls.

    The constructor has no freeze, withdrawal, override, clawback, or reroute
    parameters. Strict decoding rejects those extensions and all non-empty
    effect lists, keeping privileged recovery paths outside the model.
    """

    quote_ref: str
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.quote_ref, str) or not self.quote_ref:
            raise PaymentQuoteError("failure quote_ref must be a non-empty string")
        if not isinstance(self.reason, str) or not self.reason:
            raise PaymentQuoteError("failure reason must be a non-empty string")

    @property
    def scope(self) -> str:
        return "interaction"

    @property
    def effects(self) -> tuple[()]:
        return ()

    def to_dict(self) -> dict[str, object]:
        return {
            "quote_ref": self.quote_ref,
            "reason": self.reason,
            "scope": self.scope,
            "effects": [],
        }

    @classmethod
    def from_dict(cls, data: object) -> "InteractionLocalFailure":
        if not isinstance(data, dict):
            raise PaymentQuoteError("interaction-local failure must be an object")
        required = frozenset({"quote_ref", "reason", "scope", "effects"})
        if set(data) != required:
            raise PaymentQuoteError("interaction-local failure has noncanonical controls")
        if data["scope"] != "interaction":
            raise PaymentQuoteError("payment failure scope must be interaction")
        if data["effects"] != []:
            raise PaymentQuoteError("payment failure must not carry nonlocal effects")
        return cls(quote_ref=data["quote_ref"], reason=data["reason"])
