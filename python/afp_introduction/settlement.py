"""§14.5/§14.7 — the collateral-priced floor and safeguard-compatible recourse.

§14.5: every value interaction at the introduction tier is either trustless
ZKA-direct (atomic, no credit) or bonded (exposure <= posted collateral). There
is no uncollateralized-credit rail. §14.7: a default's recourse is bounded to the
pre-posted escrow and needs the pre-agreed arbiter co-signature; it never touches
base-layer custody (Safeguards 3 & 5). Recovery above the bond is not in-protocol:
financial recourse is limited to the pre-posted escrow, and AFP defines no portable
record of a default for use as reputation with future counterparties.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import Enum

__all__ = ["Rail", "RecourseError", "DefaultOutcome", "within_floor", "resolve_default"]


class Rail(str, Enum):
    ZKA_DIRECT = "zka_direct"  # atomic, no credit (the safe default)
    BONDED = "bonded"          # exposure must be <= posted collateral


class RecourseError(RuntimeError):
    """A slash attempted without the pre-agreed arbiter co-signature (§12.5)."""


def within_floor(*, rail: "Rail | str", exposure: str, posted_collateral: str) -> bool:
    """§14.5 floor: ZKA-direct is always within floor (no credit); bonded requires
    exposure <= collateral. Any other rail is forbidden at this tier."""
    if rail == Rail.ZKA_DIRECT:
        return True
    if rail == Rail.BONDED:
        return Decimal(exposure) <= Decimal(posted_collateral)
    raise ValueError(f"unknown/forbidden settlement rail at introduction tier: {rail!r}")


@dataclass(frozen=True)
class DefaultOutcome:
    slashed: str
    touched_base_layer: bool


def resolve_default(
    *, posted_collateral: str, claimed: str, arbiter_cosigned: bool
) -> DefaultOutcome:
    """§14.7 recourse: slashing is bounded to the pre-posted escrow and needs the
    arbiter co-signature; it NEVER touches base-layer custody (Safeguards 3 & 5)."""
    if not arbiter_cosigned:
        raise RecourseError("slash requires the pre-agreed arbiter co-signature (§12.5)")
    slashed = min(Decimal(claimed), Decimal(posted_collateral))
    return DefaultOutcome(slashed=str(slashed), touched_base_layer=False)
