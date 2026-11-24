"""§14.4/§14.6 — provisional-agreement envelope growth and graduation.

The *mechanism* is normative; the *curve* is policy (§14.6). A clean (zero-slash)
reputation proof raises the per-interaction envelope by the negotiated
``growth_curve`` factor, capped. Graduation drops the introduction tier's
mandatory bond, yielding a standard §5.5 agreement. The bilateral co-signing of
the resulting ``afp:limit-adjustment:v1`` reuses the §12.6.1 signature machinery
(``afp_session``); this module owns the envelope arithmetic, not the signing.
"""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

from .atoms import IntroductionPolicy, ReputationState

__all__ = ["GrowthRejected", "apply_limit_adjustment", "graduate"]


class GrowthRejected(RuntimeError):
    """A reputation proof that does not justify a limit increase (§14.6)."""


def _amount_str(value: Decimal) -> str:
    """Render a Decimal as a plain amount string (no exponent for integers)."""
    if value == value.to_integral_value():
        return str(int(value))
    return format(value.normalize(), "f")


def apply_limit_adjustment(
    policy: IntroductionPolicy, *, reputation: ReputationState
) -> IntroductionPolicy:
    """Raise the per-interaction envelope by the negotiated curve, capped (§14.6).

    A reputation proof carrying any slash/default event justifies no increase —
    growth is gated on a *clean* provable history. AFP fixes this mechanism; the
    step/cap live in the policy block's ``growth_curve``.
    """
    if reputation.slash_events > 0:
        raise GrowthRejected("reputation proof carries a slash/default event")
    step = Decimal(policy.growth_curve["step_factor"])
    cap = Decimal(policy.growth_curve["cap"])
    grown = min(Decimal(policy.max_per_interaction) * step, cap)
    return replace(policy, max_per_interaction=_amount_str(grown))


def graduate(policy: IntroductionPolicy) -> IntroductionPolicy:
    """Replace with a standard §5.5 agreement: drop the mandatory bond (§14.6)."""
    return replace(policy, bond_ref=None)
