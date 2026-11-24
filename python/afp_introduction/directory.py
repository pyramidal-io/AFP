"""§14.1 — the willingness-to-federate directory.

Structurally the same object as the §8.7 KERI-witnessed mix-node directory: an
opt-in, epoch-bound, witness-replicated list. The load-bearing property is what
it does **not** hold — it lists which tenants are *open* to an introduction, never
which tenants have *paired* (the pairing rides the §8 mixnet and stays
OB-2-private). There is deliberately no ``pairings`` state here.

KERI witness-quorum verification of a published offer reuses ``afp_session.keri``
exactly as ``afp_mixnet.directory`` does for mix nodes; in this reference the
epoch binding (anti-replay) is modelled fully and the witness-quorum check is the
documented §8.7-shared seam.
"""

from __future__ import annotations

from typing import Dict, List

from .atoms import IntroductionOffer

__all__ = ["DirectoryError", "IntroductionDirectory"]


class DirectoryError(RuntimeError):
    """A rejected offer or an unresolvable route (§14.1 rejection rules)."""


class IntroductionDirectory:
    """An epoch-bound store of :class:`IntroductionOffer` records (§14.1).

    Stores offers only — there is no pairing/graph state, by construction. A
    deployment additionally verifies each offer's KERI anchor + witness quorum
    (§4.5) exactly as the §8.7 mix-node directory does (the shared seam).
    """

    def __init__(self, epoch: int) -> None:
        self.epoch = epoch
        self._offers: Dict[str, IntroductionOffer] = {}

    def publish(self, offer: IntroductionOffer) -> None:
        """Accept an offer bound to the current epoch; reject any other.

        Epoch binding is the anti-replay rule mirrored from §8.7: an offer must be
        bound to the directory's *current* epoch. A stale offer (minted against a
        superseded epoch) is rejected as replay; a future-epoch offer is rejected
        because it cannot be validated against an epoch the directory has not
        reached. Only an exact-epoch match is accepted.
        """
        if offer.directory_epoch < self.epoch:
            raise DirectoryError(
                f"offer epoch {offer.directory_epoch} is stale "
                f"(directory at epoch {self.epoch})"
            )
        if offer.directory_epoch > self.epoch:
            raise DirectoryError(
                f"offer epoch {offer.directory_epoch} is ahead of the directory "
                f"(epoch {self.epoch}); it cannot be validated yet"
            )
        # (seam) a deployment verifies offer's KERI anchor + witness quorum here,
        # reusing afp_session.keri — identical to afp_mixnet.directory (§8.7).
        self._offers[offer.tenant_aid] = offer

    def offers(self) -> List[IntroductionOffer]:
        """The currently-open tenants — openness, never pairing (§14.1)."""
        return list(self._offers.values())

    def resolve_route(self, tenant_aid: str) -> str:
        """The §8.8 private-route handle for an open tenant, or raise."""
        offer = self._offers.get(tenant_aid)
        if offer is None:
            raise DirectoryError(f"no published offer for {tenant_aid!r}")
        return offer.route_handle
