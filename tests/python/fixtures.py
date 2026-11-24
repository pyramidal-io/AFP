"""Shared fixtures for the AFP session-core test suite."""

import _path  # noqa: F401  (path setup)

from afp_session import keri
from afp_session.channel import ChannelBinding, ChannelEndpoint, ChannelRole
from afp_session.session import Instance, RemoteParty
from afp_session.transport import InMemoryTransport


def make_witness():
    """A witness whose AID certifies its signing key through its own KEL."""
    identity = keri.Identity.incept_tenant()
    return keri.Witness(identity.aid, identity.signing_key)


def make_witnessed_tenant(threshold=2, n=3):
    """A witnessed tenant identity + entity, with the witness public-key map."""
    witnesses = [make_witness() for _ in range(n)]
    keys = {w.aid: w.public_key for w in witnesses}
    tenant = keri.Identity.incept_tenant(witnesses=witnesses, threshold=threshold)
    entity = keri.Identity.incept_entity(tenant, witnesses=witnesses, threshold=threshold)
    return tenant, entity, keys


def make_pair(transport=None, witnessed=False):
    """Two instances (A initiator, B responder) over a shared transport.

    Returns ``(transport, A, B, remoteA, remoteB)`` where ``remoteX`` is the
    verifier-facing material the *other* side uses to verify X (§12.3).
    """
    transport = transport or InMemoryTransport()
    if witnessed:
        tA, eA, kA = make_witnessed_tenant()
        tB, eB, kB = make_witnessed_tenant()
    else:
        tA = keri.Identity.incept_tenant()
        eA = keri.Identity.incept_entity(tA)
        kA = {}
        tB = keri.Identity.incept_tenant()
        eB = keri.Identity.incept_entity(tB)
        kB = {}
    A = Instance(tenant=tA, entity=eA, transport=transport)
    B = Instance(tenant=tB, entity=eB, transport=transport)
    remoteA = RemoteParty(eA.kel, tA.kel, witness_keys=kA)
    remoteB = RemoteParty(eB.kel, tB.kel, witness_keys=kB)
    return transport, A, B, remoteA, remoteB


def establish_channels(A, B, remote_a, remote_b, session_atom):
    """Establish channels with fresh ephemeral keys for one OPEN AFP session.

    Keeping this here lets session-exchange tests focus on the transport seam
    instead of duplicating channel setup.
    """
    binding = ChannelBinding.from_session(session_atom)
    initiator = ChannelEndpoint.create(binding, ChannelRole.INITIATOR, A.entity)
    responder = ChannelEndpoint.create(binding, ChannelRole.RESPONDER, B.entity)
    return (
        initiator.establish(responder.attestation, remote_b),
        responder.establish(initiator.attestation, remote_a),
    )
