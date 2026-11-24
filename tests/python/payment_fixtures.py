"""Shared §15 payment-quote fixtures."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from afp_payment import (
    AfpPaymentPolicyV1,
    AfpPaymentQuoteV1,
    Obligation,
    PaymentDeployment,
    Rate,
    Settlement,
    InMemoryReplayStore,
    accept_payment_quote,
    sign_payment_quote,
)
from afp_session import InMemoryTransport, Instance, RemoteParty, keri

BASE_WETH9 = "0x4200000000000000000000000000000000000006"
POOL = "0x1234567890abcdef1234567890abcdef12345678"
POOL_CONTEXT = "0x" + "01" * 32
SESSION_CONTEXT = "X_" + "22" * 32
NONCE = "0x" + "ab" * 32


def payment_policy(**overrides) -> AfpPaymentPolicyV1:
    values = {
        "deployment": PaymentDeployment(
            chain_id=8453,
            asset=BASE_WETH9,
            pool=POOL,
            pool_context=POOL_CONTEXT,
            asset_risk_profile="zka:asset-risk:s3-hard:v1",
        ),
        "accepted_rate_sources": ("bilateral:base-weth-usd:v1",),
        "max_quote_lifetime_seconds": 300,
        "max_slippage_bps": 100,
        "required_finality": "safe",
    }
    values.update(overrides)
    return AfpPaymentPolicyV1(**values)


def payment_quote(**overrides) -> AfpPaymentQuoteV1:
    values = {
        "quote_id": "quote-2026-07-11-0001",
        "session_ref": "session-0001",
        "session_context": SESSION_CONTEXT,
        "obligation": Obligation(currency="USD", amount_minor="2500"),
        # 25 USD at 2,500 USD/WETH = 0.01 WETH.
        "settlement": Settlement(
            chain_id=8453,
            asset=BASE_WETH9,
            pool=POOL,
            amount_wei="10000000000000000",
            pool_context=POOL_CONTEXT,
            asset_risk_profile="zka:asset-risk:s3-hard:v1",
        ),
        "rate": Rate(
            source="bilateral:base-weth-usd:v1",
            usd_minor="250000",
            weth_wei="1000000000000000000",
            reference_usd_minor="250000",
            reference_weth_wei="1000000000000000000",
        ),
        "quoted_at": "2026-07-11T12:00:00Z",
        "expires_at": "2026-07-11T12:05:00Z",
        "max_slippage_bps": 100,
        "quote_nonce": NONCE,
    }
    values.update(overrides)
    return AfpPaymentQuoteV1(**values)


ACCEPTED_AT = datetime(2026, 7, 11, 12, 1, 0, tzinfo=timezone.utc)


def _payment_acceptance_setup(
    *, policy=None, quote_factory=payment_quote, profile="pay", quote_transform=None,
    replay_store=None,
):
    now = ACCEPTED_AT
    initiator_tenant = keri.Identity.incept_tenant()
    initiator = keri.Identity.incept_entity(initiator_tenant)
    responder_tenant = keri.Identity.incept_tenant()
    responder = keri.Identity.incept_entity(responder_tenant)
    initiator_remote = RemoteParty(
        initiator.kel, initiator_tenant.kel, witness_keys={}
    )
    responder_remote = RemoteParty(
        responder.kel, responder_tenant.kel, witness_keys={}
    )
    transport = InMemoryTransport()
    # Mutable so tests can advance the session owner's clock past expiry.
    session_clock = {"now": now.timestamp() - 60}
    clock = lambda: session_clock["now"]
    initiator_instance = Instance(
        tenant=initiator_tenant,
        entity=initiator,
        transport=transport,
        clock=clock,
    )
    responder_instance = Instance(
        tenant=responder_tenant,
        entity=responder,
        transport=transport,
        clock=clock,
    )
    policy = payment_policy() if policy is None else policy
    fsm = initiator_instance.propose(
        responder_tenant_aid=responder_tenant.aid,
        responder_entity_aid=responder.aid,
        responder_remote=responder_remote,
        agreement_ref="agreement-1",
        agreement_version="1",
        profile=profile,
        profile_policy_hash=policy.policy_hash,
        ttl_seconds=660,
        session_id="session-0001",
    )
    responder_fsm = responder_instance.accept(
        fsm.atom, initiator_remote=initiator_remote
    )
    initiator_instance.confirm_open(
        fsm, responder_fsm.atom, responder_remote=responder_remote
    )
    initiator_instance.activate(fsm)
    live_session = initiator_instance.verified_live_session(fsm)
    session = live_session.to_atom()
    quote = quote_factory(session_context=session.session_context)
    quote = sign_payment_quote(quote, initiator, role="initiator", signed_at=now)
    quote = sign_payment_quote(quote, responder, role="responder", signed_at=now)
    if quote_transform is not None:
        quote = quote_transform(quote)
    inputs = {
        "quote": quote,
        "policy": policy,
        "live_session": live_session,
        "initiator_remote": initiator_remote,
        "responder_remote": responder_remote,
        "replay_store": InMemoryReplayStore() if replay_store is None else replay_store,
        "now": now,
    }
    return inputs, SimpleNamespace(
        owner=initiator_instance, fsm=fsm, session_clock=session_clock
    )


def payment_acceptance_inputs(
    *, policy=None, quote_factory=payment_quote, profile="pay", quote_transform=None
):
    """Build real signed inputs and a live session for acceptance tests."""
    inputs, _session = _payment_acceptance_setup(
        policy=policy, quote_factory=quote_factory, profile=profile,
        quote_transform=quote_transform,
    )
    return inputs


def accepted_payment_dispatch(
    *, policy=None, quote_factory=payment_quote, profile="pay", quote_transform=None,
    replay_store=None,
):
    """Return a real acceptance with its ledger and live-session controls."""
    inputs, session = _payment_acceptance_setup(
        policy=policy, quote_factory=quote_factory, profile=profile,
        quote_transform=quote_transform, replay_store=replay_store,
    )
    return SimpleNamespace(
        accepted=accept_payment_quote(**inputs),
        ledger=inputs["replay_store"],
        live_session=inputs["live_session"],
        owner=session.owner,
        fsm=session.fsm,
        session_clock=session.session_clock,
    )


def accepted_payment_quote_and_ledger(
    *, policy=None, quote_factory=payment_quote, profile="pay", quote_transform=None
):
    """Return real acceptance capability and its authoritative ledger."""
    dispatch = accepted_payment_dispatch(
        policy=policy, quote_factory=quote_factory, profile=profile,
        quote_transform=quote_transform,
    )
    return dispatch.accepted, dispatch.ledger


def accepted_payment_quote():
    """Return a capability minted through the real §15 acceptance path."""
    accepted, _ledger = accepted_payment_quote_and_ledger()
    return accepted
