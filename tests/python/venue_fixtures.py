"""Synthetic venue fixtures; no live deployment or asset mapping is asserted."""

from afp_payment import (
    AZTEC_NATIVE_PAY_VENUE,
    AZTEC_NULLIFIER_SEMANTICS,
    AZTEC_PAY_RECEIPT_PROFILE,
    AZTEC_PROTOCOL_FEE_ROUTE,
    HARD_S3_RISK_PROFILE,
    MAX_U128,
    AfpPaymentPolicyV2,
    AfpPaymentQuoteV2,
    Obligation,
    VenueDeployment,
    VenueRate,
    VenueSettlement,
)

ASSET = "eip155:1/erc20:0x" + "c0" * 20
MANIFEST = "sha256:" + "11" * 32
INSTANCE = "0x" + "22" * 32
CLASS = "0x" + "13" * 32
RECIPIENT = "0x" + "14" * 32
ASSET_COMMITMENT = "0x" + "15" * 32
PORTAL = "0x" + "66" * 20
NONCE = "0x" + "ab" * 32
SESSION_CONTEXT = "X_" + "ee" * 32


def venue_deployment(**overrides) -> VenueDeployment:
    values = {
        "venue_profile": AZTEC_NATIVE_PAY_VENUE,
        "network_id": "aztec:conformance",
        "anchor_chain_id": "eip155:1",
        "asset_id": ASSET,
        "asset_commitment": ASSET_COMMITMENT,
        "contract_class_id": CLASS,
        "contract_instance_id": INSTANCE,
        "settlement_portal_id": PORTAL,
        "manifest_hash": MANIFEST,
        "fee_route": AZTEC_PROTOCOL_FEE_ROUTE,
        "receipt_profile": AZTEC_PAY_RECEIPT_PROFILE,
        "nullifier_semantics": AZTEC_NULLIFIER_SEMANTICS,
        "max_note_value": str(MAX_U128),
        "asset_risk_profile": HARD_S3_RISK_PROFILE,
    }
    values.update(overrides)
    return VenueDeployment(**values)


def venue_policy(**overrides) -> AfpPaymentPolicyV2:
    values = {
        "deployment": venue_deployment(),
        "accepted_rate_sources": ("bilateral:ethereum-weth-usd:v1",),
        "max_quote_lifetime_seconds": 300,
        "max_slippage_bps": 100,
        "required_finality": "finalized",
    }
    values.update(overrides)
    return AfpPaymentPolicyV2(**values)


def venue_quote(**overrides) -> AfpPaymentQuoteV2:
    payment_policy = venue_policy()
    values = {
        "quote_id": "quote-venue-0001",
        "session_ref": "session-0001",
        "session_context": SESSION_CONTEXT,
        "policy_hash": payment_policy.policy_hash,
        "obligation": Obligation(currency="USD", amount_minor="2500"),
        "settlement": VenueSettlement(
            venue_profile=AZTEC_NATIVE_PAY_VENUE,
            network_id="aztec:conformance",
            anchor_chain_id="eip155:1",
            asset_id=ASSET,
            contract_instance_id=INSTANCE,
            settlement_portal_id=PORTAL,
            manifest_hash=MANIFEST,
            recipient_id=RECIPIENT,
            amount_atomic="10000000000000000",
            asset_risk_profile=HARD_S3_RISK_PROFILE,
        ),
        "rate": VenueRate(
            source="bilateral:ethereum-weth-usd:v1",
            usd_minor="250000",
            asset_atomic="1000000000000000000",
            reference_usd_minor="250000",
            reference_asset_atomic="1000000000000000000",
        ),
        "quoted_at": "2026-07-11T12:00:00Z",
        "expires_at": "2026-07-11T12:05:00Z",
        "max_slippage_bps": 100,
        "quote_nonce": NONCE,
    }
    values.update(overrides)
    return AfpPaymentQuoteV2(**values)
