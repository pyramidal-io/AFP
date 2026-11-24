"""Transport abstraction for the AFP NATS namespace (§12.4 / §2.3).

AFP messages travel over a NATS-based transport (§2.3). The §12 session core
does not depend on a *live* broker to be correct — establishment, lifecycle,
identity binding, dispute, commitment, and the envelope all operate over an
abstract publish/subscribe transport. This module defines that abstraction and
ships an in-memory implementation so the acceptance test (two in-process
instances open/close a session and exchange a signed envelope) runs with no
external broker.

A real deployment supplies a NATS-backed ``Transport`` (e.g. wrapping
``nats-py``). The interface is intentionally tiny — ``publish`` and
``subscribe`` over ``afp.{tenant}.{profile}.*`` subjects (§12.4) — and a NATS
adapter is a thin mapping onto ``nats.aio.client``. We do not import ``nats``
here so unit tests never require it; the seam is documented in ``NatsTransport``.

The transport carries opaque ``bytes`` payloads. When the session API publishes
an envelope, it supplies sealed bytes in an ``afp:sealed:v1`` channel frame and
implements no plaintext canonical-envelope fallback. The generic ``Transport``
accepts bytes without validating their frame type; the sealed-content rule is
enforced by the session send/receive boundary, not by an adapter. This protects
session-envelope content, but does not hide subjects, timing, or other routing
metadata; §8 mixnet routing is still required for OB-2 metadata privacy. The
in-memory transport models that *logical* delivery, not the §8 mixnet.
"""

from __future__ import annotations

import fnmatch
from typing import Callable, List, Tuple

__all__ = ["Transport", "InMemoryTransport", "Subscription", "NatsTransport"]

# A subscriber callback receives (subject, payload_bytes).
Handler = Callable[[str, bytes], None]


class Subscription:
    """A handle to an active subscription; ``unsubscribe`` to detach."""

    def __init__(self, transport: "InMemoryTransport", pattern: str, handler: Handler):
        self._transport = transport
        self.pattern = pattern
        self.handler = handler
        self._active = True

    def unsubscribe(self) -> None:
        if self._active:
            self._transport._remove(self)
            self._active = False


class Transport:
    """Abstract AFP transport. Implementations deliver to subject subscribers."""

    def publish(self, subject: str, payload: bytes) -> None:  # pragma: no cover
        raise NotImplementedError

    def subscribe(self, pattern: str, handler: Handler) -> Subscription:  # pragma: no cover
        raise NotImplementedError


class InMemoryTransport(Transport):
    """In-process pub/sub with NATS-style subject wildcards (``*`` and ``>``).

    Synchronous and deterministic: ``publish`` invokes matching subscribers
    inline, in subscription order, which keeps the bilateral session FSM and its
    tests free of async scheduling. Two ``Instance``s sharing one
    ``InMemoryTransport`` model two ADAMAS instances on one logical fabric.
    """

    def __init__(self) -> None:
        self._subs: List[Subscription] = []
        self.published: List[Tuple[str, bytes]] = []  # audit log for tests

    def publish(self, subject: str, payload: bytes) -> None:
        self.published.append((subject, payload))
        for sub in list(self._subs):
            if _subject_matches(sub.pattern, subject):
                sub.handler(subject, payload)

    def subscribe(self, pattern: str, handler: Handler) -> Subscription:
        sub = Subscription(self, pattern, handler)
        self._subs.append(sub)
        return sub

    def _remove(self, sub: Subscription) -> None:
        try:
            self._subs.remove(sub)
        except ValueError:
            pass


def _subject_matches(pattern: str, subject: str) -> bool:
    """NATS subject matching: ``*`` matches one token, ``>`` matches the tail."""
    p_tokens = pattern.split(".")
    s_tokens = subject.split(".")
    for i, p in enumerate(p_tokens):
        if p == ">":
            return True  # matches the remainder
        if i >= len(s_tokens):
            return False
        if p == "*":
            continue
        if p != s_tokens[i]:
            # allow shell-style only for explicit non-wildcard equality fallback
            if not fnmatch.fnmatch(s_tokens[i], p):
                return False
    return len(p_tokens) == len(s_tokens)


class NatsTransport(Transport):
    """Seam for a real NATS-backed transport (``nats-py``).

    Not used by unit tests (they use :class:`InMemoryTransport`) so importing
    this module never requires the ``nats`` package. A production wiring would:

        import nats
        nc = await nats.connect(servers)
        # publish -> nc.publish(subject, payload)
        # subscribe(pattern, handler) -> nc.subscribe(pattern, cb=...)

    mapping AFP subjects (§12.4) directly onto NATS subjects. The async/sync
    bridge and JetStream durability (§2.3) are deployment concerns; the §12 core
    is transport-agnostic by construction. This class is intentionally a stub
    that raises until wired, so a deployment cannot silently run without a
    broker while believing it has one.
    """

    def __init__(self, *_args, **_kwargs) -> None:
        raise NotImplementedError(
            "NatsTransport is a documented seam; wire it to nats-py in a "
            "deployment. Unit/acceptance tests use InMemoryTransport."
        )
