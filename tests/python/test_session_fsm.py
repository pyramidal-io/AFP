"""Session lifecycle FSM tests — legal transitions, abort, timeout (§12.2)."""

import _path  # noqa: F401

import unittest
from threading import Event, Thread

from afp_session import keri
from afp_session.atoms import (
    AfpPartyRef,
    AfpSessionAtom,
    AfpSessionStatus,
    unix_to_session_datetime,
)
from afp_session.session import (
    IdentityBindingError,
    Instance,
    RemoteParty,
    SessionExpired,
    SessionFSM,
    TransitionError,
)
from afp_session.transport import InMemoryTransport

from fixtures import make_witnessed_tenant


def _atom(expires_at=10**11, status=AfpSessionStatus.PROPOSED):
    ref = AfpPartyRef("E_t", "E_e", "D_d", "sig")
    return AfpSessionAtom(
        id="sess-1",
        initiator=ref,
        responder=AfpPartyRef("E_t2", "E_e2", "D_d2", ""),
        agreement_ref="a",
        agreement_version="1",
        profile="work",
        profile_policy_hash="h",
        status=status,
        opened_at=0,
        expires_at=unix_to_session_datetime(expires_at),
        session_context="X_" + "01" * 32,
    )


class LifecycleTest(unittest.TestCase):
    def test_public_lifecycle_mutations_share_the_completion_lock(self):
        operations = {
            "abort": lambda fsm: fsm.abort(),
            "transition": lambda fsm: fsm.transition(AfpSessionStatus.ABORTED),
            "timeout": lambda fsm: fsm.check_timeout(),
        }
        for name, operation in operations.items():
            with self.subTest(operation=name):
                fsm = SessionFSM(
                    _atom(expires_at=10, status=AfpSessionStatus.ACTIVE),
                    clock=lambda: 20,
                )
                started, finished = Event(), Event()
                errors = []

                def mutate():
                    started.set()
                    try:
                        operation(fsm)
                    except Exception as error:
                        errors.append(error)
                    finally:
                        finished.set()

                worker = Thread(target=mutate)
                try:
                    with fsm._state_lock:
                        worker.start()
                        self.assertTrue(started.wait(timeout=2))
                        self.assertFalse(finished.wait(timeout=0.1))
                        self.assertEqual(fsm.atom.status, AfpSessionStatus.ACTIVE)
                finally:
                    worker.join(timeout=2)
                self.assertFalse(worker.is_alive())
                self.assertEqual(errors, [])
                self.assertTrue(finished.is_set())
                self.assertTrue(fsm.is_terminal)

    def test_happy_path_transitions(self):
        fsm = SessionFSM(_atom())
        fsm.atom.responder.signature = "sig2"
        fsm.transition(AfpSessionStatus.OPEN)
        fsm.transition(AfpSessionStatus.ACTIVE)
        fsm.transition(AfpSessionStatus.CLOSING)
        fsm.transition(AfpSessionStatus.CLOSED)
        self.assertEqual(fsm.status, AfpSessionStatus.CLOSED)
        self.assertTrue(fsm.is_terminal)
        self.assertIsNotNone(fsm.atom.closed_at)

    def test_open_requires_both_party_signatures(self):
        fsm = SessionFSM(_atom())

        with self.assertRaisesRegex(TransitionError, "both party signatures"):
            fsm.transition(AfpSessionStatus.OPEN)

        fsm.atom.responder.signature = "sig2"
        fsm.atom.initiator.signature = ""
        with self.assertRaisesRegex(TransitionError, "both party signatures"):
            fsm.transition(AfpSessionStatus.OPEN)

    def test_illegal_skip_rejected(self):
        fsm = SessionFSM(_atom())
        with self.assertRaises(TransitionError):
            fsm.transition(AfpSessionStatus.ACTIVE)  # PROPOSED -> ACTIVE is illegal

    def test_no_transition_from_terminal(self):
        fsm = SessionFSM(_atom(status=AfpSessionStatus.CLOSED))
        with self.assertRaises(TransitionError):
            fsm.transition(AfpSessionStatus.ACTIVE)

    def test_propose_can_reject_to_aborted(self):
        fsm = SessionFSM(_atom())
        fsm.transition(AfpSessionStatus.ABORTED)
        self.assertEqual(fsm.status, AfpSessionStatus.ABORTED)

    def test_abort_from_any_nonterminal_state(self):
        for status in (
            AfpSessionStatus.PROPOSED,
            AfpSessionStatus.OPEN,
            AfpSessionStatus.ACTIVE,
            AfpSessionStatus.CLOSING,
        ):
            fsm = SessionFSM(_atom(status=status))
            fsm.abort("exit")
            self.assertEqual(fsm.status, AfpSessionStatus.ABORTED)

    def test_abort_is_idempotent_on_terminal(self):
        fsm = SessionFSM(_atom(status=AfpSessionStatus.CLOSED))
        fsm.abort()
        self.assertEqual(fsm.status, AfpSessionStatus.CLOSED)  # unchanged


class TimeoutTest(unittest.TestCase):
    def test_expiry_moves_to_expired(self):
        clock = [100.0]
        fsm = SessionFSM(_atom(expires_at=150), clock=lambda: clock[0])
        fsm.atom.responder.signature = "sig2"
        fsm.transition(AfpSessionStatus.OPEN)
        clock[0] = 200.0  # past expires_at
        self.assertTrue(fsm.check_timeout())
        self.assertEqual(fsm.status, AfpSessionStatus.EXPIRED)

    def test_transition_after_expiry_raises(self):
        clock = [100.0]
        fsm = SessionFSM(_atom(expires_at=150), clock=lambda: clock[0])
        fsm.atom.responder.signature = "sig2"
        fsm.transition(AfpSessionStatus.OPEN)
        clock[0] = 200.0
        with self.assertRaises(SessionExpired):
            fsm.transition(AfpSessionStatus.ACTIVE)
        self.assertEqual(fsm.status, AfpSessionStatus.EXPIRED)

    def test_expired_is_terminal(self):
        clock = [200.0]
        fsm = SessionFSM(_atom(expires_at=150), clock=lambda: clock[0])
        fsm.check_timeout()
        self.assertTrue(fsm.is_terminal)
        # check_timeout on a terminal session is a no-op.
        self.assertFalse(fsm.check_timeout())

    def test_abort_still_works_past_expiry(self):
        clock = [200.0]
        fsm = SessionFSM(_atom(expires_at=150), clock=lambda: clock[0])
        # ABORTED is reachable even past expiry (exit is unconditional, SG-5).
        fsm.transition(AfpSessionStatus.ABORTED)
        self.assertEqual(fsm.status, AfpSessionStatus.ABORTED)


class PrincipalBindingTest(unittest.TestCase):
    """§12.3: a session principal is an entity delegated by its claimed tenant."""

    def test_self_rooted_initiator_with_a_genuine_tenant_kel_is_not_accepted(self):
        transport = InMemoryTransport()
        tenant, _entity, witness_keys = make_witnessed_tenant()
        impostor = keri.Identity.incept_tenant()
        responder_tenant = keri.Identity.incept_tenant()
        responder_entity = keri.Identity.incept_entity(responder_tenant)
        initiator = Instance(
            tenant=keri.Identity(tenant.kel, impostor.signing_key, keri.KeyPair.generate()),
            entity=impostor,
            transport=transport,
        )
        responder = Instance(
            tenant=responder_tenant, entity=responder_entity, transport=transport
        )
        fsm = initiator.propose(
            responder_tenant_aid=responder_tenant.aid,
            responder_entity_aid=responder_entity.aid,
            agreement_ref="a",
            agreement_version="1",
            profile="work",
            profile_policy_hash="h",
            responder_remote=RemoteParty(
                responder_entity.kel, responder_tenant.kel, witness_keys={}
            ),
        )
        with self.assertRaisesRegex(IdentityBindingError, "delegated AID"):
            responder.accept(
                fsm.atom,
                initiator_remote=RemoteParty(
                    impostor.kel, tenant.kel, witness_keys=witness_keys
                ),
            )
        self.assertNotIn(fsm.atom.id, responder.sessions)


if __name__ == "__main__":
    unittest.main()
