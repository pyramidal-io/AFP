"""Transactional replay-key reservation for AFP §15 payment quotes."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from threading import Lock
from typing import Callable, Protocol
from weakref import WeakSet

from .quote import PaymentQuoteError

__all__ = [
    "AcceptanceEvidenceVerifier",
    "ReplayStore",
    "InMemoryReplayStore",
    "SQLiteReplayStore",
]


class AcceptanceEvidenceVerifier(Protocol):
    """Limited authority for acceptance verification and one route claim."""

    def verify_reservation(
        self,
        quote_id: str,
        quote_hash: str,
        quote_nonce: str,
        acceptance_record_hash: str,
    ) -> bool:
        """Return exactly True only when this tuple is durably accepted."""

    def claim_route(
        self,
        quote_id: str,
        quote_hash: str,
        quote_nonce: str,
        acceptance_record_hash: str,
        transaction_id: str,
    ) -> bool: ...

    def verify_route(
        self,
        quote_id: str,
        quote_hash: str,
        quote_nonce: str,
        acceptance_record_hash: str,
        transaction_id: str,
    ) -> bool: ...


class ReplayStore(Protocol):
    """Atomically reserve replay keys plus the exact signed acceptance record."""

    def reserve(
        self,
        quote_id: str,
        quote_hash: str,
        quote_nonce: str,
        acceptance_record_hash: str,
    ) -> None:
        """Reserve the four-field acceptance tuple or make no state change."""


def _define_acceptance_authority_view():
    token = object()
    issued: WeakSet[object] = WeakSet()

    class _AcceptanceVerifierView:
        __slots__ = ("_verify", "_claim", "_verify_route", "__weakref__")

        def __new__(cls, supplied_token=None, *_args):
            if supplied_token is not token:
                raise TypeError("acceptance authority views are store-issued")
            return super().__new__(cls)

        def verify_reservation(self, *args) -> bool:
            return self._verify(*args)

        def claim_route(self, *args) -> bool:
            return self._claim(*args)

        def verify_route(self, *args) -> bool:
            return self._verify_route(*args)

        def _is_issued(self) -> bool:
            return self in issued

    def issue(verify, claim, verify_route):
        view = _AcceptanceVerifierView(token)
        view._verify = verify
        view._claim = claim
        view._verify_route = verify_route
        issued.add(view)
        return view

    return _AcceptanceVerifierView, issue


_AcceptanceVerifierView, _issue_acceptance_view = _define_acceptance_authority_view()
del _define_acceptance_authority_view


def _replay_error(
    quote_id: str,
    quote_hash: str,
    quote_nonce: str,
    acceptance_record_hash: str,
    by_id: tuple[str, str, str] | None,
    by_nonce: tuple[str, str, str] | None,
) -> PaymentQuoteError:
    if by_id == (
        quote_hash,
        quote_nonce,
        acceptance_record_hash,
    ) and by_nonce == (quote_id, quote_hash, acceptance_record_hash):
        return PaymentQuoteError("duplicate accepted payment quote")
    if by_id is not None:
        return PaymentQuoteError("quote_id was already accepted with different content")
    if by_nonce is not None:
        return PaymentQuoteError("quote nonce was already accepted by a different quote")
    return PaymentQuoteError("payment replay reservation failed closed")


class InMemoryReplayStore:
    """Process-local replay store for tests only; not production-conformant."""

    def __init__(self) -> None:
        self._by_id: dict[str, tuple[str, str, str]] = {}
        self._by_nonce: dict[str, tuple[str, str, str]] = {}
        self._claimed_transaction: dict[str, str] = {}
        self._transaction_owner: dict[str, str] = {}
        self._lock = Lock()

    def reserve(
        self,
        quote_id: str,
        quote_hash: str,
        quote_nonce: str,
        acceptance_record_hash: str,
    ) -> None:
        with self._lock:
            by_id = self._by_id.get(quote_id)
            by_nonce = self._by_nonce.get(quote_nonce)
            if by_id is not None or by_nonce is not None:
                raise _replay_error(
                    quote_id,
                    quote_hash,
                    quote_nonce,
                    acceptance_record_hash,
                    by_id,
                    by_nonce,
                )
            self._by_id[quote_id] = (
                quote_hash,
                quote_nonce,
                acceptance_record_hash,
            )
            self._by_nonce[quote_nonce] = (
                quote_id,
                quote_hash,
                acceptance_record_hash,
            )

    def verifier_view(
        self, _issue_view=_issue_acceptance_view
    ) -> AcceptanceEvidenceVerifier:
        def verify(
            quote_id: str,
            quote_hash: str,
            quote_nonce: str,
            acceptance_record_hash: str,
        ) -> bool:
            with self._lock:
                return self._by_id.get(quote_id) == (
                    quote_hash,
                    quote_nonce,
                    acceptance_record_hash,
                ) and (
                    self._by_nonce.get(quote_nonce)
                    == (quote_id, quote_hash, acceptance_record_hash)
                )

        def claim(*args) -> bool:
            quote_id, quote_hash, quote_nonce, record_hash, transaction_id = args
            with self._lock:
                exact = self._by_id.get(quote_id) == (
                    quote_hash, quote_nonce, record_hash
                ) and self._by_nonce.get(quote_nonce) == (
                    quote_id, quote_hash, record_hash
                )
                if not exact:
                    return False
                claimed = self._claimed_transaction.get(quote_id)
                if claimed is None:
                    owner = self._transaction_owner.get(transaction_id)
                    if owner is not None and owner != quote_id:
                        raise PaymentQuoteError(
                            "transaction is already claimed by another accepted quote"
                        )
                    self._claimed_transaction[quote_id] = transaction_id
                    self._transaction_owner[transaction_id] = quote_id
                    return True
                if claimed != transaction_id:
                    raise PaymentQuoteError("accepted quote already claimed by another transaction")
                return True

        def verify_route(*args) -> bool:
            quote_id, quote_hash, quote_nonce, record_hash, transaction_id = args
            with self._lock:
                return self._by_id.get(quote_id) == (
                    quote_hash, quote_nonce, record_hash
                ) and self._claimed_transaction.get(quote_id) == transaction_id

        return _issue_view(verify, claim, verify_route)


class SQLiteReplayStore:
    """Durable store for atomic signed acceptance-record reservations."""

    def __init__(self, path: str) -> None:
        if not isinstance(path, str) or not path:
            raise PaymentQuoteError("SQLite replay-store path must be non-empty")
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                path, isolation_level=None, check_same_thread=False
            )
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS accepted_payment_quotes (
                    quote_id TEXT PRIMARY KEY,
                    quote_hash TEXT NOT NULL,
                    quote_nonce TEXT NOT NULL UNIQUE,
                    acceptance_record_hash TEXT NOT NULL,
                    claimed_transaction_id TEXT,
                    UNIQUE (quote_id, claimed_transaction_id)
                )
                """
            )
            columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(accepted_payment_quotes)"
                ).fetchall()
            }
            if "acceptance_record_hash" not in columns:
                connection.execute(
                    "ALTER TABLE accepted_payment_quotes "
                    "ADD COLUMN acceptance_record_hash TEXT"
                )
            if "claimed_transaction_id" not in columns:
                connection.execute(
                    "ALTER TABLE accepted_payment_quotes "
                    "ADD COLUMN claimed_transaction_id TEXT"
                )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "accepted_payment_quote_route_claim "
                "ON accepted_payment_quotes (quote_id, claimed_transaction_id)"
            )
            # One transaction settles at most one accepted quote (§15.5). NULL
            # claims stay distinct; existing duplicate claims fail closed here.
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "accepted_payment_quote_transaction_claim "
                "ON accepted_payment_quotes (claimed_transaction_id)"
            )
        except (sqlite3.Error, OSError) as exc:
            if connection is not None:
                connection.close()
            raise PaymentQuoteError(
                "durable payment replay store initialization failed"
            ) from exc
        self._connection = connection
        self._path = path
        self._lock = Lock()

    def _lookup_id(self, quote_id: str) -> tuple[str, str, str] | None:
        row = self._connection.execute(
            "SELECT quote_hash, quote_nonce, acceptance_record_hash "
            "FROM accepted_payment_quotes WHERE quote_id = ?",
            (quote_id,),
        ).fetchone()
        return (row[0], row[1], row[2]) if row is not None else None

    def _lookup_nonce(self, quote_nonce: str) -> tuple[str, str, str] | None:
        row = self._connection.execute(
            "SELECT quote_id, quote_hash, acceptance_record_hash "
            "FROM accepted_payment_quotes WHERE quote_nonce = ?",
            (quote_nonce,),
        ).fetchone()
        return (row[0], row[1], row[2]) if row is not None else None

    def reserve(
        self,
        quote_id: str,
        quote_hash: str,
        quote_nonce: str,
        acceptance_record_hash: str,
    ) -> None:
        with self._lock:
            self._reserve(
                quote_id, quote_hash, quote_nonce, acceptance_record_hash
            )

    def _reserve(
        self,
        quote_id: str,
        quote_hash: str,
        quote_nonce: str,
        acceptance_record_hash: str,
    ) -> None:
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            by_id = self._lookup_id(quote_id)
            by_nonce = self._lookup_nonce(quote_nonce)
            if by_id is not None or by_nonce is not None:
                raise _replay_error(
                    quote_id,
                    quote_hash,
                    quote_nonce,
                    acceptance_record_hash,
                    by_id,
                    by_nonce,
                )
            self._connection.execute(
                "INSERT INTO accepted_payment_quotes "
                "(quote_id, quote_hash, quote_nonce, acceptance_record_hash) "
                "VALUES (?, ?, ?, ?)",
                (quote_id, quote_hash, quote_nonce, acceptance_record_hash),
            )
            self._connection.execute("COMMIT")
        except PaymentQuoteError:
            self._connection.execute("ROLLBACK")
            raise
        except (sqlite3.Error, OSError) as exc:
            try:
                self._connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise PaymentQuoteError("durable payment replay reservation failed") from exc

    def verifier_view(
        self, _issue_view=_issue_acceptance_view
    ) -> AcceptanceEvidenceVerifier:
        try:
            uri = f"{Path(self._path).resolve().as_uri()}?mode=rw"
            connection = sqlite3.connect(
                uri, uri=True, isolation_level=None, check_same_thread=False
            )
        except (sqlite3.Error, OSError, ValueError) as exc:
            raise PaymentQuoteError(
                "limited acceptance authority initialization failed"
            ) from exc
        lock = Lock()

        def verify(
            quote_id: str,
            quote_hash: str,
            quote_nonce: str,
            acceptance_record_hash: str,
        ) -> bool:
            with lock:
                try:
                    by_id = connection.execute(
                        "SELECT quote_hash, quote_nonce, acceptance_record_hash "
                        "FROM accepted_payment_quotes WHERE quote_id = ?",
                        (quote_id,),
                    ).fetchone()
                    by_nonce = connection.execute(
                        "SELECT quote_id, quote_hash, acceptance_record_hash "
                        "FROM accepted_payment_quotes WHERE quote_nonce = ?",
                        (quote_nonce,),
                    ).fetchone()
                    return by_id == (
                        quote_hash,
                        quote_nonce,
                        acceptance_record_hash,
                    ) and by_nonce == (
                        quote_id,
                        quote_hash,
                        acceptance_record_hash,
                    )
                except (sqlite3.Error, OSError) as exc:
                    raise PaymentQuoteError(
                        "acceptance ledger verification failed"
                    ) from exc

        def claim(*args) -> bool:
            quote_id, quote_hash, quote_nonce, record_hash, transaction_id = args
            with lock:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    row = connection.execute(
                        "SELECT quote_hash, quote_nonce, acceptance_record_hash, claimed_transaction_id "
                        "FROM accepted_payment_quotes WHERE quote_id = ?", (quote_id,)
                    ).fetchone()
                    if row is None or row[:3] != (quote_hash, quote_nonce, record_hash):
                        connection.execute("ROLLBACK")
                        return False
                    if row[3] is None:
                        owner = connection.execute(
                            "SELECT quote_id FROM accepted_payment_quotes "
                            "WHERE claimed_transaction_id = ?", (transaction_id,)
                        ).fetchone()
                        if owner is not None:
                            connection.execute("ROLLBACK")
                            raise PaymentQuoteError(
                                "transaction is already claimed by another accepted quote"
                            )
                        connection.execute(
                            "UPDATE accepted_payment_quotes SET claimed_transaction_id = ? "
                            "WHERE quote_id = ? AND claimed_transaction_id IS NULL",
                            (transaction_id, quote_id),
                        )
                    elif row[3] != transaction_id:
                        connection.execute("ROLLBACK")
                        raise PaymentQuoteError("accepted quote already claimed by another transaction")
                    connection.execute("COMMIT")
                    return True
                except PaymentQuoteError:
                    raise
                except sqlite3.Error as exc:
                    try:
                        connection.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise PaymentQuoteError("route claim failed closed") from exc

        def verify_route(*args) -> bool:
            quote_id, quote_hash, quote_nonce, record_hash, transaction_id = args
            with lock:
                row = connection.execute(
                    "SELECT quote_hash, quote_nonce, acceptance_record_hash, claimed_transaction_id "
                    "FROM accepted_payment_quotes WHERE quote_id = ?", (quote_id,)
                ).fetchone()
                return row == (quote_hash, quote_nonce, record_hash, transaction_id)

        return _issue_view(verify, claim, verify_route)
    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "SQLiteReplayStore":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


del _issue_acceptance_view
