"""Sphinx packet-format tests — the §8.4 packet layer.

Covers layered encryption + roundtrip, per-hop unlinkability (blinding), the
fixed-size invariant, per-hop integrity MAC, and replay-tag rejection. These are
the §8.2 properties 1/2 at the packet layer, proven with real crypto.
"""

import _path  # noqa: F401

import unittest

from afp_mixnet import crypto, sphinx

pytestmark = None


class CryptoPrimitiveTest(unittest.TestCase):
    def test_x25519_dh_agreement(self):
        a_priv, a_pub = crypto.x25519_keypair()
        b_priv, b_pub = crypto.x25519_keypair()
        self.assertEqual(crypto.x25519(a_priv, b_pub), crypto.x25519(b_priv, a_pub))

    def test_x25519_rfc7748_vector(self):
        # RFC 7748 §5.2 test vector 1 — proves the scalar mult is real X25519.
        scalar = bytes.fromhex(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
        )
        u = bytes.fromhex(
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
        )
        self.assertEqual(
            crypto.x25519(scalar, u).hex(),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        )

    def test_hkdf_is_deterministic_and_length_correct(self):
        out1 = crypto.hkdf(b"ikm", info=b"label", length=48)
        out2 = crypto.hkdf(b"ikm", info=b"label", length=48)
        self.assertEqual(out1, out2)
        self.assertEqual(len(out1), 48)
        self.assertNotEqual(out1, crypto.hkdf(b"ikm", info=b"other", length=48))

    def test_stream_xor_roundtrips(self):
        key = b"k" * 32
        data = b"the quick brown fox" * 7
        ct = crypto.stream_xor(key, data)
        self.assertNotEqual(ct, data)
        self.assertEqual(crypto.stream_xor(key, ct), data)

    def test_mac_is_keyed_and_truncated(self):
        m = crypto.mac(b"key", b"data")
        self.assertEqual(len(m), crypto.MAC_SIZE)
        self.assertNotEqual(m, crypto.mac(b"other", b"data"))


class SphinxRoundtripTest(unittest.TestCase):
    def _route(self, n):
        nodes = [sphinx.MixNodeKeypair.generate() for _ in range(n)]
        pubs = [nd.public_point for nd in nodes]
        addrs = [f"node-{i}".encode() for i in range(n)]
        return nodes, pubs, addrs

    def test_three_hop_roundtrip_delivers_payload(self):
        nodes, pubs, addrs = self._route(3)
        msg = b"AFP coordination payload over the mixnet"
        pkt = sphinx.create_packet(
            session_scalar=crypto.random_scalar(),
            hop_public_keys=pubs,
            hop_addresses=addrs,
            destination=b"rendezvous",
            payload=msg,
        )
        cur = pkt
        delivered = None
        for i in range(3):
            res = sphinx.process_packet(cur, nodes[i])
            if res.is_final:
                delivered = res.delivered_payload
                break
            cur = res.next_packet
        self.assertEqual(delivered, msg)

    def test_one_and_two_hop_roundtrips(self):
        for n in (1, 2):
            nodes, pubs, addrs = self._route(n)
            msg = b"x" * 200
            pkt = sphinx.create_packet(
                session_scalar=crypto.random_scalar(),
                hop_public_keys=pubs,
                hop_addresses=addrs,
                destination=b"d",
                payload=msg,
            )
            cur, delivered = pkt, None
            for i in range(n):
                res = sphinx.process_packet(cur, nodes[i])
                if res.is_final:
                    delivered = res.delivered_payload
                    break
                cur = res.next_packet
            self.assertEqual(delivered, msg, f"{n}-hop roundtrip failed")

    def test_packets_are_fixed_size_regardless_of_message(self):
        # §8.4: every packet identical in size and form.
        nodes, pubs, addrs = self._route(3)
        sizes = set()
        for length in (1, 100, sphinx.DEFAULT_PARAMS.usable_payload_size):
            pkt = sphinx.create_packet(
                session_scalar=crypto.random_scalar(),
                hop_public_keys=pubs,
                hop_addresses=addrs,
                destination=b"d",
                payload=b"m" * length,
            )
            sizes.add((len(pkt.alpha), len(pkt.header), len(pkt.payload)))
        self.assertEqual(len(sizes), 1, "packet size varied with message length")

    def test_payload_length_prefix_preserves_trailing_zero(self):
        nodes, pubs, addrs = self._route(3)
        msg = b"payload\x00\x00"
        pkt = sphinx.create_packet(
            session_scalar=crypto.random_scalar(),
            hop_public_keys=pubs,
            hop_addresses=addrs,
            destination=b"d",
            payload=msg,
        )
        cur = pkt
        for i in range(3):
            res = sphinx.process_packet(cur, nodes[i])
            if res.is_final:
                self.assertEqual(res.delivered_payload, msg)
                return
            cur = res.next_packet
        self.fail("three-hop packet did not reach its destination")

    def test_routing_addresses_are_fixed_width_and_preserve_trailing_zero(self):
        nodes, pubs, _ = self._route(3)
        forwarding_addresses = [
            b"a" * 31 + b"\x00",
            b"b" * 31 + b"\x00",
            b"\x00" * 32,  # unused placeholder for the final hop
        ]
        destination = b"d" * 31 + b"\x00"
        pkt = sphinx.create_packet(
            session_scalar=crypto.random_scalar(),
            hop_public_keys=pubs,
            hop_addresses=forwarding_addresses,
            destination=destination,
            payload=b"fixed-width routing",
        )

        first = sphinx.process_packet(pkt, nodes[0])
        self.assertFalse(first.is_final)
        self.assertEqual(first.next_address, forwarding_addresses[0])
        self.assertEqual(len(first.next_address), 32)

        second = sphinx.process_packet(first.next_packet, nodes[1])
        self.assertFalse(second.is_final)
        self.assertEqual(second.next_address, forwarding_addresses[1])
        self.assertEqual(len(second.next_address), 32)

        final = sphinx.process_packet(second.next_packet, nodes[2])
        self.assertTrue(final.is_final)
        self.assertEqual(final.destination_address, destination)
        self.assertEqual(len(final.destination_address), 32)
        self.assertEqual(final.delivered_payload, b"fixed-width routing")

    def test_payload_usable_budget_is_explicit_and_enforced(self):
        self.assertEqual(sphinx.DEFAULT_PARAMS.usable_payload_size, 4092)
        nodes, pubs, addrs = self._route(3)
        with self.assertRaises(sphinx.SphinxError):
            sphinx.create_packet(
                session_scalar=crypto.random_scalar(),
                hop_public_keys=pubs,
                hop_addresses=addrs,
                destination=b"d",
                payload=b"m" * (sphinx.DEFAULT_PARAMS.usable_payload_size + 1),
            )

    def test_maximum_usable_payload_roundtrips_byte_identically(self):
        nodes, pubs, addrs = self._route(3)
        msg = bytes(range(256)) * (sphinx.DEFAULT_PARAMS.usable_payload_size // 256)
        msg += bytes(range(sphinx.DEFAULT_PARAMS.usable_payload_size % 256))
        self.assertEqual(len(msg), sphinx.DEFAULT_PARAMS.usable_payload_size)
        pkt = sphinx.create_packet(
            session_scalar=crypto.random_scalar(),
            hop_public_keys=pubs,
            hop_addresses=addrs,
            destination=b"d",
            payload=msg,
        )
        cur = pkt
        for i in range(3):
            res = sphinx.process_packet(cur, nodes[i])
            if res.is_final:
                self.assertEqual(res.delivered_payload, msg)
                return
            cur = res.next_packet
        self.fail("three-hop packet did not reach its destination")

    def test_one_byte_payload_roundtrips(self):
        nodes, pubs, addrs = self._route(3)
        pkt = sphinx.create_packet(
            session_scalar=crypto.random_scalar(),
            hop_public_keys=pubs,
            hop_addresses=addrs,
            destination=b"d",
            payload=b"x",
        )
        cur = pkt
        for i in range(3):
            res = sphinx.process_packet(cur, nodes[i])
            if res.is_final:
                self.assertEqual(res.delivered_payload, b"x")
                return
            cur = res.next_packet
        self.fail("three-hop packet did not reach its destination")

    def test_per_hop_elements_are_unlinkable(self):
        # §8.2 #1/#2 at the packet layer: the element a relay forwards differs from
        # what it received (blinding) and every hop's element is distinct.
        nodes, pubs, addrs = self._route(3)
        pkt = sphinx.create_packet(
            session_scalar=crypto.random_scalar(),
            hop_public_keys=pubs,
            hop_addresses=addrs,
            destination=b"d",
            payload=b"m",
        )
        cur = pkt
        alphas = [cur.alpha]
        headers = [cur.header]
        for i in range(3):
            res = sphinx.process_packet(cur, nodes[i])
            if res.is_final:
                break
            cur = res.next_packet
            alphas.append(cur.alpha)
            headers.append(cur.header)
        self.assertEqual(len(set(alphas)), len(alphas), "alpha repeated across hops")
        self.assertEqual(len(set(headers)), len(headers), "header repeated across hops")


class SphinxSecurityTest(unittest.TestCase):
    def _pkt_and_nodes(self):
        nodes = [sphinx.MixNodeKeypair.generate() for _ in range(3)]
        pubs = [n.public_point for n in nodes]
        pkt = sphinx.create_packet(
            session_scalar=crypto.random_scalar(),
            hop_public_keys=pubs,
            hop_addresses=[b"a", b"b", b"c"],
            destination=b"d",
            payload=b"secret",
        )
        return pkt, nodes

    def test_replay_is_rejected_within_epoch(self):
        pkt, nodes = self._pkt_and_nodes()
        seen = set()
        sphinx.process_packet(pkt, nodes[0], seen_tags=seen)
        with self.assertRaises(sphinx.ReplayError):
            sphinx.process_packet(pkt, nodes[0], seen_tags=seen)

    def test_tampered_header_fails_integrity(self):
        pkt, nodes = self._pkt_and_nodes()
        bad = bytearray(pkt.header)
        bad[20] ^= 0x01
        pkt.header = bytes(bad)
        with self.assertRaises(sphinx.IntegrityError):
            sphinx.process_packet(pkt, nodes[0])

    def test_truncated_payload_fails_integrity(self):
        pkt, nodes = self._pkt_and_nodes()
        pkt.payload = pkt.payload[:-1]
        with self.assertRaises(sphinx.IntegrityError):
            sphinx.process_packet(pkt, nodes[0])

    def test_wrong_node_key_fails(self):
        pkt, nodes = self._pkt_and_nodes()
        wrong = sphinx.MixNodeKeypair.generate()
        with self.assertRaises(sphinx.SphinxError):
            sphinx.process_packet(pkt, wrong)

    def test_route_exceeding_max_hops_is_rejected(self):
        nodes = [sphinx.MixNodeKeypair.generate() for _ in range(4)]
        pubs = [n.public_point for n in nodes]
        with self.assertRaises(sphinx.SphinxError):
            sphinx.create_packet(
                session_scalar=crypto.random_scalar(),
                hop_public_keys=pubs,
                hop_addresses=[b"a", b"b", b"c", b"e"],
                destination=b"d",
                payload=b"m",
            )

    def test_replay_tag_is_hop_specific(self):
        # The replay tag at hop 0 and hop 1 differ (blinded element -> different MAC).
        pkt, nodes = self._pkt_and_nodes()
        tag0 = pkt.replay_tag
        res = sphinx.process_packet(pkt, nodes[0])
        tag1 = res.next_packet.replay_tag
        self.assertNotEqual(tag0, tag1)


if __name__ == "__main__":
    unittest.main()
