"""X-Forwarded-For is a weapon unless the proxy is pinned."""
from __future__ import annotations

import unittest

from tripwire import logread


def row(peer="10.0.0.5", xff=""):
    return {"ip": peer, "xff": xff, "ua": "curl/8.7.1", "path": "/x", "ts": 1.0,
            "status": 200}


class TrustedProxy(unittest.TestCase):
    def test_a_trusted_proxy_passes_the_client_address(self) -> None:
        out = logread.resolve_client(row(xff="8.8.4.4"), ["10.0.0.0/8"])
        self.assertEqual(out["ip"], "8.8.4.4")
        self.assertEqual(out["peer"], "10.0.0.5")

    def test_the_rightmost_untrusted_hop_wins(self) -> None:
        out = logread.resolve_client(row(xff="1.2.3.4, 8.8.4.4, 10.0.0.9"),
                                     ["10.0.0.0/8"])
        self.assertEqual(out["ip"], "8.8.4.4")

    def test_an_untrusted_peer_cannot_spoof(self) -> None:
        out = logread.resolve_client(row(peer="198.51.100.7", xff="8.8.4.4"), ["10.0.0.0/8"])
        self.assertEqual(out["ip"], "198.51.100.7")
        self.assertEqual(out["xff_ignored"], "8.8.4.4")

    def test_without_a_trusted_list_nothing_is_trusted(self) -> None:
        self.assertEqual(logread.resolve_client(row(xff="8.8.4.4"))["ip"], "10.0.0.5")

    def test_a_garbage_hop_is_skipped(self) -> None:
        out = logread.resolve_client(row(xff="unknown, 8.8.4.4"), ["10.0.0.0/8"])
        self.assertEqual(out["ip"], "8.8.4.4")

    def test_an_all_trusted_chain_keeps_the_peer(self) -> None:
        out = logread.resolve_client(row(xff="10.0.0.9"), ["10.0.0.0/8"])
        self.assertEqual(out["ip"], "10.0.0.5")


if __name__ == "__main__":
    unittest.main()
