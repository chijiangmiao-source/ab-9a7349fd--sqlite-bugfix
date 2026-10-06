"""后继凭证保护信封的单元测试（标准库 unittest）。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protection import (  # noqa: E402
    CredentialProtector,
    InvalidToken,
    rotation_associated_data,
)


class CredentialProtectorTestCase(unittest.TestCase):
    def setUp(self):
        self.aad = rotation_associated_data("fam_x", "rot-1", 2, "h" * 64)
        self.secret = "rft_" + "a" * 48

    def test_roundtrip_recovers_identical_secret(self):
        p = CredentialProtector(b"k" * 32)
        envelope = p.protect(self.secret, self.aad)
        self.assertEqual(p.reveal(envelope, self.aad), self.secret)

    def test_envelope_is_not_plaintext_and_has_versioned_shape(self):
        p = CredentialProtector(b"k" * 32)
        envelope = p.protect(self.secret, self.aad)
        self.assertTrue(envelope.startswith("pae1."))
        self.assertEqual(len(envelope.split(".")), 5)
        self.assertNotIn(self.secret, envelope)
        self.assertNotIn(self.secret[4:], envelope)

    def test_random_nonce_makes_envelopes_unique(self):
        p = CredentialProtector(b"k" * 32)
        envelopes = {p.protect(self.secret, self.aad) for _ in range(8)}
        self.assertEqual(len(envelopes), 8)
        for envelope in envelopes:
            self.assertEqual(p.reveal(envelope, self.aad), self.secret)

    def test_wrong_key_cannot_open_envelope(self):
        e1 = CredentialProtector(b"1" * 32).protect(self.secret, self.aad)
        with self.assertRaises(InvalidToken):
            CredentialProtector(b"2" * 32).reveal(e1, self.aad)

    def test_envelope_bound_to_associated_data(self):
        p = CredentialProtector(b"k" * 32)
        envelope = p.protect(self.secret, self.aad)
        other_aads = [
            rotation_associated_data("fam_OTHER", "rot-1", 2, "h" * 64),
            rotation_associated_data("fam_x", "rot-OTHER", 2, "h" * 64),
            rotation_associated_data("fam_x", "rot-1", 3, "h" * 64),
            rotation_associated_data("fam_x", "rot-1", 2, "z" * 64),
        ]
        for aad in other_aads:
            with self.assertRaises(InvalidToken):
                p.reveal(envelope, aad)

    def test_tampering_is_rejected(self):
        p = CredentialProtector(b"k" * 32)
        version, key_id, nonce, tag, ciphertext = p.protect(
            self.secret, self.aad
        ).split(".")

        # 翻转 nonce / tag / ciphertext 段首字符。
        def flip(segment, index):
            parts = [version, key_id, nonce, tag, ciphertext]
            chars = list(parts[segment])
            chars[index] = "A" if chars[index] != "A" else "B"
            parts[segment] = "".join(chars)
            return ".".join(parts)

        for segment in (2, 3, 4):
            with self.assertRaises(InvalidToken):
                p.reveal(flip(segment, 0), self.aad)

    def test_malformed_envelopes_rejected(self):
        p = CredentialProtector(b"k" * 32)
        for bad in ("", "xxx", "pae0.a.b.c.d", "pae1.a.b", "pae1.a.b.c.d.e", 12345):
            with self.assertRaises(InvalidToken):
                p.reveal(bad, self.aad)

    def test_key_must_be_32_bytes(self):
        with self.assertRaises(ValueError):
            CredentialProtector(b"too-short")


if __name__ == "__main__":
    unittest.main()
