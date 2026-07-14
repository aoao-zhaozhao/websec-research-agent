from __future__ import annotations

import unittest

from benchmarks.jwt_weak_hmac_lab import make_token, read_token


class JwtWeakHmacLabTests(unittest.TestCase):
    def test_lab_issues_a_non_admin_token_and_rejects_tampering(self):
        token = make_token(False)
        self.assertFalse(read_token(token)["sub"]["admin"])

        header, payload, signature = token.split(".")
        self.assertIsNone(read_token(f"{header}.{payload}.invalid{signature}"))


if __name__ == "__main__":
    unittest.main()
