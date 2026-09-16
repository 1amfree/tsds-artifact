#!/usr/bin/env python3

from __future__ import annotations

import shutil
import unittest

from experiments.audit_shell_witness_syntax import (
    decode_rendered_command,
    parse_command,
    verify_parser_noexec,
)


class ShellWitnessSyntaxAuditTest(unittest.TestCase):
    def test_decodes_tsds_byte_escapes_and_c_string_boundary(self) -> None:
        self.assertEqual(
            decode_rendered_command(r"printf A\x09B\x0aC\x00ignored"),
            "printf A\tB\nC",
        )

    @unittest.skipUnless(shutil.which("bash"), "bash is not available")
    def test_bash_parser_is_noexec_and_rejects_unclosed_substitution(self) -> None:
        preflight = verify_parser_noexec(shutil.which("bash") or "bash")
        self.assertTrue(preflight["noexec_verified"])
        result = parse_command(shutil.which("bash") or "bash", "printf $(AAAA")
        self.assertFalse(result["valid"])


if __name__ == "__main__":
    unittest.main()
