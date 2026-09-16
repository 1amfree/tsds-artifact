#!/usr/bin/env python3

from __future__ import annotations

import unittest

from tsds.sink_semantics import DEFAULT_SINK_REGISTRY, normalize_sink_name


class SinkSemanticsTest(unittest.TestCase):
    def test_shell_format_direct_and_unknown_contracts(self) -> None:
        self.assertEqual("system", normalize_sink_name(" system@plt "))
        shell = DEFAULT_SINK_REGISTRY.resolve("system")
        self.assertTrue(shell.admissible_shell_claim)
        self.assertEqual("shell_command", shell.semantic_class)
        wrapper = DEFAULT_SINK_REGISTRY.resolve("doSystemCmd")
        self.assertEqual("rendered_format_wrapper", wrapper.required_binding_trust)
        direct = DEFAULT_SINK_REGISTRY.resolve("execve")
        self.assertFalse(direct.admissible_shell_claim)
        self.assertEqual("argv_vector", direct.argument_mode)
        unknown = DEFAULT_SINK_REGISTRY.resolve("sub_401000")
        self.assertEqual("unknown_wrapper", unknown.semantic_class)


if __name__ == "__main__":
    unittest.main()

