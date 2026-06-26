"""Robustness tests for the orchestrator's command runner.

These pin the fix for the live-demo 500: a slow or missing command (e.g. a ping
that never gets a reply on a down tunnel) must degrade gracefully, never raise.
Run without sudo or any real interface.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Settings  # noqa: E402
from orchestrator import Orchestrator  # noqa: E402


class TestRunRobustness(unittest.TestCase):
    def setUp(self):
        # local mode, and _run only adds sudo when called with sudo=True, so
        # these invocations run as the normal user.
        self.o = Orchestrator(Settings(local=True))

    def test_timeout_does_not_raise(self):
        r = self.o._run(["sleep", "5"], timeout=0.2)
        self.assertEqual(r.returncode, 124)  # our timeout sentinel

    def test_missing_command_does_not_raise(self):
        r = self.o._run(["definitely-not-a-real-command-xyz"])
        self.assertNotEqual(r.returncode, 0)

    def test_normal_command_still_works(self):
        r = self.o._run(["true"])
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
