"""Guard against the core verification e2e silently vanishing on CI.

The kit's strongest correctness claims (control-flow/v2 typed PASS, same-session
leak->payload->oracle proof, ASLR runtime behaviour, real-GDB heap ground truth)
live in toolchain-gated e2e classes.  On a runner without gcc/gdb/objdump/nm or
off Linux-x86_64 those classes skip with @unittest.skipUnless, so the whole
suite can report green while none of the core verification ran.

This guard makes that state visible instead of silent:

* When the toolchain IS present, it asserts every required e2e class is actually
  runnable (its skip predicate is satisfiable) -- so a future edit that breaks or
  over-tightens a skip condition, dropping core coverage, fails here loudly.
* When the toolchain is absent, it emits an explicit skip naming the missing
  tools, so a reader of the CI log sees that core verification was NOT exercised
  (a vacuous green), rather than inferring safety from an all-pass run.

It does not re-run the e2e; it checks that the collected e2e would run in this
environment.  It never weakens any gate.
"""
import importlib
import platform
import shutil
import unittest
from unittest import mock


# The core verification e2e classes and the tools each needs to actually run.
# Keep this list in sync with the skipUnless predicates it guards.
REQUIRED_E2E = [
    ("tests.test_proof_session", ("SessionProofE2E",),
     ("gcc", "gdb", "objdump", "nm")),
    ("tests.test_control_flow_transfer_e2e", ("ControlFlowTransferE2E",),
     ("gcc", "gdb", "objdump")),
    ("tests.test_aslr_control_flow_experiment",
     ("ASLRControlFlowExperiment", "ASLRProofGateExperiment"),
     ("gcc", "gdb", "objdump", "nm", "setarch")),
    ("tests.test_proof_observation_producers", ("ProofProducerIntegrationTests",),
     ("gdb", "cc")),
    ("tests.test_gdb_session_v21", ("RealGdbSession",),
     ("gdb", "gcc")),
]

CORE_TOOLS = ("gcc", "cc", "gdb", "objdump", "nm")

# The readiness gate must be the FULL set of tools any required e2e needs, not a
# gcc+gdb subset: otherwise a host that has gcc+gdb but is missing (say) setarch
# enters the "toolchain present" branch and FAILS LOUDLY on that entry, instead
# of the informative skip this guard's docstring promises for an environment
# that cannot exercise the core e2e.  Union CORE_TOOLS with every entry's tools.
REQUIRED_TOOLS = tuple(sorted(set(CORE_TOOLS).union(
    *(tools for _module, _classes, tools in REQUIRED_E2E))))


def _linux_x86_64():
    return platform.system() == "Linux" and platform.machine() in {"x86_64", "amd64"}


def _missing_tools(tools):
    return [t for t in tools if shutil.which(t) is None]


class CoreE2ECoverageGuard(unittest.TestCase):
    def test_required_e2e_modules_import(self):
        # Import failure would make the e2e silently uncollected on every host,
        # which is worse than a skip; catch that regardless of toolchain.
        for module_name, _cls, _tools in REQUIRED_E2E:
            with self.subTest(module=module_name):
                importlib.import_module(module_name)

    def test_core_verification_e2e_runs_when_toolchain_present(self):
        toolchain_ready = _linux_x86_64() and not _missing_tools(REQUIRED_TOOLS)
        if not toolchain_ready:
            missing = _missing_tools(REQUIRED_TOOLS)
            raise unittest.SkipTest(
                "core verification e2e NOT exercised in this environment "
                "(an all-pass run here is vacuous green); "
                "platform=%s/%s missing_tools=%s"
                % (platform.system(), platform.machine(), missing or "none"))
        # Toolchain is present: every required e2e must actually be runnable
        # here.  If a skip predicate is unsatisfiable despite the tools, core
        # coverage has silently dropped -- fail loudly with the offender named.
        for module_name, classes, tools in REQUIRED_E2E:
            with self.subTest(module=module_name):
                missing = _missing_tools(tools)
                self.assertFalse(
                    missing or not _linux_x86_64(),
                    "core e2e %s would skip though the toolchain is present "
                    "(missing=%s, linux_x86_64=%s)"
                    % (module_name, missing, _linux_x86_64()))
                module = importlib.import_module(module_name)
                for class_name in classes:
                    cls = getattr(module, class_name)
                    self.assertFalse(getattr(cls, "__unittest_skip__", False),
                                     "%s.%s is skipped: %s" % (
                                         module_name, class_name,
                                         getattr(cls, "__unittest_skip_why__", "")))
                    methods = unittest.defaultTestLoader.getTestCaseNames(cls)
                    self.assertTrue(methods, "%s.%s has no collected tests" %
                                    (module_name, class_name))
                    for method in methods:
                        self.assertFalse(getattr(getattr(cls, method), "__unittest_skip__", False),
                                         "%s.%s.%s is skipped" % (module_name, class_name, method))

    def test_guard_detects_a_skipped_e2e_class(self):
        from tests.test_proof_session import SessionProofE2E
        # Gate on the SAME predicate the guard uses (REQUIRED_TOOLS, incl. setarch),
        # not the CORE_TOOLS subset: on a host with gcc/gdb but no setarch the guard
        # itself skips, leaving result.failures empty, which would red-build the
        # assertion below on exactly the partial-toolchain host
        # test_partial_toolchain_skips_instead_of_failing is meant to support.
        if not (_linux_x86_64() and not _missing_tools(REQUIRED_TOOLS)):
            self.skipTest("core toolchain unavailable")
        # The guard asserts inside `with self.subTest(...)`, so a failure there is
        # captured by the active subTest outcome collector and recorded on the
        # result rather than propagating as a raised AssertionError.  Catching it
        # with assertRaisesRegex (as an earlier version did) therefore never
        # fired and the self-test passed vacuously.  Run the guard method under
        # its own TestResult while a required e2e class is force-skipped, and
        # assert the skip surfaces as a recorded failure naming the offender.
        probe = CoreE2ECoverageGuard(
            "test_core_verification_e2e_runs_when_toolchain_present")
        with mock.patch.object(SessionProofE2E, "__unittest_skip__", True, create=True):
            result = unittest.TestResult()
            probe.run(result)
        self.assertEqual(result.errors, [], "guard raised instead of failing: %r" % result.errors)
        messages = [message for _case, message in result.failures]
        self.assertTrue(
            any("SessionProofE2E is skipped" in message for message in messages),
            "guard did not flag the force-skipped e2e; failures=%r" % messages)

    def test_partial_toolchain_skips_instead_of_failing(self):
        # Regression: a host with gcc+gdb but missing a tool only some required
        # e2e need (e.g. setarch for the ASLR experiment) must SKIP with the
        # missing tool named, not red-build.  The old readiness gate checked only
        # gcc+gdb, entered the "toolchain present" branch, and then failed loudly
        # on the setarch-dependent entry.  Simulate exactly that host and assert
        # the guard records a skip and neither a failure nor an error.
        self.assertIn("setarch", REQUIRED_TOOLS,
                      "guard must require the union of e2e tools, incl. setarch")
        real_which = shutil.which

        def fake_which(tool, *args, **kwargs):
            return None if tool == "setarch" else real_which(tool, *args, **kwargs)

        probe = CoreE2ECoverageGuard(
            "test_core_verification_e2e_runs_when_toolchain_present")
        with mock.patch.object(shutil, "which", side_effect=fake_which), \
                mock.patch.object(platform, "system", return_value="Linux"), \
                mock.patch.object(platform, "machine", return_value="x86_64"):
            result = unittest.TestResult()
            probe.run(result)
        self.assertEqual(result.failures, [],
                         "partial toolchain red-built instead of skipping: %r" % result.failures)
        self.assertEqual(result.errors, [],
                         "partial toolchain raised instead of skipping: %r" % result.errors)
        self.assertEqual(len(result.skipped), 1,
                         "guard did not skip on a partial toolchain: %r" % (result.skipped,))
        self.assertIn("setarch", result.skipped[0][1],
                      "skip reason must name the missing tool; got %r" % (result.skipped[0][1],))


if __name__ == "__main__":
    unittest.main()
