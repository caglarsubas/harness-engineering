"""Synthetic source-test inputs only; no operational key, host or PASS fixture."""
from pathlib import Path
import sys

import pytest

KIT = Path(__file__).resolve().parents[2] / "ci/linux-runner"
sys.path.insert(0, str(KIT))

from common import (FIREJAIL, ISOLATION, LAUNCHER, MANIFEST, PROOFS, PUBLIC, PYTHON,
                    RUNNER, VERSION)


@pytest.fixture
def inputs():
    tools = {
        "python": {"path": PYTHON, "version": "3.12.14", "root": "/opt/planeon/python/3.12.14", "inventorySha256": "1" * 64},
        "firejail": {"path": FIREJAIL, "version": "0.9.76", "root": "/usr/bin", "inventorySha256": "2" * 64},
        "git": {"path": "/usr/bin/git", "version": "2.50.1", "root": "/usr/bin", "inventorySha256": "2" * 64},
    }
    return {"schemaVersion": "planeon.linux-build-inputs/v3",
            "target": {"os": "linux", "architecture": "amd64", "libc": "glibc", "libcVersion": "2.39",
                       "execution": "NATIVE", "imageDigest": "sha256:" + "3" * 64},
            "tools": tools, "caches": [{"root": "/opt/planeon/cache/python", "inventorySha256": "4" * 64,
                                       "os": "linux", "architecture": "amd64", "libc": "glibc", "tool": "python"}],
            "systemTrees": [{"root": root, "inventorySha256": "2" * 64 if root == "/usr/bin" else "a" * 64}
                            for root in ("/usr/bin", "/usr/lib", "/etc/firejail")],
            "systemFiles": {"/etc/ld.so.cache": "b" * 64},
            "source": {"repository": "caglarsubas/harness-onion", "commit": "5" * 40, "treeSha256": "6" * 64},
            "recipes": {"packet": "SIGNED_PACKET_WRAPPER", "nextStandalone": "LINUX_TARGET_BUILD_ONLY",
                        "downloads": "DENIED", "hostOutputReuse": "DENIED"}}


@pytest.fixture
def policy(inputs):
    from launcher import profile_bytes
    from common import digest
    value = {"schemaVersion": "planeon.linux-runner-policy/v3", "issuedAt": 100, "expiresAt": 200,
             "operatorUid": 1001, "operatorName": "runner", "workspace": "/opt/planeon/work/harness-onion/harness-onion",
             "runnerHome": "/srv/planeon/runner-agent", "packetSha256": "7" * 64,
             "warmContainer": "/srv/planeon/warm-snapshots", "warmRoots": ["/srv/planeon/warm-snapshots/reference"],
             "inputs": inputs, "profileSha256": "8" * 64,
             "transportPins": {path: "9" * 64 for path in ("ci/verify-offline.sh", "ci/run_packet_argv.py", "ci/network_canary.py")},
             "environment": {"UV_CACHE_DIR": "/opt/planeon/cache/python"}}
    value["profileSha256"] = digest(profile_bytes(value))
    return value


@pytest.fixture
def manifest():
    return {"schemaVersion": "harness.planeon.ai/trusted-runner-manifest/v1alpha1",
            "launcher": {"path": LAUNCHER, "version": VERSION, "sha256": "1" * 64, "ownerUid": 0, "ownerGid": 0, "mode": "0555"},
            "runner": dict(RUNNER), "isolation": {**ISOLATION, "warmSourceRoots": ["/srv/planeon/warm-snapshots/reference"]},
            "preflight": {"suiteVersion": VERSION, "status": "PASS", "evidenceSha256": "2" * 64, **{name: True for name in PROOFS}},
            "signature": {"algorithm": "ED25519", "signaturePath": MANIFEST + ".sig", "publicKeyPath": PUBLIC, "publicKeySha256": "3" * 64}}


# MET-PERF-030: the outer packet session already runs the complete predecessor
# suite, so its proof test reads this session's own results instead of running
# every predecessor test a second time. The recorder only observes reports.
PREDECESSOR_PROOF_NODE = ("tests/linux_runner/test_build_and_predecessors.py"
                          "::test_full_predecessor_suites_and_validators_remain_green")


class PredecessorOutcomes:
    """Session-wide (when, outcome) record per node; never alters a report."""

    def __init__(self):
        self.reports = {}

    @pytest.hookimpl(trylast=True)
    def pytest_runtest_logreport(self, report):
        self.reports.setdefault(report.nodeid, []).append((report.when, report.outcome))


def pytest_configure(config):
    if not hasattr(config, "_planeon_predecessor_outcomes"):
        config._planeon_predecessor_outcomes = PredecessorOutcomes()
        config.pluginmanager.register(config._planeon_predecessor_outcomes, "planeon-predecessor-outcomes")


def pytest_collection_modifyitems(session, config, items):
    # Run the proof last so every predecessor test in this session has reported.
    proof = [item for item in items if item.nodeid == PREDECESSOR_PROOF_NODE]
    if proof:
        items[:] = [item for item in items if item.nodeid != PREDECESSOR_PROOF_NODE] + proof
