#!/usr/bin/env python3
"""W03-0 backend distribution selection: the upstream component set chosen for SEALED_SINGLE_NODE_CONTROL_PLANE_V1.

The selection record (architecture/backend-distribution/selection.json) names one pinned upstream artifact for each
W02g backend component, maps every I06 v2 criterion (SC00-SC15, CL, IC01-IC05, OR01-OR08) to how the selection meets
it, records the excluded candidates with the criteria that exclude them, and carries the re-check of the I05 v3
outcome mapping against the selected Kubernetes commit. It is a design selection: no artifact is installed, no evidence
record exists, and I06 check_evidence still needs a production W02a record (W02a-F2, W02g-F2).

check(read) validates the record through an injected byte reader, so a history-chain layer can pass its reviewed_bytes.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import re

import yaml

try:
    from safe_yaml import SafeLoader
except ImportError:
    from scripts.safe_yaml import SafeLoader

RECORD_PATH = "architecture/backend-distribution/selection.json"
SCHEMA = "planeon.internal.backend-distribution-selection/v1"
PROFILE = "SEALED_SINGLE_NODE_CONTROL_PLANE_V1"
CRITERIA_PATH = "architecture/i06-backend-profile-v2/criteria.json"
MAPPING_PATH = "architecture/i05-gate-channel-v3/outcome-mapping.json"
LICENSE_POLICY_PATH = "legal/third-party-license-policy.yaml"
KUBERNETES = {"version": "v1.37.1", "commit": "f78e722310e50bcaca9276be22276d9e91d91308"}
KUBERNETES_REPOSITORY = "https://github.com/kubernetes/kubernetes"
KUBERNETES_PARTS = {"APISERVER": "kube-apiserver", "CONTROLLER_MANAGER": "kube-controller-manager",
                    "SCHEDULER": "kube-scheduler", "KUBELET": "kubelet", "SERVICE_PROXY": "kube-proxy"}
SOURCE_BUILD_ROLES = ("NETWORK_POLICY_AGENT",)
SANDBOX_REFERENCE = "registry.k8s.io/pause:3.10.2"
REVIEW_CLASSES = ("UNCLASSIFIED_NEEDS_POLICY_AMENDMENT", "OPTIONAL_EXPLICIT_REVIEW")
REQUIRED_ROLES = ("APISERVER", "CONTAINER_RUNTIME", "CONTROLLER_MANAGER", "DATASTORE", "KUBELET", "SCHEDULER")
OPTIONAL_ROLES = ("NETWORK_POLICY_AGENT", "SERVICE_PROXY")
DISPOSITIONS = ("SELECTION", "SEALED_CONFIGURATION", "OBSERVER", "W02A_RECORD", "OPERATIONAL")
ARCHES = ("amd64", "arm64")
KINDS = ("RELEASE_BINARY", "RELEASE_ARCHIVE", "IMAGE_INDEX", "SOURCE_BUILD")
OWNER_QUESTIONS = ("Q4", "Q-L", "Q-E", "Q-N")
MAX_BYTES = 4_194_304
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
OPEN_ID = re.compile(r"D-[A-Z0-9]+(?:-[A-Z0-9]+)*\Z")
SPDX = re.compile(r"[A-Za-z0-9.+-]+\Z")
EXPRESSION = re.compile(r"[A-Za-z0-9.+-]+(?: (?:OR|AND|WITH) [A-Za-z0-9.+-]+)*\Z")


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json(raw: bytes):
    def pairs(items):
        keys = [key for key, _ in items]
        require(len(keys) == len(set(keys)), "duplicate selection key")
        return dict(items)

    def constant(name):
        raise ValueError("nonfinite selection number: " + name)

    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "selection record size")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)


def _closed(value, keys, message):
    require(type(value) is dict and set(value) == set(keys), message)


def _text(value, message):
    require(type(value) is str and value != "" and "\x00" not in value, message)


def _texts(value, message, empty=False):
    require(type(value) is list and (empty or value) and all(type(item) is str and item for item in value)
            and len(set(value)) == len(value), message)


def _pin(value, message):
    _closed(value, ("path", "sha256"), message)
    _text(value["path"], message)
    require(type(value["sha256"]) is str and SHA256.fullmatch(value["sha256"]), message)


def _policy(raw: bytes) -> dict:
    """The license policy's default-allowed, explicit-review and denied expression lists."""
    policy = yaml.load(raw.decode("utf-8"), Loader=SafeLoader)
    lists = {}
    for key in ("defaultAllowedSpdx", "optionalExplicitReview", "deniedForDefaultDistribution"):
        value = policy.get(key) if type(policy) is dict else None
        require(type(value) is list and value and all(type(item) is str and EXPRESSION.fullmatch(item) for item in value),
                "license policy list " + key)
        lists[key] = frozenset(value)
    require(policy.get("evaluation", {}).get("expressionMatching") == "EXACT_SPDX_EXPRESSION"
            and policy.get("deniedRule", {}).get("overrideAllowed") is False, "license policy evaluation rules")
    return lists


def _part(part, role, allowed, review_ids):
    _closed(part, ("name", "upstream", "license", "artifacts", "executables", "excludedMembers"), "closed component part")
    _text(part["name"], "part name")
    upstream = part["upstream"]
    _closed(upstream, ("repository", "tag", "commit"), "part upstream")
    require(type(upstream["repository"]) is str and upstream["repository"].startswith("https://github.com/")
            and type(upstream["tag"]) is str and upstream["tag"].startswith("v")
            and type(upstream["commit"]) is str and COMMIT.fullmatch(upstream["commit"]), "part upstream pin")
    lic = part["license"]
    _closed(lic, ("spdx", "reviewEntries"), "part license")
    require(lic["spdx"] in allowed, "part license outside the default-allowed list: " + part["name"])
    _texts(lic["reviewEntries"], "license review entries", empty=True)
    require(set(lic["reviewEntries"]) <= review_ids, "unknown license review entry")
    artifacts = part["artifacts"]
    require(type(artifacts) is list and artifacts, "part artifacts")
    for artifact in artifacts:
        _closed(artifact, ("arch", "kind", "source", "sha256"), "closed artifact")
        require(artifact["arch"] in ARCHES and artifact["kind"] in KINDS, "artifact arch and kind")
        _text(artifact["source"], "artifact source")
        require(artifact["arch"] in artifact["source"], "artifact source names its architecture")
        if artifact["kind"] == "SOURCE_BUILD":
            require(role in SOURCE_BUILD_ROLES and artifact["sha256"] is None,
                    "only the network-policy agent is source-built, pinned by commit with its digest recorded at build")
        else:
            require(type(artifact["sha256"]) is str and SHA256.fullmatch(artifact["sha256"]), "artifact digest")
    require(sorted(artifact["arch"] for artifact in artifacts) == list(ARCHES), "one artifact per architecture")
    _texts(part["executables"], "part executables")
    _texts(part["excludedMembers"], "excluded archive members", empty=True)
    require(not set(part["executables"]) & set(part["excludedMembers"]), "an executable is not also excluded")


def _component(row, allowed, review_ids):
    _closed(row, ("role", "parts", "notes"), "closed component")
    require(row["role"] in REQUIRED_ROLES + OPTIONAL_ROLES, "component role")
    require(type(row["parts"]) is list and row["parts"], "component parts")
    for part in row["parts"]:
        _part(part, row["role"], allowed, review_ids)
    if row["role"] in KUBERNETES_PARTS:
        require(len(row["parts"]) == 1 and row["parts"][0]["name"] == KUBERNETES_PARTS[row["role"]]
                and row["parts"][0]["executables"] == [KUBERNETES_PARTS[row["role"]]]
                and row["parts"][0]["upstream"] == {"repository": KUBERNETES_REPOSITORY, "tag": KUBERNETES["version"],
                                                     "commit": KUBERNETES["commit"]},
                "a Kubernetes role is its v1.37.1 binary from kubernetes/kubernetes at the baseline commit")
    names = [part["name"] for part in row["parts"]]
    require(len(names) == len(set(names)), "duplicate part")
    _texts(row["notes"], "component notes", empty=True)


def _date(value, message):
    require(type(value) is str and re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}", value), message)
    try:
        datetime.date.fromisoformat(value)
    except ValueError:
        raise ValueError(message) from None


def record(raw: bytes) -> dict:
    """The parsed, closed selection record (structure only; check() binds it to the repository)."""
    value = _json(raw)
    _closed(value, ("schemaVersion", "profile", "kubernetes", "criteriaSource", "ownerDecisions", "components",
                    "sandboxImage", "hostDependencies", "criteria", "excluded", "licenseReviews", "rechecks", "openItems",
                    "notClaimed"), "closed selection record")
    require(value["schemaVersion"] == SCHEMA and value["profile"] == PROFILE, "selection schema and profile")
    require(value["kubernetes"] == KUBERNETES, "Kubernetes v1.37.1 at the I06 baseline commit")
    _pin(value["criteriaSource"], "criteria source pin")
    require(value["criteriaSource"]["path"] == CRITERIA_PATH, "criteria source path")
    decisions = value["ownerDecisions"]
    require(type(decisions) is list and [row.get("id") if type(row) is dict else None for row in decisions]
            == list(OWNER_QUESTIONS), "owner decisions in order: " + ", ".join(OWNER_QUESTIONS))
    for row in decisions:
        _closed(row, ("id", "selected", "summary", "date", "via"), "closed owner decision")
        for key in ("selected", "summary", "via"):
            _text(row[key], "owner decision " + key)
        _date(row["date"], "decision date")
    reviews = value["licenseReviews"]
    require(type(reviews) is list, "license reviews")
    selected = {row["id"]: row["selected"] for row in decisions}
    for row in reviews:
        _closed(row, ("id", "subject", "license", "class", "reason", "decision", "status"), "closed license review")
        require(type(row["id"]) is str and OPEN_ID.fullmatch(row["id"]), "license review id")
        require(type(row["license"]) is str and EXPRESSION.fullmatch(row["license"]), "license review expression")
        require(row["class"] in REVIEW_CLASSES, "license review class")
        _text(row["subject"], "license review subject")
        _text(row["reason"], "license review reason")
        require(row["decision"] == "Q-L" and row["status"] in ("PENDING_OWNER", "OWNER_APPROVED"),
                "a license review is decided by owner question Q-L")
        require((row["status"] == "OWNER_APPROVED") == (selected["Q-L"] != "PENDING"),
                "a review is approved exactly when Q-L is decided")
    review_ids = [row["id"] for row in reviews]
    require(len(review_ids) == len(set(review_ids)), "duplicate license review")
    return value


def check(read) -> dict:
    """Validate the selection record against the I06 v2 criteria, the license policy and the I05 v3 mapping."""
    try:
        return _check(read)
    except (TypeError, KeyError, AttributeError, IndexError) as error:
        raise ValueError("malformed selection record: %s" % error) from None


def _check(read) -> dict:
    value = record(read(RECORD_PATH))
    criteria_raw = read(CRITERIA_PATH)
    require(digest(criteria_raw) == value["criteriaSource"]["sha256"], "the I06 v2 criteria changed")
    criteria = _json(criteria_raw)
    require(criteria.get("kubernetesBaseline") == KUBERNETES["version"], "criteria baseline")
    ids = [row["id"] for row in criteria["criteria"]]
    policy = _policy(read(LICENSE_POLICY_PATH))
    allowed = policy["defaultAllowedSpdx"]
    reviews = value["licenseReviews"]
    review_ids = {row["id"] for row in reviews}
    for row in reviews:
        require(row["license"] not in policy["deniedForDefaultDistribution"], "a denied license cannot be reviewed")
        expected = ("OPTIONAL_EXPLICIT_REVIEW" if row["license"] in policy["optionalExplicitReview"]
                    else "UNCLASSIFIED_NEEDS_POLICY_AMENDMENT")
        require(row["license"] not in allowed and row["class"] == expected, "license review class matches the policy")
    components = value["components"]
    require(type(components) is list and components, "components")
    for row in components:
        _component(row, allowed, review_ids)
    roles = [row["role"] for row in components]
    require(len(roles) == len(set(roles)) and set(REQUIRED_ROLES) <= set(roles) <= set(REQUIRED_ROLES + OPTIONAL_ROLES),
            "one component per role, every required role present")
    parts = [part for row in components for part in row["parts"]]
    executables = [name for part in parts for name in part["executables"]]
    require(len(executables) == len(set(executables)), "an executable belongs to one part")
    digests = [artifact["sha256"] for part in parts for artifact in part["artifacts"] if artifact["sha256"] is not None]
    require(len(digests) == len(set(digests)), "every published artifact digest is distinct")
    sandbox = value["sandboxImage"]
    _closed(sandbox, ("reference", "indexDigest", "license", "usedBy", "reviewEntries"), "closed sandbox image")
    require(sandbox["reference"] == SANDBOX_REFERENCE and type(sandbox["indexDigest"]) is str
            and sandbox["indexDigest"].startswith("sha256:") and SHA256.fullmatch(sandbox["indexDigest"][7:])
            and sandbox["license"] in allowed and sandbox["usedBy"] == "CONTAINER_RUNTIME", "pinned sandbox image")
    _texts(sandbox["reviewEntries"], "sandbox license review entries", empty=True)
    require(set(sandbox["reviewEntries"]) <= review_ids, "unknown sandbox license review")
    hosts = value["hostDependencies"]
    require(type(hosts) is list, "host dependencies")
    for row in hosts:
        _closed(row, ("name", "license", "usedBy", "minimumVersion", "source", "reviewEntries"), "closed host dependency")
        _text(row["name"], "host dependency name")
        require(type(row["license"]) is str and EXPRESSION.fullmatch(row["license"]), "host dependency license")
        require(type(row["usedBy"]) is list and row["usedBy"] and set(row["usedBy"]) <= set(roles), "host dependency roles")
        _text(row["minimumVersion"], "host dependency minimum version")
        _text(row["source"], "host dependency source")
        _texts(row["reviewEntries"], "host dependency license reviews", empty=True)
        require(set(row["reviewEntries"]) <= review_ids, "unknown host dependency license review")
        require(row["license"] in allowed or row["reviewEntries"], "a host dependency outside the allowed list is reviewed")
    reviewed = ({entry for part in parts for entry in part["license"]["reviewEntries"]} | set(sandbox["reviewEntries"])
                | {entry for row in hosts for entry in row["reviewEntries"]})
    require(reviewed == review_ids, "every license review belongs to a part, the sandbox image or a host dependency")
    rows = value["criteria"]
    require(type(rows) is list and [row.get("id") if type(row) is dict else None for row in rows] == ids,
            "every I06 v2 criterion exactly once, in criteria order")
    open_items = value["openItems"]
    require(type(open_items) is list, "open items")
    for row in open_items:
        _closed(row, ("id", "owner", "text"), "closed open item")
        require(type(row["id"]) is str and OPEN_ID.fullmatch(row["id"]), "open item id")
        _text(row["owner"], "open item owner")
        _text(row["text"], "open item text")
    open_ids = [row["id"] for row in open_items]
    require(len(open_ids) == len(set(open_ids)), "duplicate open item")
    used_open = set()
    for row in rows:
        _closed(row, ("id", "dispositions", "how", "roles", "openItems"), "closed criterion row")
        require(type(row["dispositions"]) is list and row["dispositions"]
                and set(row["dispositions"]) <= set(DISPOSITIONS)
                and len(set(row["dispositions"])) == len(row["dispositions"]), "criterion dispositions")
        _text(row["how"], "criterion how")
        require(type(row["roles"]) is list and set(row["roles"]) <= set(roles)
                and len(set(row["roles"])) == len(row["roles"]), "criterion roles")
        require(type(row["openItems"]) is list and set(row["openItems"]) <= set(open_ids)
                and len(set(row["openItems"])) == len(row["openItems"]), "criterion open items")
        used_open |= set(row["openItems"])
    require(used_open == set(open_ids), "every open item is attached to a criterion")
    excluded = value["excluded"]
    require(type(excluded) is list and excluded, "excluded candidates")
    for row in excluded:
        _closed(row, ("candidate", "reason", "criteria"), "closed exclusion")
        _text(row["candidate"], "excluded candidate")
        _text(row["reason"], "exclusion reason")
        require(type(row["criteria"]) is list and row["criteria"]
                and set(row["criteria"]) <= set(ids) | {"OWNER-Q4", "LICENSE", "UPSTREAM-TESTING"}, "exclusion criteria")
    rechecks = value["rechecks"]
    _closed(rechecks, ("i05OutcomeMapping",), "closed rechecks")
    i05 = rechecks["i05OutcomeMapping"]
    _closed(i05, ("path", "sha256", "result", "files"), "closed I05 re-check")
    mapping_raw = read(MAPPING_PATH)
    require(i05["path"] == MAPPING_PATH and digest(mapping_raw) == i05["sha256"], "the I05 v3 mapping changed")
    upstream = _json(mapping_raw)["upstreamSource"]
    require(upstream["commit"] == KUBERNETES["commit"] and upstream["tag"] == KUBERNETES["version"],
            "the I05 mapping was derived from the selected Kubernetes commit")
    require(i05["files"] == upstream["files"] and i05["result"] == "SOURCES_IDENTICAL_AT_SELECTED_COMMIT",
            "the I05 re-check records every mapped source file (the comparison itself is the author's and reviewer's)")
    _texts(value["notClaimed"], "non-claims")
    return value


if __name__ == "__main__":
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    check(lambda path: (root / path).read_bytes())
    print("W03-0 backend distribution selection valid: closed record, every I06 v2 criterion mapped, published "
          "digests recorded (their values are verified by review, not by this check).")
