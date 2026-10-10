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

import hashlib
import json
import re

RECORD_PATH = "architecture/backend-distribution/selection.json"
SCHEMA = "planeon.internal.backend-distribution-selection/v1"
PROFILE = "SEALED_SINGLE_NODE_CONTROL_PLANE_V1"
CRITERIA_PATH = "architecture/i06-backend-profile-v2/criteria.json"
MAPPING_PATH = "architecture/i05-gate-channel-v3/outcome-mapping.json"
LICENSE_POLICY_PATH = "legal/third-party-license-policy.yaml"
KUBERNETES = {"version": "v1.37.1", "commit": "f78e722310e50bcaca9276be22276d9e91d91308"}
REQUIRED_ROLES = ("APISERVER", "CONTAINER_RUNTIME", "CONTROLLER_MANAGER", "DATASTORE", "KUBELET", "SCHEDULER")
OPTIONAL_ROLES = ("NETWORK_POLICY_AGENT", "SERVICE_PROXY")
DISPOSITIONS = ("SELECTION", "SEALED_CONFIGURATION", "OBSERVER", "W02A_RECORD", "OPERATIONAL")
ARCHES = ("amd64", "arm64")
KINDS = ("RELEASE_BINARY", "RELEASE_ARCHIVE", "IMAGE_INDEX", "SOURCE_BUILD")
OWNER_QUESTIONS = ("Q4", "Q-R", "Q-N")
MAX_BYTES = 4_194_304
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
OPEN_ID = re.compile(r"D-[A-Z0-9]+(?:-[A-Z0-9]+)*\Z")
SPDX = re.compile(r"[A-Za-z0-9.+-]+\Z")


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


def _allowed_licenses(policy: bytes) -> frozenset:
    """The defaultAllowedSpdx list of the license policy (a flat YAML list; parsed without a YAML library)."""
    lines = policy.decode("utf-8").splitlines()
    require(lines.count("defaultAllowedSpdx:") == 1, "license policy defaultAllowedSpdx")
    allowed = []
    for line in lines[lines.index("defaultAllowedSpdx:") + 1:]:
        if not line.startswith("  - "):
            break
        allowed.append(line[4:].strip())
    require(allowed and all(SPDX.fullmatch(item) for item in allowed), "license policy allowed list")
    return frozenset(allowed)


def _part(part, allowed, review_ids):
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
        if artifact["kind"] == "SOURCE_BUILD":
            require(artifact["sha256"] is None, "a source build is pinned by its commit; its digest is recorded at build")
        else:
            require(type(artifact["sha256"]) is str and SHA256.fullmatch(artifact["sha256"]), "artifact digest")
    require(sorted(artifact["arch"] for artifact in artifacts) == list(ARCHES), "one artifact per architecture")
    _texts(part["executables"], "part executables")
    _texts(part["excludedMembers"], "excluded archive members", empty=True)


def _component(row, allowed, review_ids):
    _closed(row, ("role", "parts", "notes"), "closed component")
    require(row["role"] in REQUIRED_ROLES + OPTIONAL_ROLES, "component role")
    require(type(row["parts"]) is list and row["parts"], "component parts")
    for part in row["parts"]:
        _part(part, allowed, review_ids)
    names = [part["name"] for part in row["parts"]]
    require(len(names) == len(set(names)), "duplicate part")
    _texts(row["notes"], "component notes", empty=True)


def record(raw: bytes) -> dict:
    """The parsed, closed selection record (structure only; check() binds it to the repository)."""
    value = _json(raw)
    _closed(value, ("schemaVersion", "profile", "kubernetes", "criteriaSource", "ownerDecisions", "components",
                    "sandboxImage", "criteria", "excluded", "licenseReviews", "rechecks", "openItems", "notClaimed"),
            "closed selection record")
    require(value["schemaVersion"] == SCHEMA and value["profile"] == PROFILE, "selection schema and profile")
    require(value["kubernetes"] == KUBERNETES, "Kubernetes v1.37.1 at the I06 baseline commit")
    _pin(value["criteriaSource"], "criteria source pin")
    require(value["criteriaSource"]["path"] == CRITERIA_PATH, "criteria source path")
    decisions = value["ownerDecisions"]
    require(type(decisions) is list and [row.get("id") for row in decisions if type(row) is dict] == list(OWNER_QUESTIONS),
            "owner decisions Q4, Q-R, Q-N in order")
    for row in decisions:
        _closed(row, ("id", "selected", "summary", "date", "via"), "closed owner decision")
        for key in ("selected", "summary", "via"):
            _text(row[key], "owner decision " + key)
        require(type(row["date"]) is str and re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}", row["date"]), "decision date")
    reviews = value["licenseReviews"]
    require(type(reviews) is list, "license reviews")
    for row in reviews:
        _closed(row, ("id", "component", "license", "reason", "decision", "status"), "closed license review")
        require(type(row["id"]) is str and OPEN_ID.fullmatch(row["id"]) and SPDX.fullmatch(row["license"] or "-"),
                "license review id and license")
        _text(row["component"], "license review component")
        _text(row["reason"], "license review reason")
        require(row["decision"] in OWNER_QUESTIONS and row["status"] in ("PENDING_OWNER", "OWNER_APPROVED"),
                "license review decision and status")
    review_ids = {row["id"] for row in reviews}
    require(len(review_ids) == len(reviews), "duplicate license review")
    return value


def check(read) -> dict:
    """Validate the selection record against the I06 v2 criteria, the license policy and the I05 v3 mapping."""
    value = record(read(RECORD_PATH))
    criteria_raw = read(CRITERIA_PATH)
    require(digest(criteria_raw) == value["criteriaSource"]["sha256"], "the I06 v2 criteria changed")
    criteria = _json(criteria_raw)
    require(criteria.get("kubernetesBaseline") == KUBERNETES["version"], "criteria baseline")
    ids = [row["id"] for row in criteria["criteria"]]
    allowed = _allowed_licenses(read(LICENSE_POLICY_PATH))
    review_ids = {row["id"] for row in value["licenseReviews"]}
    components = value["components"]
    require(type(components) is list and components, "components")
    for row in components:
        _component(row, allowed, review_ids)
    roles = [row["role"] for row in components]
    require(len(roles) == len(set(roles)) and set(REQUIRED_ROLES) <= set(roles) <= set(REQUIRED_ROLES + OPTIONAL_ROLES),
            "one component per role, every required role present")
    parts = [part for row in components for part in row["parts"]]
    for part in parts:
        if part["upstream"]["repository"] == "https://github.com/kubernetes/kubernetes":
            require(part["upstream"]["tag"] == KUBERNETES["version"] and part["upstream"]["commit"] == KUBERNETES["commit"],
                    "every Kubernetes component is the baseline release")
    executables = [name for part in parts for name in part["executables"]]
    require(len(executables) == len(set(executables)), "an executable belongs to one part")
    sandbox = value["sandboxImage"]
    _closed(sandbox, ("reference", "indexDigest", "license", "usedBy", "reviewEntries"), "closed sandbox image")
    require(type(sandbox["indexDigest"]) is str and sandbox["indexDigest"].startswith("sha256:")
            and SHA256.fullmatch(sandbox["indexDigest"][7:]) and sandbox["license"] in allowed
            and sandbox["usedBy"] == "CONTAINER_RUNTIME", "pinned sandbox image")
    _text(sandbox["reference"], "sandbox image reference")
    _texts(sandbox["reviewEntries"], "sandbox license review entries", empty=True)
    reviewed = {entry for part in parts for entry in part["license"]["reviewEntries"]} | set(sandbox["reviewEntries"])
    require(reviewed == review_ids, "every license review belongs to a part or the sandbox image")
    rows = value["criteria"]
    require(type(rows) is list and [row.get("id") for row in rows if type(row) is dict] == ids,
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
        require(type(row["openItems"]) is list and set(row["openItems"]) <= set(open_ids), "criterion open items")
        used_open |= set(row["openItems"])
    excluded = value["excluded"]
    require(type(excluded) is list and excluded, "excluded candidates")
    for row in excluded:
        _closed(row, ("candidate", "reason", "criteria"), "closed exclusion")
        _text(row["candidate"], "excluded candidate")
        _text(row["reason"], "exclusion reason")
        require(type(row["criteria"]) is list and row["criteria"]
                and set(row["criteria"]) <= set(ids) | {"OWNER-Q4", "LICENSE"}, "exclusion criteria")
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
            "the I05 re-check covers every mapped source file")
    _texts(value["notClaimed"], "non-claims")
    require(used_open <= set(open_ids), "criterion open items exist")
    return value


if __name__ == "__main__":
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    check(lambda path: (root / path).read_bytes())
    print("W03-0 backend distribution selection valid: every I06 v2 criterion mapped; artifacts pinned.")
