#!/usr/bin/env python3
"""LIC-HOST license-policy amendment A1: host-OS class, OR-choice and AND-term rules, legacy crate normalisation.

The base policy (legal/third-party-license-policy.yaml) stays byte-identical, because many records pin it. The reviewed
amendment record (legal/license-policy-amendment/amendment.json) carries the owner's decisions Q-L, Q-L2 and Q-L3:
- a HOST_OS_SYSTEM_LIBRARY class of exact license terms, scoped by component kind and custody;
- explicit-review decision records scoped to named subjects;
- owner-named elections;
- the OR-choice, AND-term and legacy-slash rules, under the base evaluation precedence.

classify(policy, expression, component) gives the effective outcome of one SPDX expression for one component. That
outcome includes every leaf's category and its elections, and it never weakens a base outcome. check(read) validates the
record and its vectors through an injected byte reader.
"""
from __future__ import annotations

import hashlib
import json
import re

import yaml

try:
    from safe_yaml import SafeLoader
except ImportError:
    from scripts.safe_yaml import SafeLoader

RECORD_PATH = "legal/license-policy-amendment/amendment.json"
VECTORS_PATH = "legal/license-policy-amendment/vectors.json"
BASE_PATH = "legal/third-party-license-policy.yaml"
BASE_SHA256 = "fa3a4398acafc3960eaaae9f5396d4e96d91e6ff252b83f6c53e1f5f0d8a40d0"
SCHEMA = "planeon.internal.license-policy-amendment/v1"
AMENDMENT_ID = "LIC-HOST-A1"
OWNER_QUESTIONS = (("Q-L", "L-a"), ("Q-L2", "L2-a"), ("Q-L3", "L3-a"))
DECISION_FIELDS = ("expression", "approvedUseAndDistributionMode", "sourceOfferOrCorrespondingSourceDisposition",
                   "networkCopyleftDisposition", "noticeAndAttributionDisposition", "approvingAuthority", "decisionDigest")
CORE_LICENSE = "Apache-2.0"
CLASS = "HOST_OS_SYSTEM_LIBRARY"
APPROVED = "OPTIONAL_EXPLICIT_REVIEW_APPROVED"
# The decided content, pinned (owner decisions Q-L and Q-L2).
CLASS_EXPRESSIONS = ("GPL-2.0-or-later", "GPL-3.0-or-later WITH GCC-exception-3.1", "LGPL-2.1-only", "LGPL-2.1-or-later")
CLASS_KINDS = ("HOST_OS_PROGRAM", "HOST_OS_LIBRARY", "STATIC_SYSTEM_LIBRARY")
CLASS_CUSTODY = ("UPSTREAM_PINNED",)
DECISIONS = {"GPL-2.0-only": (("libnftables", "nft"), "Q-L"), "LGPL-3.0-or-later": (("gmp",), "Q-L2")}
OWNER_ELECTIONS = {"LGPL-3.0-or-later OR MPL-2.0": ("MPL-2.0", "Q-L", "libpathrs"),
                   "GPL-2.0-or-later OR LGPL-3.0-or-later": ("LGPL-3.0-or-later", "Q-L2", "gmp")}
KINDS = ("CRATE", "GO_MODULE", "UPSTREAM_BINARY", "STATIC_SYSTEM_LIBRARY", "HOST_OS_PROGRAM", "HOST_OS_LIBRARY",
         "PLANEON_SOURCE", "ARTIFACT")
OPEN_CONTENT_KINDS = ("ARTIFACT",)
# Base evaluation.precedence, most restrictive first; OUT_OF_SCOPE (a scoped term used elsewhere) ranks with UNKNOWN.
BLOCKING_RANK = {"DENIED": 0, "UNKNOWN": 1, "OUT_OF_SCOPE": 1, "PLANNED_UNRESOLVED": 2, "OPTIONAL_EXPLICIT_REVIEW": 3}
ACCEPTED_RANK = {"DEFAULT_ALLOWED": 1, "ALLOWED_EXCEPTION_EXPRESSION": 2, "OPEN_CONTENT": 3, CLASS: 4, APPROVED: 5}
OUTCOMES = tuple(BLOCKING_RANK) + tuple(ACCEPTED_RANK) + ("ACCEPTED_AND", "ACCEPTED_OR", "REFUSED")
OPERATORS = ("AND", "OR", "WITH")
IDSTRING = re.compile(r"(?:LicenseRef-)?[A-Za-z0-9.-]*[A-Za-z0-9]\+?\Z")
MAX_EXPRESSION = 512
MAX_DEPTH = 16
MAX_BYTES = 4_194_304


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _json(raw: bytes):
    def pairs(items):
        keys = [key for key, _ in items]
        require(len(keys) == len(set(keys)), "duplicate amendment key")
        return dict(items)

    def constant(name):
        raise ValueError("nonfinite amendment number: " + name)

    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "amendment record size")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)


class _UniqueKeyLoader(SafeLoader):
    pass


def _unique_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        require(key not in result, "duplicate YAML key %r" % (key,))
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


# --- SPDX 2.3 Annex D expressions -----------------------------------------------------------------------------------

def _tokens(expression: str) -> list:
    require(type(expression) is str and 0 < len(expression) <= MAX_EXPRESSION, "SPDX expression length")
    require(all(c == " " or ("!" <= c <= "~") for c in expression), "an SPDX expression uses printable ASCII and spaces only")
    spaced = expression.replace("(", " ( ").replace(")", " ) ")
    tokens = [token for token in spaced.split(" ") if token]
    require(tokens, "empty SPDX expression")
    return tokens


def _license_id(token: str) -> str:
    require(token.upper() not in OPERATORS and IDSTRING.fullmatch(token) is not None and not token.startswith("DocumentRef-"),
            "not an SPDX license id: %r" % token)
    return token


def parse(expression: str):
    """("OR", [..]), ("AND", [..]) or a leaf string ("X" or "X WITH E"); WITH binds tightest, then AND, then OR."""
    tokens = _tokens(expression)
    position = 0

    def peek():
        return tokens[position] if position < len(tokens) else None

    def take():
        nonlocal position
        token = peek()
        require(token is not None, "truncated SPDX expression: %r" % expression)
        position += 1
        return token

    def primary(depth):
        require(depth <= MAX_DEPTH, "SPDX expression nesting too deep")
        token = take()
        if token == "(":
            node = disjunction(depth + 1)
            require(take() == ")", "unbalanced parentheses: %r" % expression)
            return node
        require(token != ")", "unbalanced parentheses: %r" % expression)
        name = _license_id(token)
        if peek() == "WITH":
            take()
            exception = take()
            require(exception.upper() not in OPERATORS and re.fullmatch(r"[A-Za-z0-9.-]+", exception) is not None,
                    "not an SPDX exception id: %r" % exception)
            return name + " WITH " + exception
        return name

    def conjunction(depth):
        terms = [primary(depth)]
        while peek() == "AND":
            take()
            terms.append(primary(depth))
        return terms[0] if len(terms) == 1 else ("AND", terms)

    def disjunction(depth):
        terms = [conjunction(depth)]
        while peek() == "OR":
            take()
            terms.append(conjunction(depth))
        return terms[0] if len(terms) == 1 else ("OR", terms)

    node = disjunction(0)
    require(position == len(tokens), "trailing tokens in %r" % expression)
    return node


def render(node) -> str:
    if type(node) is str:
        return node
    kind, terms = node
    return (" %s " % kind).join(render(term) if type(term) is str else "(" + render(term) + ")" for term in terms)


def _canonical_node(node):
    """Flatten nested operators of the same kind, drop duplicate operands and sort them."""
    if type(node) is str:
        return node
    kind, terms = node
    flat = []
    for term in (_canonical_node(term) for term in terms):
        flat.extend(term[1] if type(term) is tuple and term[0] == kind else [term])
    unique = sorted({render(term): term for term in flat}.items())
    terms = [term for _, term in unique]
    return terms[0] if len(terms) == 1 else (kind, terms)


def canonical(expression: str) -> str:
    return render(_canonical_node(parse(expression)))


def normalise_legacy(field: str) -> str:
    """A crates.io legacy license field "A/B" read as "A OR B" (rule legacySlash); other strings are unchanged."""
    parts = field.split("/")
    if len(parts) > 1 and all(IDSTRING.fullmatch(part) for part in parts):
        return " OR ".join(parts)
    return field


# --- classification -------------------------------------------------------------------------------------------------

class Policy:
    """The effective classification: the base categories plus the amendment's scoped class, decisions and elections."""

    def __init__(self, categories: dict):
        self.categories = categories
        self.exact = {canonical(expression): name for name, members in categories.items() for expression in members}

    def leaf(self, term: str, component: dict) -> str:
        for name in ("DENIED", "PLANNED_UNRESOLVED"):
            if term in self.categories[name]:
                return name
        if term in self.categories["OPTIONAL_EXPLICIT_REVIEW"]:
            return APPROVED if component["name"] in DECISIONS.get(term, ((), None))[0] else "OPTIONAL_EXPLICIT_REVIEW"
        if term in self.categories["OPEN_CONTENT"]:
            return "OPEN_CONTENT" if component["kind"] in OPEN_CONTENT_KINDS else "OUT_OF_SCOPE"
        for name in ("ALLOWED_EXCEPTION_EXPRESSION", "DEFAULT_ALLOWED"):
            if term in self.categories[name]:
                return name
        if term in CLASS_EXPRESSIONS:
            return CLASS if component["kind"] in CLASS_KINDS and component["custody"] in CLASS_CUSTODY else "OUT_OF_SCOPE"
        return "UNKNOWN"

    def resolve(self, node, component: dict, leaves: list) -> tuple:
        """(outcome, rank, elections): blocking outcomes follow base precedence; accepted ones carry an election rank."""
        if type(node) is str:
            outcome = self.leaf(node, component)
            leaves.append({"term": node, "category": outcome})
            rank = ACCEPTED_RANK.get(outcome)
            return outcome, (0 if node == CORE_LICENSE and rank is not None else rank), []
        kind, terms = node
        results = [self.resolve(term, component, leaves) for term in terms]
        blocking = [outcome for outcome, rank, _ in results if rank is None]
        if kind == "AND":
            if blocking:
                return min(blocking, key=lambda outcome: BLOCKING_RANK[outcome]), None, []
            return "ACCEPTED_AND", max(rank for _, rank, _ in results), [e for _, _, elections in results for e in elections]
        accepted = [(term, rank, elections) for term, (_, rank, elections) in zip(terms, results) if rank is not None]
        if not accepted:
            # An OR with no accepted alternative takes its least restrictive alternative's outcome (order-independent).
            return max(blocking, key=lambda outcome: BLOCKING_RANK[outcome]), None, []
        group = render(node)
        owner = OWNER_ELECTIONS.get(group)
        named = [item for item in accepted if owner is not None and render(item[0]) == owner[0] and component["name"] == owner[2]]
        term, rank, elections = named[0] if named else min(accepted, key=lambda item: (item[1], render(item[0])))
        return "ACCEPTED_OR", rank, [{"group": group, "elected": render(term)}] + elections


def classify(policy: Policy, expression: str, component: dict) -> dict:
    """The effective outcome of one expression for one component (name, kind, custody, crateField)."""
    require(type(component) is dict and set(component) == {"name", "kind", "custody", "crateField"}
            and type(component["name"]) is str and component["name"] != "" and component["kind"] in KINDS
            and type(component["custody"]) is str and type(component["crateField"]) is bool, "component identity")
    normalised = normalise_legacy(expression) if component["crateField"] else expression
    node = _canonical_node(parse(normalised))
    text = render(node)
    if type(node) is not str and text in policy.exact:
        # A compound listed exactly in the base keeps its base outcome, however it is spelled.
        outcome = policy.exact[text]
        if outcome == "OPTIONAL_EXPLICIT_REVIEW" and component["name"] in DECISIONS.get(text, ((), None))[0]:
            outcome = APPROVED
        return {"expression": expression, "canonical": text, "outcome": outcome, "elections": [], "leaves": []}
    leaves = []
    outcome, _, elections = policy.resolve(node, component, leaves)
    return {"expression": expression, "canonical": text, "outcome": outcome, "elections": elections, "leaves": leaves}


def base_categories(raw: bytes) -> dict:
    """The base policy's six exact-expression categories, which the amendment must not overlap or weaken."""
    try:
        policy = yaml.load(raw.decode("utf-8"), Loader=_UniqueKeyLoader)
    except (yaml.YAMLError, UnicodeDecodeError) as error:
        raise ValueError("base policy is not valid YAML: %s" % error) from None
    require(type(policy) is dict and policy.get("policyVersion") == "0.3.0"
            and policy.get("evaluation", {}).get("expressionMatching") == "EXACT_SPDX_EXPRESSION"
            and policy.get("evaluation", {}).get("precedence", [])[:4]
            == ["DENIED", "UNKNOWN", "PLANNED_UNRESOLVED", "OPTIONAL_EXPLICIT_REVIEW"]
            and policy.get("deniedRule", {}).get("overrideAllowed") is False, "base policy identity and rules")
    return {
        "DEFAULT_ALLOWED": frozenset(policy["defaultAllowedSpdx"]),
        "ALLOWED_EXCEPTION_EXPRESSION": frozenset(row["expression"] for row in policy["allowedExceptionExpressions"]),
        "OPEN_CONTENT": frozenset(row["expression"] for row in policy["openContentSpdx"]),
        "OPTIONAL_EXPLICIT_REVIEW": frozenset(policy["optionalExplicitReview"]),
        "PLANNED_UNRESOLVED": frozenset(policy["plannedUnresolvedSpdx"]),
        "DENIED": frozenset(policy["deniedForDefaultDistribution"]),
    }


# --- the record -----------------------------------------------------------------------------------------------------

def _closed(value, keys, message):
    require(type(value) is dict and set(value) == set(keys), message)


def _text(value, message):
    require(type(value) is str and value != "" and "\x00" not in value, message)


def decision_body(row: dict) -> dict:
    """The digested part of a decision record: the base's required fields plus its subjects and deciding question."""
    body = {key: row[key] for key in DECISION_FIELDS[:-1]}
    body.update(subjects=row["subjects"], decidedBy=row["decidedBy"])
    return body


def record(raw: bytes) -> dict:
    value = _json(raw)
    _closed(value, ("schemaVersion", "amendmentId", "base", "ownerDecisions", "hostOsSystemLibraryClass", "ownerElections",
                    "rules", "releaseAdmission", "explicitReviewDecisions", "notClaimed"), "closed amendment record")
    require(value["schemaVersion"] == SCHEMA and value["amendmentId"] == AMENDMENT_ID, "amendment schema and id")
    require(value["base"] == {"path": BASE_PATH, "sha256": BASE_SHA256, "policyVersion": "0.3.0"}, "the base policy pin")
    decisions = value["ownerDecisions"]
    require(type(decisions) is list and len(decisions) == len(OWNER_QUESTIONS), "owner decisions Q-L, Q-L2, Q-L3")
    for row, (qid, selected) in zip(decisions, OWNER_QUESTIONS):
        _closed(row, ("id", "selected", "date", "via", "summary"), "closed owner decision")
        require(row["id"] == qid and row["selected"] == selected and row["date"] == "2026-10-10", "owner decision " + qid)
        _text(row["via"], "decision route")
        _text(row["summary"], "decision summary")
    klass = value["hostOsSystemLibraryClass"]
    _closed(klass, ("outcome", "expressions", "allowedKinds", "allowedCustody", "neverFor", "releaseOutcome", "decidedBy"),
            "closed host-OS class")
    require(klass["outcome"] == CLASS and klass["expressions"] == list(CLASS_EXPRESSIONS)
            and klass["allowedKinds"] == list(CLASS_KINDS) and klass["allowedCustody"] == list(CLASS_CUSTODY)
            and klass["decidedBy"] == ["Q-L", "Q-L2"], "the decided host-OS class, exactly")
    require(type(klass["neverFor"]) is list and klass["neverFor"] and all(type(x) is str and x for x in klass["neverFor"]),
            "class exclusions")
    _text(klass["releaseOutcome"], "class release outcome")
    elections = value["ownerElections"]
    require(type(elections) is list and [(row.get("group"), row.get("elects"), row.get("decidedBy"), row.get("component"))
                                          for row in elections if type(row) is dict]
            == [(group, *named) for group, named in OWNER_ELECTIONS.items()], "the owner-named elections, exactly")
    for row in elections:
        _closed(row, ("group", "elects", "decidedBy", "component"), "closed owner election")
        require(canonical(row["group"]) == row["group"], "an owner election names a canonical group")
    rules = value["rules"]
    _closed(rules, ("orChoice", "andTerms", "legacySlash", "scope", "precedence"), "closed rules")
    for name, decided in (("orChoice", "Q-L2"), ("andTerms", "Q-L3"), ("legacySlash", "Q-L3"), ("scope", "Q-L")):
        _closed(rules[name], ("rule", "decidedBy"), "closed rule " + name)
        _text(rules[name]["rule"], "rule text")
        require(rules[name]["decidedBy"] == decided, "rule %s decided by %s" % (name, decided))
    _text(rules["precedence"], "rule precedence")
    admission = value["releaseAdmission"]
    require(type(admission) is dict and set(admission) == {CLASS, APPROVED, "ACCEPTED_AND", "ACCEPTED_OR"}
            and all(type(text) is str and text for text in admission.values()), "release admission per amendment outcome")
    reviews = value["explicitReviewDecisions"]
    require(type(reviews) is list and len(reviews) == len(DECISIONS), "explicit-review decisions")
    seen = set()
    for row in reviews:
        _closed(row, DECISION_FIELDS + ("subjects", "decidedBy"), "closed explicit-review decision")
        for key in DECISION_FIELDS[:-1]:
            _text(row[key], "decision field " + key)
        require(row["expression"] in DECISIONS and row["expression"] not in seen, "a decided explicit-review expression")
        seen.add(row["expression"])
        subjects, decided = DECISIONS[row["expression"]]
        require(row["subjects"] == list(subjects) and row["decidedBy"] == decided, "decision subjects and question")
        require(row["decisionDigest"] == "sha256:" + digest(canonical_json(decision_body(row))),
                "decision digest of " + row["expression"])
    require(type(value["notClaimed"]) is list and value["notClaimed"], "non-claims")
    return value


def effective_policy(read) -> Policy:
    """The base categories under the amendment, after check()."""
    check(read)
    return Policy(base_categories(read(BASE_PATH)))


def check(read) -> dict:
    try:
        return _check(read)
    except (TypeError, KeyError, AttributeError, IndexError, RecursionError) as error:
        raise ValueError("malformed amendment record: %s" % error) from None


def _check(read) -> dict:
    value = record(read(RECORD_PATH))
    base = read(BASE_PATH)
    require(digest(base) == BASE_SHA256, "the base policy changed")
    categories = base_categories(base)
    exact = frozenset().union(*categories.values())
    require(not set(CLASS_EXPRESSIONS) & exact, "the host-OS class does not reclassify a base expression")
    require(set(DECISIONS) <= categories["OPTIONAL_EXPLICIT_REVIEW"], "decisions answer base explicit-review expressions")
    policy = Policy(categories)
    vectors = _json(read(VECTORS_PATH))
    _closed(vectors, ("schemaVersion", "cases"), "closed vectors")
    require(vectors["schemaVersion"] == "planeon.internal.license-policy-amendment-vectors/v2"
            and type(vectors["cases"]) is list and vectors["cases"], "vector schema")
    keys = set()
    for case in vectors["cases"]:
        _closed(case, ("expression", "component", "outcome", "elections", "note"), "closed vector")
        key = canonical_json([case["expression"], case["component"]])
        require(key not in keys, "duplicate vector")
        keys.add(key)
        require(case["outcome"] in OUTCOMES, "vector outcome")
        try:
            got = classify(policy, case["expression"], case["component"])
        except ValueError:
            got = {"outcome": "REFUSED", "elections": []}
        require(got["outcome"] == case["outcome"] and got["elections"] == case["elections"],
                "vector %r for %s: expected %s %s, got %s %s" % (case["expression"], case["component"]["name"],
                                                                 case["outcome"], case["elections"], got["outcome"],
                                                                 got["elections"]))
    require({case["outcome"] for case in vectors["cases"]} == set(OUTCOMES),
            "the vectors cover every outcome the classifier returns, and refusal")
    require(any(case["component"]["crateField"] for case in vectors["cases"]), "a legacy crate field vector")
    return value


if __name__ == "__main__":
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    check(lambda path: (root / path).read_bytes())
    print("LIC-HOST amendment A1 valid: base policy unchanged; scoped class, decisions, elections and vectors hold.")
