#!/usr/bin/env python3
"""LIC-HOST license-policy amendment A1: host-OS class, OR-choice and AND-term rules, legacy crate normalisation.

The base policy (legal/third-party-license-policy.yaml) stays byte-identical, because many records pin it. The reviewed
amendment record (legal/license-policy-amendment/amendment.json) carries the owner's decisions Q-L, Q-L2 and Q-L3:
- a HOST_OS_SYSTEM_LIBRARY class of exact expressions, for host-OS programs and libraries and for system libraries
  statically linked into pinned upstream binaries;
- explicit-review decision records, with the base policy's required decision fields;
- three rules for compound expressions.

classify(expression) gives the effective outcome of one SPDX expression under the base policy plus the amendment. It
never weakens a DENIED, UNKNOWN or PLANNED_UNRESOLVED term. check(read) validates the record and its vectors through an
injected byte reader.
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
CLASS = "HOST_OS_SYSTEM_LIBRARY"
CORE_LICENSE = "Apache-2.0"
ACCEPTED = ("DEFAULT_ALLOWED", "ALLOWED_EXCEPTION_EXPRESSION", "OPEN_CONTENT", CLASS, "APPROVED_EXPLICIT_REVIEW")
BLOCKING = ("DENIED", "UNKNOWN", "PLANNED_UNRESOLVED", "OPTIONAL_EXPLICIT_REVIEW")
TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9.+-]+)")
LICENSE_ID = re.compile(r"[A-Za-z0-9.+-]+\Z")
MAX_BYTES = 4_194_304


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value) -> bytes:
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


def base_categories(raw: bytes) -> dict:
    """The base policy's six exact-expression categories, which the amendment must not overlap or weaken."""
    try:
        policy = yaml.load(raw.decode("utf-8"), Loader=_UniqueKeyLoader)
    except (yaml.YAMLError, UnicodeDecodeError) as error:
        raise ValueError("base policy is not valid YAML: %s" % error) from None
    require(type(policy) is dict and policy.get("policyVersion") == "0.3.0"
            and policy.get("evaluation", {}).get("expressionMatching") == "EXACT_SPDX_EXPRESSION"
            and policy.get("deniedRule", {}).get("overrideAllowed") is False, "base policy identity and rules")
    categories = {
        "DEFAULT_ALLOWED": set(policy["defaultAllowedSpdx"]),
        "ALLOWED_EXCEPTION_EXPRESSION": {row["expression"] for row in policy["allowedExceptionExpressions"]},
        "OPEN_CONTENT": {row["expression"] for row in policy["openContentSpdx"]},
        "OPTIONAL_EXPLICIT_REVIEW": set(policy["optionalExplicitReview"]),
        "PLANNED_UNRESOLVED": set(policy["plannedUnresolvedSpdx"]),
        "DENIED": set(policy["deniedForDefaultDistribution"]),
    }
    return {key: frozenset(value) for key, value in categories.items()}


def _tokens(expression: str) -> list:
    position, tokens = 0, []
    while position < len(expression):
        match = TOKEN.match(expression, position)
        require(match is not None and match.end() > position, "malformed SPDX expression: %r" % expression)
        tokens.append(match.group(1))
        position = match.end()
        while position < len(expression) and expression[position] == " ":
            position += 1
    require(tokens, "empty SPDX expression")
    return tokens


def parse(expression: str):
    """Parse an SPDX expression into ("OR", [...]), ("AND", [...]) or a leaf string ("X" or "X WITH E")."""
    require(type(expression) is str and expression == expression.strip() and "\n" not in expression,
            "an SPDX expression is one trimmed line")
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

    def primary():
        token = take()
        if token == "(":
            node = disjunction()
            require(take() == ")", "unbalanced parentheses: %r" % expression)
            return node
        require(LICENSE_ID.fullmatch(token) and token not in ("AND", "OR", "WITH", ")"), "bad license id in %r" % expression)
        if peek() == "WITH":
            take()
            exception = take()
            require(LICENSE_ID.fullmatch(exception) and exception not in ("AND", "OR", "WITH"), "bad exception in %r" % expression)
            return token + " WITH " + exception
        return token

    def conjunction():
        terms = [primary()]
        while peek() == "AND":
            take()
            terms.append(primary())
        return terms[0] if len(terms) == 1 else ("AND", terms)

    def disjunction():
        terms = [conjunction()]
        while peek() == "OR":
            take()
            terms.append(conjunction())
        return terms[0] if len(terms) == 1 else ("OR", terms)

    node = disjunction()
    require(position == len(tokens), "trailing tokens in %r" % expression)
    return node


def normalise_legacy(field: str) -> str:
    """A crates.io legacy license field "A/B" read as "A OR B" (rule legacySlash); other strings are unchanged."""
    if "/" in field and all(LICENSE_ID.fullmatch(part.strip()) for part in field.split("/")):
        return " OR ".join(part.strip() for part in field.split("/"))
    return field


class Policy:
    """The effective classification: the base categories plus the amendment's class and decisions."""

    def __init__(self, categories: dict, class_expressions: frozenset, approved_reviews: frozenset):
        self.categories = categories
        self.class_expressions = class_expressions
        self.approved_reviews = approved_reviews

    def leaf(self, term: str) -> str:
        for name in ("DENIED", "PLANNED_UNRESOLVED"):
            if term in self.categories[name]:
                return name
        if term in self.categories["OPTIONAL_EXPLICIT_REVIEW"]:
            return "APPROVED_EXPLICIT_REVIEW" if term in self.approved_reviews else "OPTIONAL_EXPLICIT_REVIEW"
        for name in ("OPEN_CONTENT", "ALLOWED_EXCEPTION_EXPRESSION", "DEFAULT_ALLOWED"):
            if term in self.categories[name]:
                return name
        if term in self.class_expressions:
            return CLASS
        return "UNKNOWN"

    def resolve(self, node) -> tuple:
        """(outcome, elections): an accepted outcome with its OR elections, or the first blocking outcome."""
        if type(node) is str:
            return self.leaf(node), []
        kind, terms = node
        results = [self.resolve(term) for term in terms]
        if kind == "AND":
            for outcome, _ in results:
                if outcome not in ACCEPTED and outcome not in ("ACCEPTED_AND", "ACCEPTED_OR"):
                    return outcome, []
            return "ACCEPTED_AND", [election for _, elections in results for election in elections]
        accepted = [(term, elections) for term, (outcome, elections) in zip(terms, results)
                    if outcome in ACCEPTED or outcome in ("ACCEPTED_AND", "ACCEPTED_OR")]
        if accepted:
            # The election prefers the core license (Apache-2.0) when it is an accepted alternative, else the first.
            term, elections = next(((term, e) for term, e in accepted if term == CORE_LICENSE), accepted[0])
            return "ACCEPTED_OR", [_render(term)] + elections
        return results[0][0], []


def _render(node) -> str:
    if type(node) is str:
        return node
    kind, terms = node
    return (" %s " % kind).join(_render(term) if type(term) is str else "(" + _render(term) + ")" for term in terms)


def classify(policy: Policy, expression: str, crate_field: bool = False) -> dict:
    """The effective outcome of one expression; crate_field applies the legacy-slash rule first."""
    normalised = normalise_legacy(expression) if crate_field else expression
    node = parse(normalised)
    exact = policy.leaf(normalised) if type(node) is str or normalised in _all_exact(policy) else None
    if exact is not None and exact != "UNKNOWN":
        return {"expression": expression, "normalised": normalised, "outcome": exact, "elections": []}
    outcome, elections = policy.resolve(node)
    return {"expression": expression, "normalised": normalised, "outcome": outcome, "elections": elections}


def _all_exact(policy: Policy) -> frozenset:
    return frozenset().union(*policy.categories.values()) | policy.class_expressions


def _closed(value, keys, message):
    require(type(value) is dict and set(value) == set(keys), message)


def _text(value, message):
    require(type(value) is str and value != "" and "\x00" not in value, message)


def record(raw: bytes) -> dict:
    value = _json(raw)
    _closed(value, ("schemaVersion", "amendmentId", "base", "ownerDecisions", "hostOsSystemLibraryClass", "rules",
                    "explicitReviewDecisions", "notClaimed"), "closed amendment record")
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
    _closed(klass, ("outcome", "expressions", "allowedKinds", "allowedCustody", "neverFor", "releaseOutcome",
                    "decidedBy"), "closed host-OS class")
    require(klass["outcome"] == CLASS and klass["decidedBy"] == ["Q-L", "Q-L2"], "host-OS class outcome and decisions")
    expressions = klass["expressions"]
    require(type(expressions) is list and expressions and len(set(expressions)) == len(expressions), "class expressions")
    for expression in expressions:
        require(type(parse(expression)) is str, "a class entry is one exact license term: %r" % expression)
    for key in ("allowedKinds", "allowedCustody", "neverFor"):
        require(type(klass[key]) is list and klass[key] and all(type(item) is str and item for item in klass[key]),
                "class " + key)
    _text(klass["releaseOutcome"], "class release outcome")
    rules = value["rules"]
    _closed(rules, ("orChoice", "andTerms", "legacySlash", "precedence"), "closed rules")
    for name, decided in (("orChoice", "Q-L2"), ("andTerms", "Q-L3"), ("legacySlash", "Q-L3")):
        _closed(rules[name], ("rule", "decidedBy"), "closed rule " + name)
        _text(rules[name]["rule"], "rule text")
        require(rules[name]["decidedBy"] == decided, "rule %s decided by %s" % (name, decided))
    _text(rules["precedence"], "rule precedence")
    reviews = value["explicitReviewDecisions"]
    require(type(reviews) is list and reviews, "explicit-review decisions")
    for row in reviews:
        _closed(row, DECISION_FIELDS + ("subjects", "decidedBy"), "closed explicit-review decision")
        for key in DECISION_FIELDS[:-1]:
            _text(row[key], "decision field " + key)
        require(row["decidedBy"] in ("Q-L", "Q-L2") and type(row["subjects"]) is list and row["subjects"],
                "decision provenance and subjects")
        body = {key: row[key] for key in DECISION_FIELDS[:-1]}
        require(row["decisionDigest"] == "sha256:" + digest(canonical(body)), "decision digest of " + row["expression"])
    require(type(value["notClaimed"]) is list and value["notClaimed"], "non-claims")
    return value


def effective_policy(read) -> Policy:
    """The base categories plus the amendment, after check()."""
    value = check(read)
    categories = base_categories(read(BASE_PATH))
    return Policy(categories, frozenset(value["hostOsSystemLibraryClass"]["expressions"]),
                  frozenset(row["expression"] for row in value["explicitReviewDecisions"]))


def check(read) -> dict:
    try:
        return _check(read)
    except (TypeError, KeyError, AttributeError, IndexError) as error:
        raise ValueError("malformed amendment record: %s" % error) from None


def _check(read) -> dict:
    value = record(read(RECORD_PATH))
    base = read(BASE_PATH)
    require(digest(base) == BASE_SHA256, "the base policy changed")
    categories = base_categories(base)
    exact = frozenset().union(*categories.values())
    klass = frozenset(value["hostOsSystemLibraryClass"]["expressions"])
    require(not klass & exact, "the host-OS class does not reclassify a base expression")
    for row in value["explicitReviewDecisions"]:
        require(row["expression"] in categories["OPTIONAL_EXPLICIT_REVIEW"],
                "a decision record answers a base explicit-review expression: " + row["expression"])
    policy = Policy(categories, klass, frozenset(row["expression"] for row in value["explicitReviewDecisions"]))
    vectors = _json(read(VECTORS_PATH))
    _closed(vectors, ("schemaVersion", "cases"), "closed vectors")
    require(vectors["schemaVersion"] == "planeon.internal.license-policy-amendment-vectors/v1"
            and type(vectors["cases"]) is list and vectors["cases"], "vector schema")
    for case in vectors["cases"]:
        _closed(case, ("expression", "crateField", "outcome", "elections", "note"), "closed vector")
        got = classify(policy, case["expression"], case["crateField"])
        require(got["outcome"] == case["outcome"] and got["elections"] == case["elections"],
                "vector %r: expected %s %s, got %s %s" % (case["expression"], case["outcome"], case["elections"],
                                                         got["outcome"], got["elections"]))
    outcomes = {case["outcome"] for case in vectors["cases"]}
    require({"DENIED", "UNKNOWN", "OPTIONAL_EXPLICIT_REVIEW", "ACCEPTED_AND", "ACCEPTED_OR", CLASS} <= outcomes,
            "the vectors cover every kind of outcome")
    return value


if __name__ == "__main__":
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    check(lambda path: (root / path).read_bytes())
    print("LIC-HOST amendment A1 valid: base policy unchanged; class, rules, decisions and vectors hold.")
