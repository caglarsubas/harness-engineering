"""Draft 2020-12 validation whose uniqueItems gives jsonschema's own answer with fewer comparisons.

jsonschema 4.24.0 checks uniqueItems by sorting the items; when they do not sort (objects, mixed
types) it compares every pair with its ``equal``, which is quadratic. Items that are ``equal``
always share the key below, so comparing only items with the same key gives the same answer.
The sorted path is unchanged, and any value outside plain JSON keeps jsonschema's own check.
"""
from __future__ import annotations

from typing import Any

import jsonschema
from jsonschema import _utils

JSONSCHEMA_VERSION = "4.24.0"
_PLAIN_JSON = (dict, list, str, int, float, bool, type(None))


def equality_key(value: Any) -> Any:
    """A hashable key that is equal for any two plain-JSON values jsonschema's ``equal`` accepts."""
    if type(value) is bool:
        return ("b", value)
    if type(value) is dict:
        return ("m", frozenset((key, equality_key(item)) for key, item in value.items()))
    if type(value) is list:
        return ("q", tuple(equality_key(item) for item in value))
    if type(value) is str:
        return ("s", value)
    if type(value) in (int, float):
        return ("n", value)
    return ("z", None)


def plain_json(value: Any) -> bool:
    if type(value) is dict:
        return all(plain_json(key) and plain_json(item) for key, item in value.items())
    if type(value) is list:
        return all(plain_json(item) for item in value)
    return type(value) in _PLAIN_JSON


def unique(container: list) -> bool:
    """The answer of jsonschema 4.24.0 ``_utils.uniq`` for the same container."""
    try:
        ordered = sorted(_utils.unbool(item) for item in container)
        for left, right in zip(ordered, ordered[1:]):
            if _utils.equal(left, right):
                return False
        return True
    except (NotImplementedError, TypeError):
        pass
    if not plain_json(container):
        return _utils.uniq(container)
    seen: dict[Any, list] = {}
    for item in container:
        key, item = equality_key(item), _utils.unbool(item)
        bucket = seen.setdefault(key, [])
        if any(_utils.equal(other, item) for other in bucket):
            return False
        bucket.append(item)
    return True


def unique_items(validator: Any, enabled: Any, instance: Any, schema: Any) -> Any:
    """jsonschema's uniqueItems keyword with the same condition and message."""
    if enabled and validator.is_type(instance, "array") and not unique(instance):
        yield jsonschema.ValidationError(f"{instance!r} has non-unique elements")


SchemaInstanceValidator = jsonschema.validators.extend(
    jsonschema.Draft202012Validator, {"uniqueItems": unique_items}
)
