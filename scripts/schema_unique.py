"""Draft 2020-12 validation whose uniqueItems gives jsonschema's answer with fewer comparisons.

jsonschema 4.24.0 checks uniqueItems by sorting the items; when they do not sort (objects, mixed types) it
compares every pair with its ``equal``, which is quadratic. Items that are ``equal`` always share the key
below, so comparing only items with the same key gives the same answer. The sorted path is unchanged.
Arrays holding anything but plain JSON, or nested deeper than MAX_GROUPED_DEPTH (a cycle always is), keep
jsonschema's own check, and so does any array whose grouping exceeds the recursion limit. So ``unique``
returns jsonschema's answer whenever jsonschema returns one; only where jsonschema itself would exceed the
recursion limit may this return an answer instead.

The class is not registered for a ``$schema`` URI, so a subschema that names its own ``$schema`` is checked
by jsonschema's stock class: the same answers, without the speed-up.
"""
from __future__ import annotations

from typing import Any

import jsonschema
from jsonschema import _utils

JSONSCHEMA_VERSION = "4.24.0"
MAX_GROUPED_DEPTH = 100
_PLAIN_SCALARS = (str, int, float, bool, type(None))


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


def plain_and_shallow(container: list) -> bool:
    """Every value is a plain-JSON dict, list or scalar, nested at most MAX_GROUPED_DEPTH deep."""
    pending = [(container, 0)]
    while pending:
        value, depth = pending.pop()
        if depth > MAX_GROUPED_DEPTH:
            return False
        if type(value) is dict:
            if not all(type(key) in _PLAIN_SCALARS for key in value):
                return False
            pending.extend((item, depth + 1) for item in value.values())
        elif type(value) is list:
            pending.extend((item, depth + 1) for item in value)
        elif type(value) not in _PLAIN_SCALARS:
            return False
    return True


def _grouped(container: list) -> bool:
    seen: dict[Any, list] = {}
    for item in container:
        key, item = equality_key(item), _utils.unbool(item)
        bucket = seen.setdefault(key, [])
        if any(_utils.equal(other, item) for other in bucket):
            return False
        bucket.append(item)
    return True


def unique(container: list) -> bool:
    """jsonschema 4.24.0 ``_utils.uniq``'s answer for the same container, whenever uniq returns one."""
    try:
        ordered = sorted(_utils.unbool(item) for item in container)
        for left, right in zip(ordered, ordered[1:]):
            if _utils.equal(left, right):
                return False
        return True
    except (NotImplementedError, TypeError):
        pass
    if not plain_and_shallow(container):
        return _utils.uniq(container)
    try:
        return _grouped(container)
    except RecursionError:
        return _utils.uniq(container)


def unique_items(validator: Any, enabled: Any, instance: Any, schema: Any) -> Any:
    """jsonschema's uniqueItems keyword with the same condition and message."""
    if enabled and validator.is_type(instance, "array") and not unique(instance):
        yield jsonschema.ValidationError(f"{instance!r} has non-unique elements")


SchemaInstanceValidator = jsonschema.validators.extend(
    jsonschema.Draft202012Validator, {"uniqueItems": unique_items}
)
