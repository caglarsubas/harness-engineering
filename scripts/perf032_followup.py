#!/usr/bin/env python3
"""PERF-032-F: the MET-PERF-032 review round-3 findings F12, F14 and F15, checked on current bytes.

The merged MET-PERF-032 packet text is immutable; its findings are answered by tighter checks, and each item states
what it covers:
- F12: in every route test, setup values contain none of the listed deferring constructs: lambda, generator,
  comprehension, a call whose final name is map, filter, iter, zip, reversed, enumerate or partial (bare or through
  any module), a call through getattr, __import__, eval, exec, vars, globals or locals, or a call whose target is itself
  computed (a subscript or a call); and every route call's receiver is a module alias, never a setup name. This is a
  closed list, not a proof that nothing defers;
- F14: the stubbed status replay's model (`scripts/native_qualification_v2.py`) uses exactly its reviewed set of Name
  ids and Attribute names, so no new name or attribute (such as `json.__builtins__`, `__loader__`, `__spec__` or
  `RefResolver.resolve_remote`) can appear. A function composed only from existing symbols is not excluded; the model's
  history-chain byte pin is what fixes its behaviour;
- F15: executing the current `scripts/schema_unique.py` bytes and running its `unique` over a fixed corpus leave the
  jsonschema family as found: every value of every jsonschema, referencing and jsonschema_specifications module dict
  and of the classes they define, the Draft 2020-12 class dict and its VALIDATORS, by identity, and for every function
  among them its code, defaults, keyword defaults, attribute dict and closure cells, and each module's own identity in
  sys.modules, with every identified object kept alive so no identity can be reused (identities are taken with the id
  bound at import). `_keywords.uniq is _utils.uniq` is checked too. The state is checked before the exec, after it and
  after the whole corpus; every answer of the reviewed `unique` and, after the corpus, of stock uniqueItems' `uniq` and
  of a fresh stock Draft 2020-12 validator must equal the stock answer computed before the exec; these three answer
  sets are the only answers compared (no other validator class is consulted). This is a tripwire for the named
  changes, not a proof: the bytes run in this check's own process with full Python access, so they can also rebind or
  mutate this check's globals, locals and builtins (its require, its corpus and expected answers, its stored id), and
  then nothing is excluded. Even when the check itself is left intact, a change the snapshot cannot see (in-place
  mutation of an object's internal state, replaced interpreter internals, a patched builtin) that leaves those three
  answer sets unchanged, and any change triggered by anything other than the exec and the corpus calls, is not
  excluded. The PERF-032 layer's byte pin of the reviewed bytes is the guard.

Every function takes a `read(path) -> bytes` callable, so a layer validator can pass its reviewed bytes. Every refusal
is a ValueError naming the refused rule.
"""
from __future__ import annotations

import ast
import hashlib
import json
from typing import Any, Callable

ROUTE_TEST = "test_newest_authority_is_freshly_checked_on_every_route"
DEFERRING = (ast.Lambda, ast.GeneratorExp, ast.ListComp, ast.SetComp, ast.DictComp)
DEFERRING_CALLS = frozenset({"map", "filter", "iter", "zip", "reversed", "enumerate", "partial"})
# Calls that reach a callable by computed name; refused in setup values because they can reach any deferring builtin.
DYNAMIC_CALLS = frozenset({"getattr", "__import__", "eval", "exec", "vars", "globals", "locals"})
STATUS_MODEL_PATH = "scripts/native_qualification_v2.py"
MODEL_SYMBOLS_SHA256 = "1a80347b5164c9eada78a132fe65e5fd27aab8ce58dd137fae73b72fbfbdb083"
UNIQUE_PATH = "scripts/schema_unique.py"
UNIQUE_ATOMS = (0, 1, True, False, 1.0, "a", None, [], {}, [1], [True], {"a": 1}, {"a": True}, {"a": [1, 2]}, [[1]],
                [{}])
FAMILY = ("jsonschema", "referencing", "jsonschema_specifications")
# Bound at import, so a builtins.id patched by the bytes under check cannot hide a change from the snapshot.
_ID = id


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _module_aliases(tree: ast.Module) -> set[str]:
    aliases = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "scripts":
            aliases |= {alias.asname or alias.name for alias in node.names}
        elif isinstance(node, ast.Import):
            aliases |= {(alias.asname or alias.name).split(".")[0] for alias in node.names}
    return aliases


def _deferring_call(node: ast.Call) -> bool:
    """A call to a listed deferring callable by its final name (map, builtins.map, functools.partial), a call that
    reaches a callable by computed name, or a call whose target is itself computed (a subscript or another call)."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in DEFERRING_CALLS | DYNAMIC_CALLS
    if isinstance(func, ast.Attribute):
        return func.attr in DEFERRING_CALLS | DYNAMIC_CALLS
    return True


def check_route_test(path: str, source: bytes) -> int:
    """F12 for one test file; returns its number of route calls."""
    tree = ast.parse(source)
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == ROUTE_TEST]
    require(len(functions) == 1, "one route test: " + path)
    function, aliases = functions[0], _module_aliases(tree)
    tables = [i for i, node in enumerate(function.body) if isinstance(node, ast.Assign)
              and [ast.unparse(t) for t in node.targets] == ["calls"] and isinstance(node.value, ast.Dict)]
    require(len(tables) == 1, "one route table: " + path)
    setup_names = set()
    for statement in function.body[:tables[0]]:
        require(isinstance(statement, ast.Assign) and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name), "route setup holds only assignments: " + path)
        setup_names.add(statement.targets[0].id)
        for node in ast.walk(statement.value):
            require(not isinstance(node, DEFERRING)
                    and not (isinstance(node, ast.Call) and _deferring_call(node)),
                    "route setup defers no computation: %s %s" % (statement.targets[0].id, path))
    calls = 0
    for value in function.body[tables[0]].value.values:
        body = value.body if isinstance(value, ast.Lambda) else value
        func = body.func if isinstance(body, ast.Call) else body
        require(isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id in aliases
                and func.value.id not in setup_names, "route call receiver is a module alias: " + path)
        calls += 1
    return calls


def model_symbols(source: bytes) -> bytes:
    tree = ast.parse(source)
    names = sorted({node.id for node in ast.walk(tree) if isinstance(node, ast.Name)})
    attributes = sorted({node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)})
    return canonical({"names": names, "attributes": attributes})


def check_model_symbols(source: bytes) -> None:
    """F14: the stubbed replay's model uses exactly the reviewed symbol set."""
    require(digest(model_symbols(source)) == MODEL_SYMBOLS_SHA256, "the stubbed model's exact symbol set")


def unique_corpus() -> list:
    """Every pair of the atoms, every triple of the first eight, and a few longer arrays: 773 arrays."""
    import copy
    import itertools
    atoms = UNIQUE_ATOMS
    arrays = [[]] + [list(pair) for pair in itertools.product(atoms, repeat=2)]
    arrays += [list(triple) for triple in itertools.product(atoms[:8], repeat=3)]
    arrays += [list(atoms), list(atoms) + list(atoms), [{"a": [1, 2]}] * 5, [[1], [True], [1.0], [1]]]
    return copy.deepcopy(arrays)


def _function_state(value: Any, keep: list) -> tuple:
    import types
    value = getattr(value, "__func__", value)
    if not isinstance(value, types.FunctionType):
        return ()
    cells = []
    for cell in value.__closure__ or ():
        try:
            keep.append(cell.cell_contents)
            cells.append(_ID(cell.cell_contents))
        except ValueError:
            cells.append(None)
    keep.extend((value.__code__, value.__defaults__, value.__kwdefaults__, *vars(value).values()))
    return (_ID(value.__code__), _ID(value.__defaults__), _ID(value.__kwdefaults__),
            tuple(sorted((k, _ID(v)) for k, v in vars(value).items())), tuple(cells))


def _dict_state(mapping: Any, keep: list) -> tuple:
    """Identities, with every identified object kept alive in keep, so no id can be reused while it is compared."""
    keep.extend(mapping.values())
    return tuple(sorted((k, _ID(v), _function_state(v, keep)) for k, v in mapping.items()))


def _oracle_state(keep: list) -> tuple:
    import sys
    import jsonschema
    from jsonschema import _keywords, _utils
    modules = sorted(name for name in sys.modules if name.split(".")[0] in FAMILY)
    classes = sorted({(value.__module__, value.__qualname__, value) for name in modules
                      for value in vars(sys.modules[name]).values()
                      if isinstance(value, type) and str(value.__module__).split(".")[0] in FAMILY},
                     key=lambda row: row[:2])
    keep.extend(sys.modules[name] for name in modules)
    return (tuple((name, _ID(sys.modules[name]), _dict_state(vars(sys.modules[name]), keep)) for name in modules),
            tuple((module, qualname, _dict_state(vars(cls), keep)) for module, qualname, cls in classes),
            _dict_state(vars(jsonschema.Draft202012Validator), keep),
            _dict_state(jsonschema.Draft202012Validator.VALIDATORS, keep),
            _keywords.uniq is _utils.uniq)


def check_unique_oracle(source: bytes) -> int:
    """F15: the current schema_unique bytes leave the jsonschema family as found, after the exec and after the corpus;
    both their unique and stock uniq answer every corpus case as stock jsonschema did before the exec; returns the
    corpus size."""
    import jsonschema
    from jsonschema import _keywords, _utils
    corpus = unique_corpus()
    keep: list = []
    before = _oracle_state(keep)
    require(before[-1], "stock uniqueItems calls jsonschema's own uniq")
    expected = [_utils.uniq(case) for case in corpus]
    stock = jsonschema.Draft202012Validator({"uniqueItems": True})
    valid = [stock.is_valid(case) for case in corpus]
    require(_oracle_state(keep) == before, "stock uniq leaves jsonschema as found")
    namespace: dict[str, Any] = {"__name__": "reviewed_schema_unique_current"}
    exec(compile(source, UNIQUE_PATH, "exec"), namespace)
    require(_oracle_state(keep) == before, "schema_unique leaves jsonschema as found")
    for case, answer in zip(corpus, expected):
        require(namespace["unique"](case) is answer, "uniqueItems answer: " + repr(case)[:200])
    require(_oracle_state(keep) == before and _keywords.uniq is _utils.uniq,
            "schema_unique leaves jsonschema as found after the corpus")
    for case, answer, verdict in zip(corpus, expected, valid):
        require(_keywords.uniq(case) is answer, "stock uniqueItems answer after the corpus: " + repr(case)[:200])
        require(jsonschema.Draft202012Validator({"uniqueItems": True}).is_valid(case) is verdict,
                "stock Draft 2020-12 verdict after the corpus: " + repr(case)[:200])
    return len(corpus)


def validate_perf032_followup(read: Callable[[str], bytes], test_paths: list[str]) -> int:
    """F12 on every given route test, F14 on the stubbed model and F15 on the schema_unique bytes; returns the route
    calls."""
    require(len(test_paths) >= 17 and len(set(test_paths)) == len(test_paths), "the route tests")
    calls = sum(check_route_test(path, read(path)) for path in test_paths)
    check_model_symbols(read(STATUS_MODEL_PATH))
    check_unique_oracle(read(UNIQUE_PATH))
    return calls
