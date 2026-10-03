"""Source-only diagnostics; no selection, fixture, report or authority changes."""
from importlib.util import module_from_spec as _module_from_spec
from importlib.util import spec_from_file_location as _spec_from_file_location
from os import write as _write
from pathlib import Path as _Path
from time import monotonic as _monotonic

import pytest


def _load_diagnostics():
    # No sys.path edit, test-module import or mutable validator import. The
    # repository's exact source is separately pinned by packet acceptance.
    path = _Path(__file__).parent / "ci" / "pytest_diagnostics.py"
    spec = _spec_from_file_location("_planeon_met_perf_021_pytest_diagnostics", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("diagnostic module unavailable")
    module = _module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_DIAGNOSTICS = _load_diagnostics()
_STATE_KEY = "_planeon_met_perf_021_diagnostics"


def pytest_configure(config):
    manager = config.pluginmanager.getplugin("capturemanager")
    disable = manager.global_and_fixture_disabled if manager is not None else None
    write = _write

    def sink(data):
        if disable is None:
            raise RuntimeError("diagnostic capture boundary unavailable")
        # Pinned pytest 8.4.2 temporarily suspends BOTH global and fixture
        # capture here, restoring them in finally. FD2 is still the parent's
        # stderr pipe in nested pytest: this does not make nested output live.
        with disable():
            offset = 0
            while offset < len(data):
                amount = write(2, data[offset:])
                if type(amount) is not int or amount <= 0 or amount > len(data) - offset:
                    raise OSError("diagnostic sink unavailable")
                offset += amount
            return offset

    setattr(config, _STATE_KEY, _DIAGNOSTICS.Diagnostics(sink, _monotonic))


def _state(item):
    return getattr(item.config, _STATE_KEY)


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_setup(item):
    _state(item).start(item.nodeid, "setup")
    return (yield)


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_call(item):
    _state(item).start(item.nodeid, "call")
    return (yield)


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_teardown(item):
    _state(item).start(item.nodeid, "teardown")
    return (yield)


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_makereport(item, call):
    # Outermost wrapper sees the finalized skip/xfail report without changing it.
    report = yield
    _state(item).end(item.nodeid, report.when, report.outcome, report.duration,
                     xfail=hasattr(report, "wasxfail"))
    return report


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_sessionfinish(session, exitstatus):
    result = yield
    state = getattr(session.config, _STATE_KEY)
    session.exitstatus = state.finish(session.exitstatus)
    return result
