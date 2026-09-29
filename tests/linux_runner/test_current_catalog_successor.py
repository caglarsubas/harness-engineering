"""Source-only adversarial tests for the exact current-to-accepted bridge."""
from copy import deepcopy

import pytest

from scripts import validate_current_catalog_successor as bridge


def test_full_accepted_tree_materializes_without_successor(tmp_path):
    destination = tmp_path.resolve() / "accepted-189"
    bridge.materialize_predecessor(destination)
    record = bridge.authority()
    assert len(record["baselineFiles"]) == 637
    assert len(list((destination / "task-packets").glob("*.yaml"))) == 189
    assert not (destination / "task-packets/MET-LINUX-003.yaml").exists()
    assert not (destination / bridge.AUTHORITY_PATH).exists()
    assert not (destination / bridge.BRIDGE_PATH).exists()
    assert not (destination / ".git").exists()
    for path, expected in record["baselineFiles"].items():
        assert bridge.digest(bridge.regular_bytes(destination, path)) == expected["sha256"]


def test_changed_live_source_is_rejected(monkeypatch):
    actual = bridge.regular_bytes

    def altered(root, path, **kwargs):
        raw = actual(root, path, **kwargs)
        return raw + b"\n" if path == "README.md" else raw

    monkeypatch.setattr(bridge, "regular_bytes", altered)
    with pytest.raises(ValueError, match="unchanged accepted source"):
        bridge.validated_predecessor()


def test_changed_authority_is_rejected(monkeypatch):
    actual = bridge.regular_bytes

    def altered(root, path, **kwargs):
        raw = actual(root, path, **kwargs)
        return raw + b" " if path == bridge.AUTHORITY_PATH else raw

    monkeypatch.setattr(bridge, "regular_bytes", altered)
    with pytest.raises(ValueError, match="successor authority digest"):
        bridge.validated_predecessor()


def test_changed_accepted_preimage_is_rejected(monkeypatch):
    record = deepcopy(bridge.authority())
    path = next(iter(record["changedFiles"]))
    record["changedFiles"][path]["beforeZlibBase64"] = "eA=="
    monkeypatch.setattr(bridge, "authority", lambda: record)
    with pytest.raises(ValueError, match="preimage|bounded complete"):
        bridge.validated_predecessor()


def test_accepted_git_tree_identity_rejects_byte_or_mode_change():
    source = bridge.validated_predecessor()
    assert bridge.git_tree_oid(source) == bridge.BASE_TREE
    path = next(iter(source))
    raw, mode = source[path]
    changed = dict(source)
    changed[path] = (raw + b" ", mode)
    assert bridge.git_tree_oid(changed) != bridge.BASE_TREE
    changed[path] = (raw, 0o755 if mode == 0o644 else 0o644)
    assert bridge.git_tree_oid(changed) != bridge.BASE_TREE


def test_new_file_mode_is_pinned(monkeypatch):
    record = deepcopy(bridge.authority())
    path = next(iter(record["newFiles"]))
    mode = record["newFiles"][path]["mode"]
    record["newFiles"][path]["mode"] = "100755" if mode == "100644" else "100644"
    monkeypatch.setattr(bridge, "authority", lambda: record)
    with pytest.raises(ValueError, match="accepted source mode"):
        bridge.validated_predecessor()


def test_bridge_cannot_self_authorize_as_new_file(monkeypatch):
    record = deepcopy(bridge.authority())
    record["newFiles"][bridge.BRIDGE_PATH] = bridge.digest(
        bridge.regular_bytes(bridge.ROOT, bridge.BRIDGE_PATH)
    )
    monkeypatch.setattr(bridge, "authority", lambda: record)
    with pytest.raises(ValueError, match="accepted file membership"):
        bridge.validated_predecessor()
