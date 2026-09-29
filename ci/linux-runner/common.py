"""Closed, standard-library-only inputs for an UNINSTALLED Linux candidate."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

VERSION = "1.2.0"
LAUNCHER = "/opt/planeon/bin/harness-offline-launch"
PYTHON = "/opt/planeon/python/3.12.14/bin/python3.12"
FIREJAIL = "/usr/bin/firejail"
TRUST = "/etc/planeon"
PACKET = "/opt/planeon/packet/active.yaml"
PROFILE = TRUST + "/linux-runner/firejail.profile"
MANIFEST = TRUST + "/harness-runner-manifest.json"
PUBLIC = TRUST + "/harness-runner-manifest.pub"
POLICY = TRUST + "/linux-runner/policy.json"
ANCHOR = TRUST + "/linux-runner/custody.json"
PREFLIGHT = TRUST + "/harness-runner-preflight.json"
HEX = re.compile(r"[0-9a-f]{64}\Z")
OFFLINE = {"UV_OFFLINE": "1", "UV_FROZEN": "1", "UV_NO_SYNC": "1"}
EXECUTION = {
    "wrapperArgv": ["./ci/verify-offline.sh"], "packetPathEnvironment": "HARNESS_TASK_PACKET",
    "packetPathMode": "HASH_PINNED_READ_ONCE_NO_CHILD_PATH", "commandTransport": "ARGV_ARRAY_V1",
    "isolation": "OS_ENFORCED_DENY_ALL_OUTBOUND", "sessionScope": "SINGLE_PROCESS_TREE",
    "prefetchOutsideSession": False, "offlineEnvironment": OFFLINE,
}
RUNNER = {"requiredLabels": ["self-hosted", "harness-engineering", "ephemeral", "credential-free"],
          "ephemeral": True, "ambientCloudCredentials": False, "sshAgent": False,
          "kubeconfig": False, "containerControlSockets": [], "billableBrokers": []}
ISOLATION = {"network": "OS_ENFORCED_DENY_ALL_OUTBOUND",
             "warmSourceRootEnvironment": "HARNESS_WARM_SOURCE_ROOTS",
             "warmSourceRootMode": "CANONICAL_EXHAUSTIVE_DENY_READ_METADATA_WRITE",
             "credentialHomeMode": "HIDDEN_OR_EMPTY", "localSocketMode": "CONTROL_AND_AGENT_SOCKETS_HIDDEN",
             "childPathMode": "WARM_ROOT_PATHS_SCRUBBED",
             "runnerManifestChildMode": "MANIFEST_KEY_SIGNATURE_AND_PREFLIGHT_HIDDEN"}
PROOFS = ("networkDenied", "warmReadDenied", "warmMetadataDenied", "warmWriteDenied",
          "packetWriteDenied", "credentialEnvironmentScrubbed", "brokerSocketsAbsent")


class Refused(ValueError):
    """Invalid authority or observed failed control: FAIL, never unavailable."""


class Unavailable(RuntimeError):
    """Missing host/backend/installation: NOT_RUN_ENV_UNAVAILABLE."""


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refused("nonfinite JSON")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Refused("invalid JSON") from exc


def closed(value, fields):
    require(type(value) is dict and set(value) == set(fields), "unknown or missing field")


def sha(value):
    require(type(value) is str and HEX.fullmatch(value) is not None, "invalid SHA-256")
    return value


def absolute(value):
    require(type(value) is str and re.fullmatch(r"/[A-Za-z0-9_./-]+", value) is not None,
            "unsafe absolute path")
    path = Path(value)
    require(str(path) == value and len(path.parts) >= 3 and all(p not in (".", "..") for p in path.parts),
            "noncanonical or broad path")
    return path


def disjoint(paths):
    values = [absolute(p) for p in paths]
    require(len(set(values)) == len(values), "duplicate roots")
    for index, left in enumerate(values):
        require(all(left not in right.parents and right not in left.parents for right in values[index + 1:]),
                "overlapping roots")


def identity(metadata):
    # atime is allowed to change merely because this verifier reads a file.
    return (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid,
            metadata.st_mode, metadata.st_nlink, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def trusted_entry(metadata):
    return (metadata.st_uid == metadata.st_gid == 0 and
            (stat.S_ISLNK(metadata.st_mode) or not metadata.st_mode & 0o022))


def root_read(value, *, mode=None, maximum=32 * 1024 * 1024, allow_hardlinks=False):
    """Open each parent via dirfd/O_NOFOLLOW; never follow a checked path again."""
    path = absolute(value)
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = next_fd
            metadata = os.fstat(directory)
            require(metadata.st_uid == metadata.st_gid == 0 and not metadata.st_mode & 0o022,
                    "writable or unowned trust parent")
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            metadata = os.fstat(fd)
            require(stat.S_ISREG(metadata.st_mode) and (allow_hardlinks or metadata.st_nlink == 1) and
                    metadata.st_uid == metadata.st_gid == 0 and not metadata.st_mode & 0o022,
                    "trust custody/type/link mismatch")
            require(mode is None or stat.S_IMODE(metadata.st_mode) == mode, "trust mode mismatch")
            require(metadata.st_size <= maximum, "oversized authority")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(maximum + 1)
            require(len(raw) <= maximum and identity(os.fstat(fd)) == identity(metadata), "authority changed while reading")
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def validate_manifest(m):
    closed(m, ("schemaVersion", "launcher", "runner", "isolation", "preflight", "signature"))
    require(m["schemaVersion"] == "harness.planeon.ai/trusted-runner-manifest/v1alpha1", "manifest version")
    closed(m["launcher"], ("path", "version", "sha256", "ownerUid", "ownerGid", "mode"))
    require(canonical(m["launcher"]) == canonical({"path": LAUNCHER, "version": VERSION,
            "sha256": sha(m["launcher"]["sha256"]), "ownerUid": 0, "ownerGid": 0, "mode": "0555"}), "launcher binding")
    require(canonical(m["runner"]) == canonical(RUNNER), "runner boundary")
    closed(m["isolation"], (*ISOLATION, "warmSourceRoots"))
    roots = m["isolation"]["warmSourceRoots"]
    require(type(roots) is list, "warm root array")
    disjoint(roots)
    require(canonical(m["isolation"]) == canonical({**ISOLATION, "warmSourceRoots": roots}), "isolation contract")
    closed(m["preflight"], ("suiteVersion", "status", "evidenceSha256", *PROOFS))
    require(m["preflight"]["suiteVersion"] == VERSION and m["preflight"]["status"] == "PASS"
            and all(m["preflight"][k] is True for k in PROOFS), "preflight incomplete")
    sha(m["preflight"]["evidenceSha256"])
    require(m["signature"] == {"algorithm": "ED25519", "signaturePath": MANIFEST + ".sig",
            "publicKeyPath": PUBLIC, "publicKeySha256": sha(m["signature"].get("publicKeySha256"))}, "signature contract")
    return roots


def packet_commands(raw):
    text = raw.decode("utf-8")
    def field(name):
        matches = [line[len(name) + 1:].strip() for line in text.splitlines() if line.startswith(name + ":")]
        require(len(matches) == 1, "missing or duplicate packet transport field")
        return parse(matches[0])
    require(canonical(field("offlineExecution")) == canonical(EXECUTION), "packet wrapper contract")
    phases = [field("prefetchCommands"), field("offlineAcceptanceCommands")]
    require(all(type(phase) is list for phase in phases) and phases[1], "empty/malformed phases")
    require(phases[0] in ([], [["make", "prefetch"]]), "prefetch command not admitted")
    for command in phases[0] + phases[1]:
        require(type(command) is list and command and all(type(v) is str and v and
                not any(c in v for c in "\x00\r\n") for v in command), "malformed argv")
        require(command[0] in ("make", "uv", "python", "python3", "npm"), "unapproved executable or shell")
        require(not any(v in ("-c", "--eval", "-e", "--command") for v in command), "command-string interpreter")
    for command in phases[1]:
        require(not set(map(str.lower, command)) & {"curl", "wget", "npx", "fetch", "download", "install", "sync", "add", "pull", "prefetch"}, "network argv")
        require(command[:2] != ["make", "verify-offline"], "recursive packet")
        if command[0] == "uv":
            require(command[1:5] == ["run", "--offline", "--frozen", "--no-sync"], "unlocked uv")
    return phases


def inventory(root, *, trusted=False, source=False, system=False):
    """Strict source/cache inventory; system aliases require the whole signed graph."""
    if system:
        require(trusted and not source, "system aliases require trusted system inventory")
        root = str(absolute(str(root)))
        return system_inventories([root])[root]
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), "inventory root missing or symlink")
    if trusted:
        require(trusted_entry(root.lstat()), "inventory root custody")
    entries = []

    def traversal_error(exc):
        raise Refused("inventory traversal incomplete") from exc

    for current, dirs, files in os.walk(root, followlinks=False, onerror=traversal_error):
        if source and Path(current) == root:
            # Git object transport is not source content. Actual HEAD is checked
            # with the pinned Git executable and all hooks/config disabled.
            dirs[:] = [name for name in dirs if name != ".git"]
            files[:] = [name for name in files if name != ".git"]
        for name in sorted(dirs + files):
            path = Path(current) / name
            m = path.lstat()
            if trusted:
                require(trusted_entry(m), "inventory custody")
            require(not stat.S_ISLNK(m.st_mode), "inventory symlink")
            if stat.S_ISDIR(m.st_mode):
                continue
            require(stat.S_ISREG(m.st_mode) and m.st_nlink == 1, "inventory special/hardlink")
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                require(identity(os.fstat(fd)) == identity(m), "inventory substitution")
                h = hashlib.sha256()
                while block := os.read(fd, 1024 * 1024):
                    h.update(block)
                require(identity(os.fstat(fd)) == identity(m), "inventory changed")
            finally:
                os.close(fd)
            entries.append({"path": str(path.relative_to(root)), "mode": f"{stat.S_IMODE(m.st_mode):04o}",
                            "size": m.st_size, "sha256": h.hexdigest()})
    return sorted(entries, key=lambda entry: entry["path"].encode())


def system_inventories(roots):
    """Inventory and resolve one closed union of root-owned system trees.

    The returned map is keyed by canonical absolute root. Every root's value is
    a deterministic list suitable for its separately signed inventory digest.
    A target may cross roots only through their verified real-dir ancestors;
    source and cache inventories never call this resolver.
    """
    require(type(roots) in (list, tuple) and bool(roots), "missing system roots")
    root_paths = [absolute(str(root)) for root in roots]
    disjoint([str(root) for root in root_paths])
    entries = {str(root): [] for root in root_paths}
    nodes = {}
    bridges = set()
    hardlinks = {}

    def traversal_error(exc):
        raise Refused("inventory traversal incomplete") from exc

    def observed(path, metadata):
        require(trusted_entry(metadata), "system inventory custody")
        nodes[str(path)] = (path, metadata, None)

    for root in root_paths:
        root_meta = root.lstat()
        require(stat.S_ISDIR(root_meta.st_mode), "system inventory root missing or symlink")
        for parent in root.parents:
            bridge_meta = parent.lstat()
            require(stat.S_ISDIR(bridge_meta.st_mode) and trusted_entry(bridge_meta),
                    "system bridge custody")
            bridges.add(str(parent))
        observed(root, root_meta)
        entries[str(root)].append({"kind": "directory", "path": "", "mode": f"{stat.S_IMODE(root_meta.st_mode):04o}"})
        for current, dirs, files in os.walk(root, followlinks=False, onerror=traversal_error):
            current_path = Path(current)
            current_meta = current_path.lstat()
            require(str(current_path) in nodes and stat.S_ISDIR(current_meta.st_mode)
                    and identity(current_meta) == identity(nodes[str(current_path)][1]),
                    "system directory changed")
            symlink_dirs = set()
            for name in sorted(dirs + files):
                path = current_path / name
                metadata = path.lstat()
                relative = str(path.relative_to(root))
                observed(path, metadata)
                if stat.S_ISLNK(metadata.st_mode):
                    require(metadata.st_nlink == 1, "system symlink hardlink")
                    target = os.readlink(path)
                    require(target and "\x00" not in target and len(os.fsencode(target)) <= 4096,
                            "unsafe system link target")
                    nodes[str(path)] = (path, metadata, target)
                    entries[str(root)].append({"kind": "symlink", "path": relative, "target": target})
                    if name in dirs:
                        symlink_dirs.add(name)
                    continue
                if stat.S_ISDIR(metadata.st_mode):
                    entries[str(root)].append({"kind": "directory", "path": relative,
                                               "mode": f"{stat.S_IMODE(metadata.st_mode):04o}"})
                    continue
                require(stat.S_ISREG(metadata.st_mode), "system inventory special file")
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    require(identity(os.fstat(fd)) == identity(metadata), "system inventory substitution")
                    h = hashlib.sha256()
                    while block := os.read(fd, 1024 * 1024):
                        h.update(block)
                    require(identity(os.fstat(fd)) == identity(metadata), "system inventory changed")
                finally:
                    os.close(fd)
                entry = {"kind": "file", "path": relative, "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                         "size": metadata.st_size, "sha256": h.hexdigest()}
                entries[str(root)].append(entry)
                hardlinks.setdefault((metadata.st_dev, metadata.st_ino), []).append((str(path), entry, metadata.st_nlink))
            dirs[:] = [name for name in dirs if name not in symlink_dirs]
            require(identity(current_path.lstat()) == identity(current_meta), "system directory changed during traversal")

    for members in hardlinks.values():
        paths = sorted((path for path, _, _ in members), key=str.encode)
        require(all(count == len(paths) for _, _, count in members), "incomplete system hardlink group")
        for _, entry, _ in members:
            entry["hardlinkGroup"] = paths

    # A bridge is only an ancestor of a signed tree, never a general /usr or
    # /etc namespace. Links may cross it to another signed tree, not end there.
    for bridge in bridges:
        metadata = Path(bridge).lstat()
        require(stat.S_ISDIR(metadata.st_mode) and trusted_entry(metadata), "system bridge changed")
        nodes[bridge] = (Path(bridge), metadata, None)

    def resolve(alias):
        pending = list(Path(alias).parts[1:])
        stack = []
        hops = 0
        while pending:
            part = pending.pop(0)
            if part in ("", "."):
                continue
            if part == "..":
                require(bool(stack), "system link escapes root")
                stack.pop()
                continue
            path = "/" + "/".join((*stack, part))
            require(path in nodes, "system link traverses uninventoried path")
            node_path, metadata, target = nodes[path]
            if stat.S_ISLNK(metadata.st_mode):
                hops += 1
                require(hops <= 40, "cyclic or excessive system link")
                require(identity(node_path.lstat()) == identity(metadata)
                        and os.readlink(node_path) == target, "system link changed")
                if target.startswith("/"):
                    stack = []
                pending = target.split("/") + pending
                continue
            require(stat.S_ISDIR(metadata.st_mode) or (stat.S_ISREG(metadata.st_mode) and not pending),
                    "system link traverses non-directory")
            stack.append(part)
        final = "/" + "/".join(stack)
        require(final in nodes and final not in bridges, "system link target not inventoried")
        final_path, final_meta, _ = nodes[final]
        require(identity(final_path.lstat()) == identity(final_meta), "system link target changed")
        return final

    for root, records in entries.items():
        for record in records:
            if record["kind"] == "symlink":
                record["resolvedPath"] = resolve(str(Path(root) / record["path"]))
    for path, (node_path, metadata, target) in nodes.items():
        require(identity(node_path.lstat()) == identity(metadata), "system inventory changed during resolution")
        if target is not None:
            require(os.readlink(node_path) == target, "system link changed during resolution")
    return {root: sorted(records, key=lambda record: record["path"].encode()) for root, records in entries.items()}


def input_roots(value):
    return sorted({t["root"] for t in value["tools"].values()} |
                  {c["root"] for c in value["caches"]} | {s["root"] for s in value["systemTrees"]})


def validate_inputs(value):
    closed(value, ("schemaVersion", "target", "tools", "caches", "systemTrees", "systemFiles", "source", "recipes"))
    require(value["schemaVersion"] == "planeon.linux-build-inputs/v3", "build input version")
    target = value["target"]
    closed(target, ("os", "architecture", "libc", "libcVersion", "execution", "imageDigest"))
    require(target["os"] == "linux" and target["architecture"] in ("amd64", "arm64") and
            target["libc"] in ("glibc", "musl") and target["execution"] == "NATIVE", "wrong build target")
    require(re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", target["libcVersion"]) is not None, "libc version")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", target["imageDigest"]) is not None, "mutable image")
    require(type(value["tools"]) is dict and {"python", "firejail", "git"} <= value["tools"].keys()
            <= {"python", "firejail", "git", "uv", "node", "npm", "make"}, "tool set")
    for name, tool in value["tools"].items():
        closed(tool, ("path", "version", "root", "inventorySha256"))
        path, root = absolute(tool["path"]), absolute(tool["root"])
        require(root in path.parents and type(tool["version"]) is str and bool(tool["version"]), "tool pin")
        sha(tool["inventorySha256"])
    require(value["tools"]["python"]["path"] == PYTHON and value["tools"]["python"]["version"] == "3.12.14"
            and value["tools"]["firejail"]["path"] == FIREJAIL, "fixed host tools")
    require(type(value["caches"]) is list and value["caches"], "missing cache inventories")
    for cache in value["caches"]:
        closed(cache, ("root", "inventorySha256", "os", "architecture", "libc", "tool"))
        absolute(cache["root"])
        sha(cache["inventorySha256"])
        require(cache["tool"] in value["tools"] and all(cache[k] == target[k] for k in ("os", "architecture", "libc")), "cache target mismatch")
    require(type(value["systemTrees"]) is list, "system closure missing")
    system_roots = []
    for item in value["systemTrees"]:
        closed(item, ("root", "inventorySha256"))
        require(item["root"] in ("/usr/bin", "/usr/lib", "/usr/lib64", "/usr/libexec", "/etc/firejail",
                                 "/etc/alternatives"), "unapproved system root")
        sha(item["inventorySha256"])
        system_roots.append(item["root"])
    require({"/usr/bin", "/usr/lib", "/etc/firejail"} <= set(system_roots)
            and len(set(system_roots)) == len(system_roots), "incomplete/duplicate system closure")
    require(value["tools"]["firejail"]["root"] == "/usr/bin", "firejail must use pinned system closure")
    require(value["tools"]["python"]["root"] == "/opt/planeon/python/3.12.14",
            "python root outside pinned installation")
    for name, tool in value["tools"].items():
        root = Path(tool["root"])
        require(tool["root"] in system_roots or
                (name != "python" and Path("/opt/planeon/tools") in root.parents) or
                (name == "python" and root == Path("/opt/planeon/python/3.12.14")),
                "tool root unavailable in private profile")
    for cache in value["caches"]:
        for system_root in system_roots:
            cache_root = Path(cache["root"])
            system_path = Path(system_root)
            require(cache_root != system_path and cache_root not in system_path.parents
                    and system_path not in cache_root.parents, "cache overlaps system closure")
        require(Path("/opt/planeon/cache") in Path(cache["root"]).parents,
                "cache root unavailable in private profile")
    closed(value["systemFiles"], ("/etc/ld.so.cache",))
    sha(value["systemFiles"]["/etc/ld.so.cache"])
    closed(value["source"], ("repository", "commit", "treeSha256"))
    require(re.fullmatch(r"caglarsubas/(?:harness-onion|mas-harness-[a-z-]+)", value["source"]["repository"]) is not None,
            "source is not an owned product")
    require(re.fullmatch(r"[0-9a-f]{40}", value["source"]["commit"]) is not None, "mutable source")
    sha(value["source"]["treeSha256"])
    require(value["recipes"] == {"packet": "SIGNED_PACKET_WRAPPER", "nextStandalone": "LINUX_TARGET_BUILD_ONLY",
                                 "downloads": "DENIED", "hostOutputReuse": "DENIED"}, "unapproved build recipe")
    roots = input_roots(value)
    # Multiple tools may live in one exhaustive inventory; distinct roots may not overlap.
    disjoint(sorted(set(roots)))
    return value
