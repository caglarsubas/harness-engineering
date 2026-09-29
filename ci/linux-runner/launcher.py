"""Root-custodied, unprivileged Linux launcher CANDIDATE; never installs itself."""
from __future__ import annotations

import os
import ctypes
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import time

from common import (ANCHOR, FIREJAIL, LAUNCHER, MANIFEST, OFFLINE, PACKET, POLICY,
                    PREFLIGHT, PROFILE, PUBLIC, PYTHON, Refused, Unavailable, absolute,
                    canonical, closed, digest, disjoint, input_roots, inventory, packet_commands, parse,
                    require, root_read, sha, system_inventories, validate_inputs, validate_manifest)
from ed25519 import pem_public, verify
import preflight

POLICY_DOMAIN = b"planeon.linux-runner-policy/v3\x00"
RUNNER_SIBLINGS = ("_temp", "_actions", "_tool", "_PipelineMapping")
SIBLING_SENTINEL = "_planeon-deny-sentinel"
PROTECTED_HOST_ROOTS = ("/etc/planeon", "/run", "/var/run", "/srv", "/root", "/home")
SRV_PRIVATE_ANCHOR = "/srv/planeon-runner-placeholder"
INTERNAL = ("--inside", "--probe-child")
AUTHORITY_FILES = {"anchor": ANCHOR, "public": PUBLIC, "policy": POLICY, "signature": POLICY + ".sig"}
NORMAL_AUTHORITY_FILES = {**AUTHORITY_FILES, "manifest": MANIFEST,
                          "manifestSignature": MANIFEST + ".sig", "preflight": PREFLIGHT}


def protect_process():
    # Also deny same-UID /proc/<pid>/mem and environ inspection of this trusted
    # supervisor. Seccomp ptrace/process_vm denial alone would not cover procfs.
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    require(prctl(4, 0, 0, 0, 0) == 0, "cannot disable process dumpability")
    require(all(not stat.S_ISSOCK(os.fstat(fd).st_mode) for fd in (0, 1, 2)), "inherited broker descriptor")


def validate_policy(policy, now):
    closed(policy, ("schemaVersion", "issuedAt", "expiresAt", "operatorUid", "operatorName",
                   "workspace", "runnerHome", "packetSha256", "warmContainer", "warmRoots",
                   "inputs", "profileSha256", "transportPins", "environment"))
    require(policy["schemaVersion"] == "planeon.linux-runner-policy/v3", "policy version")
    require(all(type(policy[k]) is int for k in ("issuedAt", "expiresAt", "operatorUid")), "policy integer")
    require(0 <= policy["issuedAt"] <= now < policy["expiresAt"] <= policy["issuedAt"] + 86400,
            "policy not current or TTL too long")
    require(policy["operatorUid"] > 0 and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", policy["operatorName"]) is not None,
            "operator identity")
    inputs = validate_inputs(policy["inputs"])
    repository = inputs["source"]["repository"].split("/", 1)[1]
    workspace = absolute(policy["workspace"])
    require(workspace == Path("/opt/planeon/work") / repository / repository,
            "workspace differs from pinned GitHub checkout layout")
    runner_home = absolute(policy["runnerHome"])
    require(runner_home.parent == Path("/srv/planeon"), "runner home outside custody")
    require(policy["warmContainer"] == "/srv/planeon/warm-snapshots" and type(policy["warmRoots"]) is list,
            "snapshot container")
    require(all(absolute(root).parent == Path(policy["warmContainer"]) for root in policy["warmRoots"]), "snapshot root placement")
    disjoint([str(workspace), str(runner_home), policy["warmContainer"]])
    disjoint(policy["warmRoots"])
    roots = input_roots(inputs)
    disjoint([str(workspace), str(runner_home), policy["warmContainer"], *roots])
    require(all(not (Path(root) == Path("/etc/planeon") or Path("/etc/planeon") in Path(root).parents
                    or Path(root) in Path("/etc/planeon").parents) for root in roots), "inventory overlaps trust")
    sha(policy["packetSha256"])
    sha(policy["profileSha256"])
    closed(policy["transportPins"], ("ci/verify-offline.sh", "ci/run_packet_argv.py", "ci/network_canary.py"))
    for value in policy["transportPins"].values():
        sha(value)
    # These values are pinned per product, never inherited from the CI agent.
    allowed_env = {"UV_PROJECT_ENVIRONMENT", "UV_CACHE_DIR", "VIRTUAL_ENV", "NPM_CONFIG_CACHE", "PLAYWRIGHT_BROWSERS_PATH"}
    require(type(policy["environment"]) is dict and set(policy["environment"]) <= allowed_env, "unknown tool environment")
    for value in policy["environment"].values():
        path = absolute(value)
        require(any(path == Path(root) or Path(root) in path.parents for root in roots), "unpinned environment path")
    return policy


def profile_bytes(policy):
    """The full profile is signed indirectly; no warm root appears in argv."""
    roots = input_roots(policy["inputs"])
    lines = ["# MET-LINUX-003 candidate v3; native preflight required", "quiet", "net none",
             "private", "private-tmp", "private-dev", "private-srv planeon-runner-placeholder",
             "caps.drop all", "nonewprivs",
             "nogroups", "restrict-namespaces", "seccomp-error-action EPERM", "seccomp.block-secondary",
             "seccomp socket,connect,sendto,sendmsg,sendmmsg,ptrace,process_vm_readv,process_vm_writev,pidfd_getfd,bpf,io_uring_setup,setns,unshare",
             "read-only " + PACKET, "blacklist /etc/planeon", "blacklist /run", "disable-mnt",
             "blacklist /var/run", "blacklist /root", "blacklist /home"]
    lines += ["blacklist " + str(Path("/opt/planeon/work") / name)
              for name in (*RUNNER_SIBLINGS, SIBLING_SENTINEL)]
    lines += ["read-only " + root for root in roots]
    lines += ["read-only /etc/ld.so.cache"]
    # Do not expose adjacent checkouts or runner credentials through the work parent.
    lines += ["whitelist " + value for value in [policy["workspace"], LAUNCHER, PACKET,
                                                 *[root for root in roots if root.startswith("/opt/")]]]
    return ("\n".join(lines) + "\n").encode()


def verify_signed(raw, signature, public, domain=b""):
    require(verify(public, domain + raw, signature), "Ed25519 signature refused")


def verify_host_manifest(raw, signature, evidence_raw, *, public, key, launcher_bytes, policy_raw, policy):
    verify_signed(raw, signature, public)
    manifest = parse(raw)
    roots = validate_manifest(manifest)
    require(roots == policy["warmRoots"] and manifest["launcher"]["sha256"] == digest(launcher_bytes)
            and manifest["signature"]["publicKeySha256"] == digest(key), "manifest custody differs")
    require(digest(evidence_raw) == manifest["preflight"]["evidenceSha256"], "installed preflight digest")
    evidence = parse(evidence_raw)
    closed(evidence, ("status", "scope", "networkCases", "hiddenPathCount", "descendantsChecked",
                      *preflight.PROOFS, "policySha256", "launcherSha256", "kernel", "architecture",
                      "observedAt", "nativeLinuxAcceptance"))
    closed(evidence["networkCases"], preflight.NETWORK_CASES)
    require(all(evidence["networkCases"][name] is True for name in preflight.NETWORK_CASES)
            and evidence["descendantsChecked"] is True and evidence["nativeLinuxAcceptance"] is False
            and type(evidence["hiddenPathCount"]) is int
            and evidence["hiddenPathCount"] == len(policy["warmRoots"]) + len(hidden_paths(policy)), "preflight case closure")
    require(evidence["status"] == "PASS" and evidence["scope"] == "HOST_ISOLATION_ONLY"
            and evidence["policySha256"] == digest(policy_raw) and evidence["launcherSha256"] == digest(launcher_bytes)
            and evidence["kernel"] == platform.release() and evidence["architecture"] == platform.machine()
            and type(evidence["observedAt"]) is int and 0 <= int(time.time()) - evidence["observedAt"] <= 3600
            and all(evidence[k] is True for k in preflight.PROOFS), "stale or mismatched installed preflight")


def verify_tools(inputs):
    target = inputs["target"]
    require(platform.system() == "Linux" and platform.machine() == {"amd64": "x86_64", "arm64": "aarch64"}[target["architecture"]], "host architecture mismatch")
    libc, version = platform.libc_ver()
    require((libc, version) == (target["libc"], target["libcVersion"]), "libc mismatch or unobservable libc")
    require(not os.path.lexists("/etc/ld.so.preload"), "global dynamic loader injection")
    for path, expected in inputs["systemFiles"].items():
        require(digest(root_read(path)) == expected, "system loader cache mismatch")
    system_roots = {spec["root"] for spec in inputs["systemTrees"]}
    roots = input_roots(inputs)
    for root in roots:
        # The graph verifier checks its nodes; also close custody of every
        # declared root and ancestor before opening any pinned tool or cache.
        directory = absolute(root)
        for parent in (directory, *directory.parents):
            m = parent.lstat()
            require(stat.S_ISDIR(m.st_mode) and m.st_uid == m.st_gid == 0 and not m.st_mode & 0o022,
                    "inventory root custody")
    system_entries = system_inventories(sorted(system_roots))
    seen = {root: digest(canonical(records)) for root, records in system_entries.items()}
    for spec in [*inputs["tools"].values(), *inputs["caches"], *inputs["systemTrees"]]:
        root = spec["root"]
        if root not in seen:
            seen[root] = digest(canonical(inventory(root, trusted=True)))
        require(seen[root] == spec["inventorySha256"], "tool/cache inventory mismatch")
    system_nodes = {str(Path(root) / entry["path"]): entry
                    for root, records in system_entries.items() for entry in records if entry["path"]}
    for name in sorted(set(inputs["tools"]) - {"npm"}):
        tool = inputs["tools"][name]
        path = tool["path"]
        if tool["root"] in system_roots:
            node = system_nodes.get(path)
            require(node is not None and node["kind"] in ("file", "symlink"), "selected system tool not inventoried")
            final = node["resolvedPath"] if node["kind"] == "symlink" else path
            final_node = system_nodes.get(final)
            require(final_node is not None and final_node["kind"] == "file", "selected system tool is not a file")
            raw = root_read(final, maximum=256 * 1024 * 1024, allow_hardlinks=True)
            require(digest(raw) == final_node["sha256"], "selected system tool changed")
        else:
            raw = root_read(path, maximum=256 * 1024 * 1024)
        validate_elf(raw, target["architecture"])


def validate_elf(raw, architecture):
    require(raw[:6] == b"\x7fELF\x02\x01" and len(raw) >= 20, "non-Linux native tool")
    require(int.from_bytes(raw[18:20], "little") == {"amd64": 62, "arm64": 183}[architecture], "ELF architecture mismatch")


def check_workspace_custody(policy, *, host_siblings=False):
    """Reject aliases and writable ancestors before checkout bytes are trusted."""
    uid = policy["operatorUid"]
    workspace = Path(policy["workspace"])
    owners = ((Path("/"), 0), (Path("/opt"), 0), (Path("/opt/planeon"), 0),
              (Path("/opt/planeon/work"), 0),
              (workspace.parent, uid if host_siblings else 0), (workspace, uid),
              (workspace / ".git", uid))
    if host_siblings:
        owners += ((Path("/srv"), 0), (Path("/srv/planeon"), 0),
                   (Path(policy["runnerHome"]), uid))
    for path, owner in owners:
        metadata = path.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == owner
                and not metadata.st_mode & 0o022, "workspace or runner custody")
        if owner == 0:
            require(metadata.st_gid == 0, "root workspace parent group")
    require(workspace.resolve(strict=True) == workspace, "checkout alias")
    if host_siblings:
        srv_anchor = Path(SRV_PRIVATE_ANCHOR).lstat()
        require(stat.S_ISREG(srv_anchor.st_mode) and srv_anchor.st_uid == srv_anchor.st_gid == 0
                and srv_anchor.st_nlink == 1 and srv_anchor.st_size == 0
                and stat.S_IMODE(srv_anchor.st_mode) == 0o444,
                "private-srv anchor custody")
        for value in PROTECTED_HOST_ROOTS:
            path = Path(value)
            metadata = path.lstat()
            require((stat.S_ISDIR(metadata.st_mode) or
                     (value == "/var/run" and stat.S_ISLNK(metadata.st_mode)))
                    and metadata.st_uid == metadata.st_gid == 0
                    and (stat.S_ISLNK(metadata.st_mode) or not metadata.st_mode & 0o022),
                    "protected host root not observed under root custody")
        for name in RUNNER_SIBLINGS:
            metadata = (Path("/opt/planeon/work") / name).lstat()
            require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == uid
                    and not metadata.st_mode & 0o022, "runner sibling sentinel custody")
        sentinel = Path("/opt/planeon/work") / SIBLING_SENTINEL
        metadata = sentinel.lstat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == metadata.st_gid == 0
                and metadata.st_nlink == 1 and stat.S_IMODE(metadata.st_mode) == 0o444,
                "root sibling sentinel custody")


def work_mount_alias_present(mountinfo):
    work = Path("/opt/planeon/work")
    for line in mountinfo.splitlines():
        fields = line.split(" - ", 1)[0].split()
        require(len(fields) >= 5, "malformed mount inventory")
        path = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), fields[4])
        require(path.startswith("/") and "\\" not in path, "malformed mount point")
        mount = Path(path)
        if mount in (Path("/opt"), Path("/opt/planeon"), work) or work in mount.parents:
            return True
    return False


def check_no_work_mount_aliases():
    require(not work_mount_alias_present(Path("/proc/self/mountinfo").read_text()),
            "work checkout contains mounted alias")


def load_authority(*, bootstrap_preflight=False):
    if platform.system() != "Linux":
        raise Unavailable("NON_LINUX_HOST")
    require(os.getuid() == os.geteuid() != 0, "launcher must use unprivileged real identity")
    require(Path(sys.argv[0]) == Path(LAUNCHER), "candidate is not the fixed installed launcher")
    try:
        anchor = parse(root_read(ANCHOR))
    except FileNotFoundError as exc:
        raise Unavailable("SIGNED_LINUX_INSTALLATION_ABSENT") from exc
    closed(anchor, ("schemaVersion", "publicKeySha256", "launcherSha256", "policySha256"))
    require(anchor["schemaVersion"] == "planeon.linux-runner-custody/v1", "custody version")
    launcher = root_read(LAUNCHER, mode=0o555)
    key = root_read(PUBLIC)
    policy_raw = root_read(POLICY)
    require(digest(launcher) == sha(anchor["launcherSha256"]) and digest(key) == sha(anchor["publicKeySha256"])
            and digest(policy_raw) == sha(anchor["policySha256"]), "custody pin mismatch")
    public = pem_public(key)
    verify_signed(policy_raw, root_read(POLICY + ".sig"), public, POLICY_DOMAIN)
    policy = validate_policy(parse(policy_raw), int(time.time()))
    require(os.getuid() == policy["operatorUid"], "wrong runner UID")
    require(profile_bytes(policy) == root_read(PROFILE) and digest(root_read(PROFILE)) == policy["profileSha256"], "profile tamper")
    packet = root_read(PACKET)
    require(digest(packet) == policy["packetSha256"], "packet tamper")
    packet_commands(packet)
    if not bootstrap_preflight:
        verify_host_manifest(root_read(MANIFEST), root_read(MANIFEST + ".sig"), root_read(PREFLIGHT),
                             public=public, key=key, launcher_bytes=launcher, policy_raw=policy_raw, policy=policy)
    expected_roots = "\n".join(policy["warmRoots"]) or "NONE"
    require(os.environ.get("HARNESS_WARM_SOURCE_ROOTS") == expected_roots, "warm setting differs")
    container = Path(policy["warmContainer"])
    require(container.resolve(strict=True) == container and container.stat().st_uid == 0
            and not container.stat().st_mode & 0o022, "snapshot container custody")
    # Only immediate metadata is inspected. No checkout or snapshot file is opened.
    detected = []
    for entry in container.iterdir():
        m = entry.lstat()
        require(stat.S_ISDIR(m.st_mode), "unknown snapshot entry")
        detected.append(str(entry))
    require(sorted(detected) == sorted(policy["warmRoots"]), "undeclared/missing warm snapshot")
    workspace = Path(policy["workspace"])
    check_workspace_custody(policy, host_siblings=True)
    check_no_work_mount_aliases()
    require(os.environ.get("GITHUB_WORKSPACE") == str(workspace)
            and os.environ.get("GITHUB_SHA") == policy["inputs"]["source"]["commit"]
            and os.environ.get("GITHUB_REPOSITORY") == policy["inputs"]["source"]["repository"], "checkout context not signed")
    if not Path(FIREJAIL).is_file():
        raise Unavailable("FIREJAIL_ABSENT")
    if not Path(FIREJAIL).stat().st_mode & stat.S_ISUID:
        raise Unavailable("FIREJAIL_PRIVILEGE_BACKEND_ABSENT")
    if not all(Path("/proc/self/ns/" + name).exists() for name in ("net", "mnt", "pid")):
        raise Unavailable("KERNEL_NAMESPACES_ABSENT")
    verify_tools(policy["inputs"])
    return policy, digest(policy_raw), digest(launcher)


def environment(policy):
    # No ambient environment is forwarded, including LD_*, PYTHON*, provider
    # keys, CI runner tokens, agent sockets or arbitrary HARNESS_* markers.
    paths = sorted({str(Path(t["path"]).parent) for t in policy["inputs"]["tools"].values()})
    return {"PATH": ":".join(paths), "HOME": "/tmp", "TMPDIR": "/tmp",
            "USER": policy["operatorName"], "LOGNAME": policy["operatorName"],
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
            "UV_PYTHON_DOWNLOADS": "never", "NEXT_TELEMETRY_DISABLED": "1",
            "NPM_CONFIG_OFFLINE": "true", "NPM_CONFIG_AUDIT": "false", "NPM_CONFIG_FUND": "false",
            "NPM_CONFIG_UPDATE_NOTIFIER": "false", **OFFLINE}


def supervise(argv, *, env, cwd, payload, timeout, pass_fds=()):
    """Bound the entire namespace lifetime; close ambient FDs and kill descendants."""
    child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE,
                             close_fds=True, pass_fds=pass_fds, start_new_session=True)
    try:
        child.communicate(input=payload, timeout=timeout)
        return child.returncode
    except subprocess.TimeoutExpired as exc:
        raise Refused("isolation session deadline exceeded") from exc
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()


def internal_authority(context):
    """A pipe payload is not authority: reverify retained root-custodied FDs."""
    require(type(context["preflightOnly"]) is bool, "ambiguous internal operation")
    files = AUTHORITY_FILES if context["preflightOnly"] else NORMAL_AUTHORITY_FILES
    closed(context["authorityDescriptors"], files)
    raw = {}
    try:
        for name, path in files.items():
            fd = context["authorityDescriptors"][name]
            require(type(fd) is int and fd > 2 and os.readlink(f"/proc/self/fd/{fd}") == path, "wrong authority descriptor")
            m = os.fstat(fd)
            require(stat.S_ISREG(m.st_mode) and m.st_uid == m.st_gid == 0 and m.st_nlink == 1
                    and not m.st_mode & 0o022 and m.st_size <= 8 * 1024 * 1024, "descriptor custody")
            os.lseek(fd, 0, os.SEEK_SET)
            raw[name] = os.read(fd, 8 * 1024 * 1024 + 1)
            require(len(raw[name]) == m.st_size, "descriptor changed")
    finally:
        for fd in set(context["authorityDescriptors"].values()):
            if type(fd) is int and fd > 2:
                os.close(fd)
    anchor = parse(raw["anchor"])
    closed(anchor, ("schemaVersion", "publicKeySha256", "launcherSha256", "policySha256"))
    require(anchor["schemaVersion"] == "planeon.linux-runner-custody/v1"
            and digest(raw["public"]) == anchor["publicKeySha256"] and digest(raw["policy"]) == anchor["policySha256"]
            and digest(root_read(LAUNCHER, mode=0o555)) == anchor["launcherSha256"], "internal custody mismatch")
    verify_signed(raw["policy"], raw["signature"], pem_public(raw["public"]), POLICY_DOMAIN)
    policy = validate_policy(parse(raw["policy"]), int(time.time()))
    if not context["preflightOnly"]:
        verify_host_manifest(raw["manifest"], raw["manifestSignature"], raw["preflight"],
                             public=pem_public(raw["public"]), key=raw["public"],
                             launcher_bytes=root_read(LAUNCHER, mode=0o555), policy_raw=raw["policy"], policy=policy)
    require(canonical(policy) == canonical(context["policy"]) and context["policySha256"] == digest(raw["policy"])
            and context["launcherSha256"] == anchor["launcherSha256"] and context["roots"] == policy["warmRoots"]
            and context["hiddenPaths"] == hidden_paths(policy) and context["launcher"] == LAUNCHER,
            "unsigned internal policy substitution")
    return policy


def hidden_paths(policy):
    return [MANIFEST, MANIFEST + ".sig", PUBLIC, PREFLIGHT, POLICY, PROFILE, ANCHOR,
            "/etc/planeon/linux-runner", "/srv/planeon",
            "/home/runner", "/root/.ssh",
            policy["runnerHome"], policy["runnerHome"] + "/.credentials",
            policy["warmContainer"], "/run/docker.sock", "/run/containerd/containerd.sock",
            *[str(Path("/opt/planeon/work") / name) for name in (*RUNNER_SIBLINGS, SIBLING_SENTINEL)]]


def inside(context):
    require(platform.system() == "Linux", "internal mode requires Linux")
    protect_process()
    policy = internal_authority(context)
    require(os.getuid() == os.geteuid() == policy["operatorUid"], "internal identity mismatch")
    result = preflight.run(context)
    result.update({"policySha256": context["policySha256"], "launcherSha256": context["launcherSha256"],
                   "kernel": platform.release(), "architecture": platform.machine(), "observedAt": int(time.time()),
                   "nativeLinuxAcceptance": False})
    require(digest(Path(PACKET).read_bytes()) == policy["packetSha256"], "packet changed before wrapper")
    if context["preflightOnly"]:
        print(canonical(result).decode(), flush=True)
        return 0
    verify_tools(policy["inputs"])
    packet_commands(Path(PACKET).read_bytes())
    workspace = Path(policy["workspace"])
    check_workspace_custody(policy)
    source = policy["inputs"]["source"]
    require(digest(canonical(inventory(workspace, source=True))) == source["treeSha256"], "source tree mismatch")
    for name, expected in policy["transportPins"].items():
        require(digest((workspace / name).read_bytes()) == expected, "packet transport changed")
    git = policy["inputs"]["tools"]["git"]["path"]
    git_env = {**environment(policy), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
               "GIT_NO_REPLACE_OBJECTS": "1"}
    for args, expected in ((["rev-parse", "--verify", "HEAD"], source["commit"]),
                           (["rev-parse", "--show-toplevel"], str(workspace)),
                           (["rev-parse", "--absolute-git-dir"], str(workspace / ".git"))):
        check = subprocess.run([git, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *args],
                               env=git_env, cwd=workspace, capture_output=True, text=True, timeout=20, close_fds=True)
        require(check.returncode == 0 and check.stdout.strip() == expected, "checkout Git identity differs")
    env = {**environment(policy), **policy["environment"], "HARNESS_TASK_PACKET": PACKET,
           "GITHUB_WORKSPACE": str(workspace), "GITHUB_SHA": source["commit"], "GITHUB_REPOSITORY": source["repository"],
           "HARNESS_OFFLINE_ENFORCED": "1", "HARNESS_OFFLINE_BACKEND": "linux-firejail",
           "HARNESS_OFFLINE_SESSION_ID": "linux-" + str(os.getpid()), "CI": "true", "GITHUB_ACTIONS": "true"}
    # The exact digest-pinned ARGV_ARRAY_V1 wrapper owns the command-by-command
    # packet recheck and child allowlist. Prefetch and acceptance share this tree.
    code = subprocess.run(["./ci/verify-offline.sh"], cwd=workspace, env=env, stdin=subprocess.DEVNULL,
                          close_fds=True, timeout=max(1, min(900, policy["expiresAt"] - int(time.time())))).returncode
    require(digest(Path(PACKET).read_bytes()) == policy["packetSha256"], "packet changed after wrapper")
    return code


def main():
    try:
        args = sys.argv[1:]
        require(args in ([], ["--operator-preflight"], ["--inside"], ["--probe-child"]), "unsupported launcher arguments")
        if args and args[0] in INTERNAL:
            # This route cannot create isolation, gain privileges or claim a
            # signature. Kernel/namespace/file negatives are re-proven first.
            context = parse(sys.stdin.buffer.read(8 * 1024 * 1024))
            if args == ["--probe-child"]:
                preflight.run(context, descendants=False)
                print("CHILD_NEGATIVES_PASS")
                return 0
            return inside(context)
        only = args == ["--operator-preflight"]
        if platform.system() == "Linux":
            protect_process()
        policy, policy_sha, launcher_sha = load_authority(bootstrap_preflight=only)
        context = {"policy": policy, "policySha256": policy_sha, "launcherSha256": launcher_sha,
                   "roots": policy["warmRoots"], "hiddenPaths": hidden_paths(policy),
                   "parentNamespaces": {n: os.readlink("/proc/self/ns/" + n) for n in ("net", "mnt", "pid")},
                   "launcher": LAUNCHER, "preflightOnly": only}
        descriptors = {}
        try:
            for name, path in (AUTHORITY_FILES if only else NORMAL_AUTHORITY_FILES).items():
                descriptors[name] = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            context["authorityDescriptors"] = descriptors
            code = supervise([FIREJAIL, "--keep-fd=" + ",".join(str(fd) for fd in descriptors.values()),
                              "--profile=" + PROFILE, "--", PYTHON, "-IB", LAUNCHER, "--inside"],
                             env=environment(policy), cwd=policy["workspace"], payload=canonical(context),
                             timeout=max(1, min(900, policy["expiresAt"] - int(time.time()))), pass_fds=tuple(descriptors.values()))
        finally:
            for fd in descriptors.values():
                os.close(fd)
        require(digest(root_read(POLICY)) == policy_sha and digest(root_read(PACKET)) == policy["packetSha256"], "authority changed during session")
        return code
    except Unavailable as exc:
        print(canonical({"status": "NOT_RUN_ENV_UNAVAILABLE", "reason": str(exc), "nativeLinuxAcceptance": False}).decode())
        return 77
    except (Refused, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        # Do not echo rejected secrets, paths, argv, or hostile file contents.
        print(canonical({"status": "FAIL", "reason": type(exc).__name__, "nativeLinuxAcceptance": False}).decode())
        return 2
