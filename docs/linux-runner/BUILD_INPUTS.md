# Closed Linux build inputs — MET-LINUX-004 candidate

This specification is local operator-kit configuration, not a tenant wire API
or a change to `schemas/trusted-runner-manifest.schema.json`. The executable
closed validators are `common.validate_inputs` and `launcher.validate_policy`.
Unknown fields, duplicate JSON names, nonfinite values and unsafe paths fail.
All digests below are exact-byte lowercase SHA-256, without a prefix unless
explicitly stated. No sample digest in a unit test is operational authority.

## Build-input object

Exactly `schemaVersion`, `target`, `tools`, `caches`, `systemTrees`,
`systemFiles`, `source`, `recipes`:

- `schemaVersion`: `planeon.linux-build-inputs/v3`. V1/V2 signatures and
  inventories are not compatible with this source candidate.
- `target`: exactly `os=linux`, `architecture=amd64|arm64`,
  `libc=glibc|musl`, numeric dotted `libcVersion`, `execution=NATIVE`,
  and `imageDigest=sha256:<64 hex>` for the operator's existing immutable host
  image. Runtime verifies the observable libc; an unobservable musl version
  cannot pass. Other libc targets require reviewed detection, not a guessed label.
- `tools`: a closed named map containing python, firejail and git, optionally
  uv, node, npm and make. Each record has exactly `path`, `version`, `root`,
  `inventorySha256`. Python is exactly 3.12.14 at
  `/opt/planeon/python/3.12.14/bin/python3.12`; Firejail is `/usr/bin/firejail`.
  Every required tool for the actual packet must be present. Missing executables
  fail; there is no PATH search outside the supplied locked tool directories.
  Python's root is exactly `/opt/planeon/python/3.12.14`; non-system other
  tool roots are direct or deeper children of `/opt/planeon/tools`. Tools in
  `/srv`, `/run`, `/home` or another hidden/private tree are refused.
- `caches`: nonempty records with exactly `root`, `inventorySha256`, `os`,
  `architecture`, `libc`, `tool`; target fields must match `target`, and `tool`
  must name a supplied pinned tool. No mutable or absent cache is admitted.
  Cache roots must be below `/opt/planeon/cache`, where the exact signed
  profile can whitelist them without exposing runner siblings.
- `systemTrees`: unique `root`/`inventorySha256` records covering at least
  `/usr/bin`, `/usr/lib` and `/etc/firejail`, optionally `/usr/lib64`,
  `/usr/libexec` and `/etc/alternatives`.
  Firejail must use the `/usr/bin` system root. This prevents an unreviewed
  broad `/usr` tool root from admitting aliases outside the declared closure.
  Pin all helper/native-library/configuration closures for the selected immutable
  host image. The same exhaustive ownership/inventory rules apply.
- `systemFiles`: exactly `/etc/ld.so.cache` and its byte digest. Global
  `/etc/ld.so.preload` is forbidden. This initial closure requires an observable
  glibc-compatible loader cache; unsupported musl layouts cannot qualify by
  borrowing glibc evidence.
- `source`: exactly `repository`, `commit`, `treeSha256`. Repository is the
  owned harness-onion or mas-harness-* family; a warm repository is forbidden.
  Commit is 40 lowercase hex characters, not a branch or tag. Tree digest covers
  `common.inventory(workspace, source=True)`. Only root `.git` transport metadata
  is excluded; hidden/untracked files and old build outputs are NOT excluded.
  The pinned Git executable separately verifies actual HEAD inside isolation.
- `recipes`: exactly `packet=SIGNED_PACKET_WRAPPER`,
  `nextStandalone=LINUX_TARGET_BUILD_ONLY`, `downloads=DENIED`,
  `hostOutputReuse=DENIED`. Build argv come only from the signed packet, not an
  arbitrary recipe string or imported script.

An inventory is a UTF-8-bytewise path-sorted JSON array. Source, cache and
dedicated-tool inventories retain the strict V1 file entry encoding (`path`,
`mode`, `size`, `sha256`) and reject every symlink and hardlink. Only declared
root-owned `systemTrees` use a V3 union graph. Directory entries record
`kind=directory`, `path` and `mode`; regular files add `kind=file`, size,
digest and a complete absolute-path `hardlinkGroup` across the union. Symlinks
record `kind=symlink`, exact raw `target` and graph-resolved absolute
`resolvedPath`. Every observed hardlink count must equal the complete signed
union group. The verifier inventories every real tree without following links,
then resolves every alias component-by-component through inventoried real nodes
and root-owned, non-writable bridge ancestors. Relative and absolute file or
directory targets may cross only between explicitly declared trees, such as
`/usr/bin` → `/etc/alternatives` → `/usr/bin`. Missing, untrusted, mutable,
escaping, cyclic or special-file paths fail; an alias must end at an inventoried
regular file or real directory. Root-level aliases used as inventory roots,
such as `/lib` → `/usr/lib`, are not admitted without a separate signed
root-alias contract. Source/cache/dedicated-tool aliases remain forbidden.
This permits a reviewed closure, not arbitrary distribution adoption. The
operator must still pin the target image, all closure bytes and fresh host
negative evidence; a stock Linux image is not assumed to qualify.
Canonical inventory encoding uses ASCII-escaped JSON, sorted object keys,
comma/colon separators and no trailing newline. Hash that encoding.

Distinct tool/cache roots may not overlap each other, the workspace, runner
home, trust or warm container. Tools sharing one root must have the same
exhaustive inventory digest. System helper/configuration/library trees and
loader-cache bytes are verified too; ELF headers alone do not establish closure.
The candidate does not parse ELF `PT_INTERP`, `DT_NEEDED`, RPATH/RUNPATH or
dynamic loader search results, and it cannot independently attest the booted
host image against `imageDigest`. Before installation or listener registration,
the external operator must derive and review the actual transitive loader and
helper closure for the exact immutable Linux image, include every used path in
the signed inventories, and independently verify the image identity. A signed
configuration value or source-only test is not that evidence. An undeclared
dependency or unobservable image identity blocks native qualification.

## Signed execution policy

Exactly these fields:

| Field | Constraint |
| --- | --- |
| schemaVersion | planeon.linux-runner-policy/v3 |
| issuedAt / expiresAt | Integer epoch seconds; current, ordered, maximum 24 hours |
| operatorUid / operatorName | Dedicated non-root numeric UID and safe local name |
| workspace | Exactly /opt/planeon/work/REPO/REPO, with REPO derived from the already validated signed source repository; no arbitrary extra depth |
| runnerHome | One canonical direct child of /srv/planeon, disjoint from work/sources |
| packetSha256 | Exact fixed /opt/planeon/packet/active.yaml bytes |
| warmContainer | /srv/planeon/warm-snapshots, root-owned and non-writable by runner |
| warmRoots | Complete unique direct-child directories of warmContainer; empty allowed only when container is empty |
| inputs | Closed build-input object above |
| profileSha256 | Exact deterministic Firejail profile bytes |
| transportPins | Exactly ci/verify-offline.sh, ci/run_packet_argv.py, ci/network_canary.py and their reviewed digests |
| environment | Only pinned UV_PROJECT_ENVIRONMENT, UV_CACHE_DIR, VIRTUAL_ENV, NPM_CONFIG_CACHE, PLAYWRIGHT_BROWSERS_PATH references |

The operator request to `prepare.py` contains all these fields except
`profileSha256`, which is computed. The renderer emits only unsigned candidate
data in a new caller-owned private directory. It neither reads warm contents
nor signs, installs, downloads, builds an image, contacts a registry or executes
a packet.

Detached raw 64-byte Ed25519 policy signature covers:
`UTF8("planeon.linux-runner-policy/v3\u0000") || exact policy.json bytes`.
No RFC 8785 claim is made for this private byte-signed format. Manifest signing
is unchanged: detached Ed25519 over exact manifest bytes. Public key is strict
Ed25519 SPKI PEM, pinned by exact PEM-byte SHA-256 in root image custody.
The changed launcher version/profile, input schema and signature domain require
a fresh signed policy, manifest and host preflight. No V1/V2 PASS transfers.

## Native product recipes and evidence

Before a Linux-target product build the external operator supplies a clean
source tree, native ELF Python/Node/Git and architecture/libc-specific local
wheel/npm/browser caches. Python, Firejail and Git ELF machine IDs are checked
before execution; the whole inventories bind other native dependencies too.
No Darwin `.next/standalone`, `node_modules`, virtualenv, wheel, Mach-O or MLX
output is reusable as a Linux release input. Create standalone Next.js output
inside that Linux target using the existing packet's frozen offline build argv.

The kit does not provision or directly build containers. Product image/SBOM,
build-log, source-lock, base-image, recipe and cache digests must later be bound
by CONF-LINUX-001's independent evidence. Merely putting an image digest or
NATIVE string in this configuration does not qualify a release or prove physical
hardware. Native AMD64 and native ARM64 need separate external observation.
