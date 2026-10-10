# Backend distribution selection — W03-0 (DATA_CHECK_ONLY)

Status: **CONTRACT_CANDIDATE_ROUND4_AWAITING_INDEPENDENT_REVIEW**. Rounds 1 to 3 (`review-round1.json` to `review-round3.json`, bytes in `round1/` to `round3/`) returned CHANGES_REQUIRED, and every finding is answered below. The branch was rebased onto main `195c4c9` (packet 220) after round 3; the earlier rounds' subject commits are the pre-rebase ones their records name, and their bytes are kept in the round directories. DATA_CHECK_ONLY: nothing is installed or executed, no
I06 evidence record exists, and E01-E12 stay OPEN_UNPROVEN.

W01 §2.1 leaves the concrete Kubernetes backend for `SEALED_SINGLE_NODE_CONTROL_PLANE_V1` to W03, "under license and
offline closure". W02g (I06 v1 and v2) fixed what that backend must satisfy: the criteria SC00-SC15, the closure CL, the
snapshot checks IC01-IC05 and the operational rules OR01-OR08, all at Kubernetes v1.37.1 (commit `f78e7223`). This
directory selects the concrete component set and shows, row by row, how it meets those criteria. It is the input W04
(independent tests) and W02a-F2 and W02g-F2 (the production backend profile) start from.

## Owner decisions (2026-10-10, via the lane monitor)

| ID | Decision |
|---|---|
| Q4 | An upstream component set configured only from sealed files, with no installer at runtime. The parts: official v1.37.1 kube-apiserver, kube-controller-manager, kube-scheduler, kubelet and kube-proxy (nftables mode); etcd on a unix socket; containerd 2.x with runc and the cgroupfs driver; the CNI plugins bridge, host-local and loopback; kube-network-policies (nftables); no CoreDNS. Every part is digest-pinned. |
| Q-L | L-a: keep the official upstream binaries, pinned. The license policy gains a reviewed class for host-OS and statically linked system libraries, with exact entries: glibc LGPL-2.1-or-later, libseccomp LGPL-2.1-only, libpathrs "MPL-2.0 OR LGPL-3.0-or-later" electing MPL-2.0, and nft GPL-2.0-only as a separately executed host program. Source offers come from the pinned tags (D-POLICY-AMEND, its own packet). |
| Q-L2 | L2-a: the LIC-HOST amendment also adds an OR-choice rule (an "A OR B" expression with an allowed alternative is accepted, electing it, with the election recorded per component) and exact entries for GPL-3.0-or-later WITH GCC-exception-3.1 and the nft library closure in the host-OS class; gmp elects LGPL-3.0-or-later. |
| Q-L3 | L3-a: LIC-HOST also adds an AND-term rule (a compound is accepted when every AND term is allowed, an allowed exception, reviewed or OR-resolved) and reads legacy "A/B" crate strings as "A OR B", with the normalisation recorded. The build-time license gate and SBOM produce the full crate list and elections (HE-001, HE-008). |
| Q-E | E-a: etcd v3.7.2, the line Kubernetes v1.37.1 builds and tests against. |
| Q-N | N-a: build kube-network-policies' standard command from tag v1.1.2 (`a145b01c`) with a pinned Go toolchain, static and with CGO off, in the host-image packet. |

## Files

| File | Content |
|---|---|
| `selection.json` | `planeon.internal.backend-distribution-selection/v1`. It holds: one component per W02g backend role, its upstream parts (repository, tag, commit, SPDX license) and their per-architecture artifacts with the upstream's published SHA-256; the sandbox image; one row per I06 v2 criterion; the excluded candidates; the license reviews; the I05 re-check; the open items |
| `../../scripts/backend_distribution.py` | reference check: closed schema, every I06 v2 criterion exactly once in criteria order, every required role, Kubernetes parts at the baseline commit, licenses within the policy's default-allowed list (other licenses only through a listed review), both architectures, and the I05 re-check bound to the mapping's own upstream pin |

## The component set

| W02g role | Selected part(s) | Pin |
|---|---|---|
| APISERVER | kube-apiserver v1.37.1 | official release binary, `.sha256` on dl.k8s.io |
| CONTROLLER_MANAGER | kube-controller-manager v1.37.1 | the same |
| SCHEDULER | kube-scheduler v1.37.1 | the same |
| KUBELET | kubelet v1.37.1 | the same |
| SERVICE_PROXY | kube-proxy v1.37.1, nftables mode | the same |
| DATASTORE | etcd v3.7.2 (`68c065e5`) | release archive, `SHA256SUMS`; only `etcd` is installed |
| CONTAINER_RUNTIME | containerd v2.4.1 static (`f2551031`), runc v1.5.2 (`29dd3dc2`), CNI plugins v1.9.1 (`adc3e6b5`) | release archives and binaries with their checksum files; containerd's `ctr` and `containerd-stress` and every CNI plugin except bridge, host-local and loopback are left out |
| NETWORK_POLICY_AGENT | kube-network-policies v1.1.2 (`a145b01c`), `standard` command | built from the tag (no release binaries) |

The sandbox image is `registry.k8s.io/pause:3.10.2`, pinned by index digest. That is containerd 2.4.1's default and
Kubernetes v1.37.1's pause version. Every upstream project is Apache-2.0; the release binaries' static libraries are
listed under "License closure".

Version notes:
- containerd 2.4 is listed for Kubernetes 1.37 in containerd's support matrix (2.4.0+ and 2.3.0+, CRI v1).
- Kubernetes v1.37.1 builds and tests against etcd 3.7.0 (`build/dependencies.yaml:66-67`); etcd 3.7.2 is that line's
  newest patch, and runc 1.5.2 is the newest of its line.

Sealed process facts:
- containerd: the gRPC socket `/run/qualification-k8s/containerd.sock` and its `.ttrpc` companion, NRI disabled, the
  debug socket unset.
- kube-network-policies: `--fail-open=false`, `--disable-nri`, metrics on loopback.
- kube-proxy and the other components: healthz, metrics and secure ports on loopback.
- The shim daemonizes away from containerd; runc and the containers run under the shim. kube-proxy executes the host's
  `nft` (1.0.1 or later), recorded as a host dependency.

## How the criteria are met

Each row of `selection.json` names its dispositions:
- `SELECTION`: holds because of the chosen artifacts.
- `SEALED_CONFIGURATION`: holds through the W03 sealed file set. The target values are those of the I06 v2 positive
  evidence vector.
- `OBSERVER`: a runtime observer check.
- `W02A_RECORD`: needs the production W02a record.
- `OPERATIONAL`: a rule of operation.

The rows say what the setting is and which part supports it.

Two rows cannot be met by this selection alone:
- **SC00 (D-W02A-F2).** I06 v2 evidence binds a W02a v3 record by digest, and no production W02a backend profile exists.
  W02a-F2 adds it, naming these components with their canonical paths, confined types and verity digests, and W02g-F2 binds
  an I06 successor to it.
- **SC01 (D-SC01-PEER).** etcd v3.7.2 cannot run without a peer listener. An empty `--listen-peer-urls` is accepted as
  the flag's empty-string exception and silently keeps the default TCP `localhost:2380` (`server/embed/config.go:87`,
  `:608-609`; `pkg/flags/unique_urls.go`). The peer listener passes only the URL's host to the listener
  (`server/embed/etcd.go:576`), so the one AF_UNIX peer socket is `unix://<name>[:<port>]`, relative to etcd's working
  directory (the datastore's private directory). At v3.7.2 `checkHostURLs` skips unix schemes (`config.go:1340-1344`), so
  the advertise URLs may be unix URLs too. I06 v1 and v2 refuse anything but `peerListen == []`, so W02g-F2 accepts exactly
  one AF_UNIX peer listener and no TCP listener, and native evidence shows no TCP listener.

## License closure

Every upstream project is Apache-2.0, but the release binaries and kube-proxy's host program carry more. Owner decisions
Q-L (L-a) and Q-L2 (L2-a) approve these, through the LIC-HOST amendment:

| Review | Expression | Elects | Where |
|---|---|---|---|
| D-LIC-GLIBC | LGPL-2.1-or-later | | glibc, statically linked into containerd's static archive, runc and the pause binary |
| D-LIC-LIBGCC | GPL-3.0-or-later WITH GCC-exception-3.1 | | the GCC runtime in the same static links |
| D-LIC-LIBSECCOMP | LGPL-2.1-only | | libseccomp in runc |
| D-LIC-LIBPATHRS | MPL-2.0 OR LGPL-3.0-or-later | MPL-2.0 | libpathrs in runc |
| D-LIC-CRATES-MIT-APACHE | MIT OR Apache-2.0 | Apache-2.0 | libpathrs' crates bitflags, itertools, libc, once_cell, thiserror, static_assertions |
| D-LIC-CRATES-UNLICENSE-MIT | Unlicense OR MIT | MIT | memchr |
| D-LIC-CRATES-LLVM-APACHE-MIT | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | Apache-2.0 | rustix |
| D-LIC-NFT | GPL-2.0-only | | the host's nft and libnftables, executed by kube-proxy (`nft --json`) |
| D-LIC-LIBNFTNL | GPL-2.0-or-later | | libnftnl |
| D-LIC-LIBMNL | LGPL-2.1-or-later | | libmnl |
| D-LIC-GMP | LGPL-3.0-or-later OR GPL-2.0-or-later | LGPL-3.0-or-later | gmp |

The crate lists above are libpathrs' direct and named transitive crates; under owner decision Q-L3 (L3-a), the
build-time license gate and SBOM enumerate the full crate closures, including the Rust std closure linked into runc,
and record every election. jansson (MIT) needs no review. The nft libraries' expressions are the upstream licenses as recorded here; the host-image
packet verifies them against the shipped packages. The policy pins its identity, so the amendment is its own packet
(D-POLICY-AMEND, LIC-HOST) before the host-image packet and before HE-001's license gate, which needs the OR-choice rule
for Rust std and core (MIT OR Apache-2.0). I06 SC13 admits only `distribution.license == "Apache-2.0"`, so W02g-F2
replaces that check with a reference to the reviewed closure (D-I06-LICENSE).

## I05 re-check

The I05 v3 outcome mapping (`architecture/i05-gate-channel-v3/outcome-mapping.json`) was derived from five Kubernetes
source files at v1.37.1 (`f78e7223`). It asked for its rows and DELETE bodies to be re-checked against the selected
distribution before the gate is built. The selected apiserver is the unmodified v1.37.1 release of that commit. All five
files were fetched at that commit, and each matches the mapping's pinned SHA-256
(`SOURCES_IDENTICAL_AT_SELECTED_COMMIT`), so the rows and DELETE bodies stand as written.

## Excluded candidates

Each exclusion names the criterion that rules it out:
- k3s, k0s and RKE2 (one multi-call binary or a vendor suffix: SC08, SC14);
- kine (Kubernetes does not test its emulated etcd API; SQLite license and CGO);
- kubeadm and its defaults (SC03, SC06, SC12);
- Calico, Cilium and Antrea (CRDs or BPF datapaths: SC09, SC08);
- CoreDNS and CRI-O (owner decision Q4);
- crun (license);
- the AdminNetworkPolicy commands of kube-network-policies (SC09);
- etcdctl, etcdutl, ctr and containerd-stress (clients, not components).

## Open items

| ID | Owner | Item |
|---|---|---|
| D-W02A-F2 | W02a-F2, W02g-F2 | production W02a backend profile and an I06 successor bound to it |
| D-SC01-PEER | W02g-F2 | accept exactly one AF_UNIX etcd peer listener and no TCP listener |
| D-HELPER-TYPES | W02a-F2, W02g-F2 | confined types for the shim, runc, the CNI plugins and the host's nft |
| D-POLICY-AMEND | LIC-HOST | the license-policy amendment approved in Q-L |
| D-I06-LICENSE | W02g-F2 | replace SC13's single-license check with the reviewed closure |
| D-LIC-CLOSURE | W03 host-image packet | full license closure and SBOM, including nft 1.0.1 or later and its libraries |
| D-KUBELET-LISTENER | W03 host-image packet | the kubelet's `--address` and `--node-ip`, reachable only from the apiserver |
| D-NETPOL-BUILD | W03 host-image packet | build the agent from its tag, digests recorded |
| D-SANDBOX | W03 host-image packet | pin and import the sandbox image |
| D-RUNTIME-BPF | T04 | containerd and runc load only cgroup-device programs; CNI and kube-proxy (nftables) load none |

## Round-1 findings and dispositions

| Finding | Disposition |
|---|---|
| F1 MAJOR, etcd peer mechanism and unsafe option | SC01 and D-SC01-PEER rewritten with the real mechanism and the exact URL forms at v3.7.2; the "empty list" option is gone |
| F2 MAJOR, runc's full static closure | Q-L re-posed with glibc, libseccomp and libpathrs; owner chose L-a; one review entry per expression |
| F3 MAJOR, static glibc in containerd and pause | D-LIC-GLIBC covers containerd, runc and pause; "Apache-2.0 only" removed; I06 SC13 carried as D-I06-LICENSE |
| F4 MAJOR, NRI socket | NRI disabled, agent `--disable-nri`; SC11 covers every containerd listener |
| F5 MINOR, rows versus the positive vector | socket path, the 15 sealed files with ENCRYPTION_CONFIG, conditional files, the vector's 34 controllers |
| F6 MINOR, process tree and helpers | SC08 rewritten; D-HELPER-TYPES; nft as a host dependency with its minimum version |
| F7 MINOR, containerd-stress | excluded with ctr |
| F8 MINOR, agent defaults | `--fail-open=false`, loopback metrics, `--disable-nri`, kubeconfig and hostname flags |
| F9 MINOR, kine and etcd 3.7 | kine's real reasons; owner chose etcd 3.7.2 (Q-E) |
| F10 MINOR, check-module gaps | reviews bound to the policy and to Q-L; Kubernetes roles bound to kubernetes/kubernetes at the baseline; source builds only for the agent; distinct digests; architecture in each source; pinned sandbox reference; executables not excluded; real dates; every open item attached; malformed input is a ValueError; the success message says digests are checked by review |
| F11, F12 NOTE | no change needed; loopback binds for the controller-manager, scheduler and kube-proxy adopted (SC02) |

## Round-2 findings and dispositions

| Finding | Disposition |
|---|---|
| F1 MAJOR, steady-state calls outside NATIVE_STATIC (mremap, prctl, tkill) | owner decision Q-S (S-b): W02d v3 adds them with narrow argument rules; the W03 plan records W02d v3 as a precondition (W02D-V3, SEC-8) and T04 still traces |
| F2 MAJOR, more of the license closure unclassified | owner decision Q-L2 (L2-a): OR-choice rule plus exact entries; one review per expression, with its election, for libgcc, libpathrs' crates and nft's libraries; Rust std and core recorded in the plan (LIC-RUST-STD) |
| F3 MINOR, W02d v2 not merged; citations | W02D-V2 registered as a precondition (SEC-7) and checked by `w03_plan.py`; `current_os_id` cited at `sys/thread/unix.rs:330-347` via `thread_info.rs:112-113`; the musl patch list includes CVE-2025-26519 |
| F4 MINOR, advertise URLs at v3.7.2 | SC01, README and D-SC01-PEER corrected: unix advertise URLs allowed (`config.go:1340-1344`), `:<port>` optional |
| F5 MINOR, plan versus selection | every selection open item registered with its packet; the Go 1.26.7 agent build toolchain and module cache recorded (also in VERIFIER-EXT); D-I06-LICENSE text updated |
| F6 MINOR, check-module gaps | owner decisions bound to the parts (Q-L, Q-E, Q-N), role repositories pinned, URL-path architecture check, duplicate-key policy loading, the policy pinned by digest, required static-closure reviews; in `w03_plan.py` the exact musl flags and patches, the Rust commit for its version, cited lines and anchors, no `..`, R12 only for the obligation outside W03, ValueError on malformed input |
| F7 NOTE, kubelet listener | D-KUBELET-LISTENER |
| F8 NOTE | no change needed |

## Round-3 findings and dispositions

| Finding | Disposition |
|---|---|
| F1 MAJOR, the Rust std closure | owner decision Q-L3 (L3-a): AND-term rule and legacy normalisation in LIC-HOST; the build-time gate and SBOM produce the crate list and elections; `either` and `linux-raw-sys` added to runc's crate reviews; the plan records LIC-RUST-STD and LIC-GATE |
| F2 MINOR, decisions not recorded | Q-L2 and Q-L3 recorded in `selection.json`, Q-L3 and Q-S in `plan.json`, each bound by the checks; the Q-L2 reviews attributed to Q-L2; SC13, LIC-HOST and VERIFIER-EXT updated; gmp's election tied to its explicit-review decision record |
| F3 MINOR, TR-SETXID reason | restated: the clone3 child makes only raw, async-signal-safe calls, because `__synccall` takes `__tl_lock` (`synccall.c:59`) and the child runs on the parent's copied libc state |
| F4 MINOR, check gaps | elected alternatives must be allowed, an allowed exception or an owner-approved explicit-review license; a host dependency's license equals its review's; the plan checks that every selection open item and LIC-RUST-STD are registered, refuses self-citation and reversed ranges, pins Go exactly, and requires every packet to discharge an obligation |
| F5 NOTE, nft closure and crun | the host dependency list is labelled the minimum, extended from the shipped packages; versions set with the host OS; crun's reason reworded |
| F6 NOTE | no change needed; the W01-AMEND citations now point at the merged record (`architecture/host-interface-amendment-w02d/`) |

## Not claimed

No artifact is installed or executed, and no evidence record exists. This is not native or tenant acceptance. The digests
are the upstreams' published values; the host-image packet verifies the bytes it installs against them.
