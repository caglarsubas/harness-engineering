# Backend distribution selection — W03-0 (DATA_CHECK_ONLY)

Status: **CONTRACT_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW**. DATA_CHECK_ONLY: nothing is installed or executed, no
I06 evidence record exists, and E01-E12 stay OPEN_UNPROVEN.

W01 §2.1 leaves the concrete Kubernetes backend for `SEALED_SINGLE_NODE_CONTROL_PLANE_V1` to W03, "under license and
offline closure". W02g (I06 v1 and v2) fixed what that backend must satisfy: the criteria SC00-SC15, the closure CL, the
snapshot checks IC01-IC05 and the operational rules OR01-OR08, all at Kubernetes v1.37.1 (commit `f78e7223`). This
directory selects the concrete component set and shows, row by row, how it meets those criteria. It is the input W04
(independent tests) and W02a-F2 and W02g-F2 (the production backend profile) start from.

## Owner decisions (2026-10-10, via the lane monitor)

| ID | Decision |
|---|---|
| Q4 | An upstream component set configured only from sealed files, with no installer at runtime. The parts: official v1.37.1 kube-apiserver, kube-controller-manager, kube-scheduler, kubelet and kube-proxy (nftables mode); etcd 3.6 on a unix socket; containerd 2.x with runc and the cgroupfs driver; the CNI plugins bridge, host-local and loopback; kube-network-policies (nftables); no CoreDNS. Every part is digest-pinned. |
| Q-R | Pending: runc's release binaries statically link libseccomp (LGPL-2.1), which the license policy does not classify. |
| Q-N | Pending: kube-network-policies publishes container images only, so the agent is built from its tag. |

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
| DATASTORE | etcd v3.6.15 (`a3346427`) | release archive, `SHA256SUMS`; only `etcd` is installed |
| CONTAINER_RUNTIME | containerd v2.4.1 static (`f2551031`), runc v1.5.2 (`29dd3dc2`), CNI plugins v1.9.1 (`adc3e6b5`) | release archives and binaries with their checksum files; containerd's `ctr` and every CNI plugin except bridge, host-local and loopback are left out |
| NETWORK_POLICY_AGENT | kube-network-policies v1.1.2 (`a145b01c`), `standard` command | built from the tag (no release binaries) |

The sandbox image is `registry.k8s.io/pause:3.10.2`, pinned by index digest. That is containerd 2.4.1's default and
Kubernetes v1.37.1's pause version. Every upstream is Apache-2.0.

Version notes:
- containerd 2.4 is listed for Kubernetes 1.37 in containerd's support matrix (2.4.0+ and 2.3.0+, CRI v1).
- etcd 3.6.15 and runc 1.5.2 are the newest patch releases of their selected lines.

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
- **SC01 (D-SC01-PEER).** etcd v3.6.15 accepts unix client and peer URLs, but an empty peer listener list is not a
  dependable configuration. `UpdateDefaultClusterFromName` indexes `ListenPeerUrls[0]`
  (`server/embed/config.go:1573`, called at `server/etcdmain/etcd.go:83`) whenever a default host is detected. The
  selection therefore uses a unix peer socket in the datastore's private directory. I06 v1 and v2 refuse anything but
  `peerListen == []`. W02g-F2 either accepts an AF_UNIX peer listener confined to the datastore's type, or keeps the
  literal rule and requires native proof that an empty list starts on the enrolled host.

## License closure

Every upstream part is Apache-2.0. runc's release binaries statically link libseccomp (LGPL-2.1). The license policy
(`legal/third-party-license-policy.yaml`) neither allows LGPL-2.1 nor lists it for review, so the fail-closed rule denies
it until the owner decides (D-LIC-RUNC, owner question Q-R). The host-image packet checks the full closure: every Go module
set, and any statically linked C library in containerd, runc and the pause binary (D-LIC-CLOSURE).

## I05 re-check

The I05 v3 outcome mapping (`architecture/i05-gate-channel-v3/outcome-mapping.json`) was derived from five Kubernetes
source files at v1.37.1 (`f78e7223`). It asked for its rows and DELETE bodies to be re-checked against the selected
distribution before the gate is built. The selected apiserver is the unmodified v1.37.1 release of that commit. All five
files were fetched at that commit, and each matches the mapping's pinned SHA-256
(`SOURCES_IDENTICAL_AT_SELECTED_COMMIT`), so the rows and DELETE bodies stand as written.

## Excluded candidates

Each exclusion names the criterion that rules it out:
- k3s, k0s and RKE2 (one multi-call binary or a vendor suffix: SC08, SC14);
- kine (SC01, SC08);
- kubeadm and its defaults (SC03, SC06, SC12);
- Calico, Cilium and Antrea (CRDs or BPF datapaths: SC09, SC08);
- CoreDNS and CRI-O (owner decision Q4);
- crun (license);
- the AdminNetworkPolicy commands of kube-network-policies (SC09);
- the etcd and containerd command-line clients (not components).

## Open items

| ID | Owner | Item |
|---|---|---|
| D-W02A-F2 | W02a-F2, W02g-F2 | production W02a backend profile and an I06 successor bound to it |
| D-SC01-PEER | W02g-F2 | etcd's peer listener against SC01 |
| D-LIC-CLOSURE | W03 host-image packet | full license closure and SBOM |
| D-NETPOL-BUILD | W03 host-image packet | reproducible build of the agent from its tag, digests recorded |
| D-SANDBOX | W03 host-image packet | pin and import the sandbox image |
| D-RUNTIME-BPF | T04 | containerd and runc load only cgroup-device programs; CNI and kube-proxy (nftables) load none |

## Not claimed

No artifact is installed or executed, and no evidence record exists. This is not native or tenant acceptance. The digests
are the upstreams' published values; the host-image packet verifies the bytes it installs against them.
