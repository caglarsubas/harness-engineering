# Alpha 2A — W03-0 backend distribution selection and W03 plan (MET-ENFORCE-019)

> Current-status page for W03-0. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md) gives packet status; the
> records are [`architecture/backend-distribution/`](../../architecture/backend-distribution/README.md) and
> [`architecture/w03-plan/`](../../architecture/w03-plan/README.md).

W01 §2.1 left the concrete Kubernetes backend for `SEALED_SINGLE_NODE_CONTROL_PLANE_V1` to W03, and W02g (I06) fixed what
it must satisfy. W03-0 selects it and records the owner's W03 decisions. The owner decided each question on 2026-10-10, via
the lane monitor.

- **The component set (Q4).** It is configured from sealed files, with no installer at runtime:
  - official v1.37.1 kube-apiserver, kube-controller-manager, kube-scheduler, kubelet and kube-proxy (nftables mode);
  - etcd v3.7.2, a single member on a unix socket (Q-E);
  - containerd 2.4.1 with runc 1.5.2 under the cgroupfs driver;
  - the CNI plugins bridge, host-local and loopback;
  - kube-network-policies v1.1.2, built from its tag (Q-N);
  - no CoreDNS.
  Every downloaded artifact is pinned by its upstream's published digest. The network-policy agent is built from
  commit `a145b01c` (tag v1.1.2), and its digests are recorded at build (D-NETPOL-BUILD). Each of the 30 I06 v2 criteria
  is mapped to how the set meets it. The I05 outcome mapping's five sources are identical at the selected Kubernetes commit.
- **The license closure (Q-L, Q-L2, Q-L3).** The official binaries are kept. One review per expression covers the
  statically linked glibc, libgcc, libseccomp, libpathrs and its crates, and the host's nft with its libraries. The
  license-policy amendment, with a host-OS class, OR-choice and AND-term rules and legacy normalisation, is its own
  packet (LIC-HOST), because validators pin the policy.
- **The W03 plan (Q1, Q2, Q3, Q5, Q-S).**
  - Scope: R10 `host-enforcement/` with five modules, plus `host-image/` and `enrollment/`.
  - Toolchain: Rust 1.99.0 with musl 1.2.5, fully static, for the native roles; Go 1.26.7 for the agent build.
  - Start-up: a re-check against W02d v2's analysed reference (Rust 1.90.0) finds the same start-up syscalls.
  - Steady state: W02d v3 adds mremap, prctl(PR_SET_NAME) and tkill (Q-S).
  - The plan registers 71 obligations across 17 planned packets.
- **Open items** carried forward: the production backend profile and I06 successor (W02a-F2, W02g-F2), including etcd's
  peer listener against SC01 and helper confined types; the license amendment (LIC-HOST); the host-image packet's
  closure, agent build, sandbox image and kubelet listener; and the native confirmation of the runtime BPF programs
  (D-RUNTIME-BPF, T04).
- **Review.** Five independent rounds: four CHANGES_REQUIRED, then PASS_FOR_SOURCE_PUBLICATION on `104b115`.

The new layer `scripts/validate_backend_distribution.py` first binds every reviewed file, round copy and review record by
digest and checks the adoption record. It then executes both reference modules from this era's reviewed bytes, with this
era's `safe_yaml`: the selection check and the plan check. Their results must carry the owner's decisions. DATA_CHECK_ONLY: nothing is installed or
executed, no I06 evidence record exists, and every E01-E12 obligation stays OPEN_UNPROVEN.
