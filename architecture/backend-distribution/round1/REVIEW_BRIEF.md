# Review brief — W03-0 backend distribution selection, round 1

Subject: `architecture/backend-distribution/` (README.md, selection.json) and `scripts/backend_distribution.py`.

Please check:
1. **Criteria coverage.** Every I06 v2 criterion (`architecture/i06-backend-profile-v2/criteria.json`, SC00-SC15, CL,
   IC01-IC05, OR01-OR08) has a row whose dispositions and text are right for the selected parts. Pay particular attention
   to these:
   - SC01: the etcd peer-listener finding (`server/embed/config.go:1573`, `server/etcdmain/etcd.go:83` at `a3346427`);
   - SC03, SC05 and SC06: the flags against the I06 v2 positive evidence and the v1.37.1 upstream facts;
   - SC08: separate processes, distinct executables;
   - SC09: kube-network-policies' standard command uses no CRDs;
   - SC13: pinning, offline operation and licenses.
2. **Pins.** Each artifact digest equals the upstream's published checksum:
   - Kubernetes: `https://dl.k8s.io/release/v1.37.1/bin/linux/{amd64,arm64}/<name>.sha256`;
   - etcd v3.6.15: `SHA256SUMS`;
   - containerd v2.4.1: `containerd-static-*.sha256sum`;
   - runc v1.5.2: `runc.sha256sum`;
   - CNI plugins v1.9.1: `*.sha256`.
   Each tag resolves to the recorded commit, and the sandbox image index digest matches `registry.k8s.io/pause:3.10.2`.
3. **Exclusions** cite the right criteria, and no qualifying candidate the owner should have seen is missing.
4. **License.** Is the runc libseccomp finding right? Is anything else outside the policy, such as statically linked C
   libraries in containerd's static archive or the pause binary?
5. **I05 re-check.** The mapping's five source files match at `f78e7223`.
6. **The check module** refuses malformed or incomplete records, does not read outside its four inputs, and makes no
   claim it does not check.

Read-only. Network reads of public release metadata and source files are fine. Do not download large archives unless
needed; if you do, say which ones. No sudo, no edits.
