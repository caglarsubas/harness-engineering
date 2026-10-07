# Alpha 2A — W02e SELinux matrix (MET-ENFORCE-009)

> Current-status page for the W02e part. The [unified master roadmap](../MASTER_DEVELOPMENT_PLAN.md) gives packet and
> phase status; W02c is recorded on the [W02c page](I07_POLICY_WRITE.md).

W02e: **ADOPTED_DATA_CONTRACT.** The closed SELinux domain, type, boolean and permission matrix
`planeon.internal.selinux-matrix/v3` passed its third independent source-only review with verdict
PASS_FOR_SOURCE_PUBLICATION. It formalizes the SELinux choices of the reviewed W01 design (§2.1 P1/P2/P4/P5/P9, §2.3,
§4.1-§4.3, §5.1-§5.5) and fills the W02a slots left to W02e: role cgroup, pin and seal-marker labels, and the confined
backend types. It closes W01 review finding F2 at design level and W02a round-2 finding N1 as a requirement. It is
DATA_CHECK_ONLY: no policy module is written, compiled or loaded, and all E01-E12 remain OPEN_UNPROVEN.

## Contract

- [README](../../architecture/selinux-matrix/README.md): what the matrix closes, booleans and boot states, domains, types
  and rules, the 100 deny assertions, the corrected F2 closure, the W02a slot values, the backend module requirements,
  owner decision E1, decisions 1-10 and the round-1 and round-2 dispositions.
- [Matrix](../../architecture/selinux-matrix/matrix.json):
  - 19 domains and 56 types;
  - cgroup2, bpffs and selinuxfs genfscon labelling and named type transitions for runtime objects;
  - capability, `bpf`, `security`, `process` and `service` grants, `/proc` access and per-source closures.
- [Vectors](../../architecture/selinux-matrix/vectors.json): 1,716 access checks, 50 mutation checks and the W02a slot
  values.
- Reference evaluator `scripts/selinux_matrix.py`: `allowed`, `check_matrix`, `failed_assertions`, `w02a_slots`.

Key rules:
- **Apiserver port:** exactly the gate, the observer and the enumerated control-plane clients connect to it (P2).
- **Sockets:** only the broker reaches I05, only the writer reaches I07, only the apiserver reaches the datastore (P1) and
  only the kubelet reaches the runtime (P9).
- **Sealed types:** written only by the maintenance domain in the maintenance boot, where fs-verity is also enabled.
- **BPF:** programs are loaded only by containment before the seal, plus the runtime under E1. Containment programs are
  read only by the reader roles, and nothing creates a map.
- **Booleans:** frozen after the S4 commit.
- **Cgroups:** reached only by systemd, containment, the readers and, on its delegated cgroups, the broker. They are
  labelled by cgroup2 genfscon path rules.
- **Planeon processes:** the per-source closures deny connections and program execution beyond their listed targets,
  declared or not.

## Owner decision E1

On cgroup v2 every OCI runtime loads a device-control BPF program per container. The owner chose a narrow exception to
W01 §5.3 and re-confirmed it after review at its real scope.
- **Enforced by the policy:** no maps, no containment programs, no planeon cgroups or pins.
- **Trusted, not enforced:** the runtime's BPF use. SELinux cannot restrict program type, attach type or target, and
  CAP_SYS_ADMIN reaches other program families.
- **Controls:** W03 runtime selection, T04, and a W02a-F census of planeon cgroups' effective programs.

## Independent review

| Round | Verdict | Record | Reviewed subject |
|---|---|---|---|
| 1 | CHANGES_REQUIRED (8 MAJOR, 9 MINOR, 1 NOTE) | `review-round1.json` | `round1/` |
| 2 | CHANGES_REQUIRED (2 MAJOR, 4 MINOR, 2 NOTE; 16 of 18 round-1 findings closed) | `review-round2.json` | `round2/` |
| 3 | PASS_FOR_SOURCE_PUBLICATION (2 MINOR, 4 NOTE) | `review-round3.json` | current files |

The reviewer was a separate agent that did not author the matrix. It worked read-only against Linux v6.12 kernel and
SELinux source, and the reviewed bytes were kept unchanged. It checked every class and permission against the classmap
and replayed all vectors. It probed the closure with in-memory mutations, and found the F2 statement correct and resting
on the controls that decide.

Round 2 caught that named type transitions never fire under cgroup2 parents. Round 3 confirmed the genfscon labelling that
replaced them. The [status record](../../architecture/selinux-matrix/status.json) derives the adoption state from the final
verdict and records owner decision E1. `scripts/validate_selinux_matrix.py` checks that derivation and the agreement with
the W02a schema.

## Carried findings (none blocking)

- **K1** → W02a-F, T04 and W01's record. The maintenance domain's policy load carries boolean values over, so A62-A65 hold
  under the pinned policy only. The maintenance-boot property needs a record-level boot-entry discriminator. This keeps
  round-2 finding N4 partial.
- **K2-K4, K6** → W02e-F: per-target `/proc` assertions, `load_policy` asserted before the seal, cgroup2 wording, and the
  brief's assertion count.
- **K5** → W03 and T04:
  - `DelegateSubgroup=broker` for the pre-created delegated leaves;
  - the maintenance unit writes booleans in `init_t`;
  - `portcon` for the server listener.

## Still open

All E01-E12 and T01-T08. The binary policy and its behaviour on the enrolled kernel (T04). The backend policy module, the
selected runtime's BPF behaviour and the selected distribution (W03). The effective-program census and the schema
constants for these labels (W02a-F). The seccomp filters (W02d). W03-W07 remain gated. Alpha2 remains open; model-effort
transition NOT_DUE.
