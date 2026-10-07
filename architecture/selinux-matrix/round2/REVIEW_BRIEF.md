# Independent review brief — W02e SELinux matrix, round 2

Status: **CONTRACT_CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a
verdict.

Round 1 (`review-round1.json`) returned CHANGES_REQUIRED; its reviewed bytes are kept in `round1/`. README.md ("Round-1
findings and dispositions") states how round 2 answers R1-R18. The owner re-confirmed decision E1 at its real scope after
R7.

## Subject

The exact bytes listed under `subject` in `source-index.json`: README.md, this brief, `matrix.json`, `vectors.json` and
the reference evaluator `scripts/selinux_matrix.py`. Check them against the predecessor inputs listed there:
- the reviewed W01 resolution (§2.1 P1/P2/P4/P5/P9, §2.3, §4.1-§4.3, §5.1-§5.5, counterexamples 19, 25, 27, 28) and its
  review with finding F2;
- the adopted W02a v2 record contract (its schema's label slots and fixed process labels, round-2 finding N1, owner
  decision D5);
- the adopted W02g I06 profile (backend components and identities);
- the adopted W02b and W02c channel contracts (the I05 and I07 sockets).

The working tree also contains this packet's mechanical history-chain edits. They are outside this subject, are checked by
the required verify suite, and will not change while you review.

The owner made decision E1 during authoring (README "Owner decision"). It is an input you may question, not a subject
to rubber-stamp.

## Questions to answer

0. **Round-1 closure.** For each round-1 finding R1-R18, is the README disposition true in the round-2 bytes? Give
   CLOSED, PARTIAL or OPEN under `openItemStatus`.
1. **Fidelity.** Does the matrix encode the W01 SELinux design without weakening it? Check P1, P2, P4, P5 and P9, the
   §5.3 per-role domains and admin denials, the §5.1 BPF and cgroup controls, the §5.2 seal sequence and booleans, and
   the §5.5 maintenance. Does every deviation appear as a disclosed decision? The deviations are E1, gate `setsockcreate`,
   containment labelling before the seal, the admin capability set, reader `/proc` reads and backend capability sets.
2. **F2.** Is the F2 closure text correct about kernel and SELinux behaviour? Consider O_PATH opens without an open check,
   path-walk `dir search`, `open_by_handle_at` and CAP_DAC_READ_SEARCH (including the v6.10 relaxation), cgroup2 on
   kernfs, BPF_F_ALLOW_MULTI detach and `bpf_prog_new_fd`'s `prog_run`. Does it rest on the controls that actually
   decide, and does it overclaim anything?
3. **SELinux semantics.** Are the classes, permissions and their meanings right? Check:
   - `unix_stream_socket connectto` for AF_UNIX SOCK_SEQPACKET and its target (the listening socket's label,
     `setsockcreate`);
   - `sock_file write` to connect;
   - `tcp_socket name_bind`/`name_connect` on labelled ports;
   - the ptrace read check as `file read` on the target process;
   - `process transition` with `file execute`/`entrypoint`;
   - `bpf prog_load`/`prog_run`/`map_*`;
   - `security setbool`/`load_policy`/`setenforce` with `secure_mode_policyload`;
   - `service` permissions under systemd;
   - `capability`/`capability2`/`cap_userns` names;
   - the policy capabilities `cgroup_seclabel` and `open_perms`.

   Flag anything a real policy could not express or would express differently.
4. **Closure and assertions.** Is the closure claim sound: what is closed, what is outside, and the "W03 may add nothing
   the matrix closes" rule? Do the 54 assertions capture the W01 deny properties? Are any vacuous, missing or wrong? Do
   the mutation checks prove they bite? Is anything granted that a W01 property forbids?
5. **W02a consistency.** Do the slot values fit the W02a schema patterns, do the process labels equal its constants, and
   is the N1 closure real?
6. **Vectors.** Does each access check and mutation check produce exactly its stated result for its stated reason?
7. **Overclaims.** Does anything claim a policy module, a compiled or loaded policy, native behaviour, a selected
   distribution, seccomp filters or any E01-E12 proof?

## How to check

You may run the reference evaluator read-only from the repository root with the locked environment
(`uv run --offline --frozen --no-sync python`): import `scripts/selinux_matrix.py`. Do not run the repository test suite
or validators, and do not modify any file.

## Result

Return one JSON object:
- `schemaVersion` `"planeon.internal.selinux-matrix-review/v1"`, `round` 2, `reviewDate`;
- `verdict`: PASS_FOR_SOURCE_PUBLICATION, CHANGES_REQUIRED or BLOCKED;
- `subjectSha256`: subject file name to digest;
- `findings`, each with `id`, `severity` (BLOCKING / MAJOR / MINOR / NOTE), `location`, `finding` and `requiredChange`;
- `openItemStatus` (R1-R18), `questionAnswers` (Q0-Q7), `modelExecution`, `sourcesRead`;
- `actions`, booleans: `filesEdited`, `githubMutated`, `nativeActions`, `referenceModelExecuted`,
  `repositoryValidatorsRun`, `runnerActivated`, `testsRun`, `warmSourcesAccessed`;
- `reviewLimit`.

A PASS is not a policy module, native qualification or authorization for anything installed.

Rules: separate agent from the author; read-only; no repository edits, no tests or validators, no runner, native, cloud
or GitHub actions, no warm-source access. Public documentation and kernel or SELinux source may be read; list what you
read.
