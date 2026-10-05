# Owner-operated required check — MET-VERIFY-001

Status: source-only contract on accepted main `e4e0bebc77737d99a32aedee7916f36a3906c3bd`.
It records an owner decision of October 3, 2026, amended on October 4, 2026 by
MET-VERIFY-002 (isolated runner call and exact-commit transport approval) and
MET-VERIFY-003 (isolated network canary and corrected approval wording), and on
October 5, 2026 by MET-VERIFY-004 (dedicated verifier account). It is not native Linux
qualification, exact-main evidence, an installed Linux host, runtime or tenant
acceptance, and it authorizes no cloud provisioning or spending.

## Why

The required `verify` check on `main` could only be produced by the
`offline-readiness` workflow on a self-hosted runner. No runner was ever
registered (the bounded disposable-guest design in
[CI_CAPACITY_EXCEPTION.md](CI_CAPACITY_EXCEPTION.md) was never provisioned), so
PR #145 and PR #146 were merged under two consumed one-time administrator
exceptions. Those exceptions are not reusable and transfer no allowance.

## Required-check source

- Branch protection on `main` requires the check `verify`, pinned to the owner's
  GitHub App `harness-onion-verify` (App ID 5175550). The App has Checks write,
  Pull requests read and Metadata read, and is installed only on this repository.
  A check or status named `verify` from any other source does not satisfy it.
- The `offline-readiness` workflow file stays byte-identical but is disabled.
  No GitHub-hosted runner or hosted minutes are used.
- The verifier is external operator infrastructure on an owner-operated host.
  Its code, keys and evidence are operator records outside this repository.

## Admission rules

For each open, same-repository, non-draft pull request into `main`:

1. Verify the exact head commit once. There is no automatic retry; a new push is
   a new head. Fork pull requests are never fetched or executed.
2. Require the branch to contain the current `main`, so the verified tree is the
   merge candidate.
3. Require exactly one added `task-packets/*.yaml` (a regular file) and no other
   packet change. The packet must keep every command of the newest accepted
   packet on `main`, in order.
4. Refuse pull requests changing anything under `ci/` other than top-level
   `ci/test_*.py` and `ci/linux-runner/`, unless the owner has approved that
   exact head commit. The launcher executes the checkout's own offline
   transport, which also prints the evidence lines, so such a change runs only
   after an independent source review and the owner's approval: a root-owned,
   non-writable record `/private/etc/planeon/transport-approvals/<head>.json`
   naming the pull request number and the exact head commit, inside root-owned
   directories. Creating it needs the owner's administrator password, so agents
   running as the operator cannot create the approval record; they can still
   alter the verifier itself (see the residual risks). A new push is a new head
   and needs a new approval. The check summary records the approval digest.
5. Sign a short-lived activation for the exact packet bytes and commit, activate
   it through the installed root helper, and run the installed trusted launcher
   once. The launcher still enforces deny-all outbound isolation, the 900-second
   ceiling, the exact packet and the exact commit.
6. Report success only for exit code zero, the exact packet/session header,
   every declared command in order, unchanged tracked files and a run inside the
   deadline. Only strict pytest totals are published; logs stay on the host.

The verifier pauses while any operator LOCAL attempt or launcher is running, when
the operator creates `/opt/planeon/verifier-control/PAUSE`, at a daily run cap, or
before the shared activation store nears capacity. Operators create `PAUSE` at the
start of every manual LOCAL gate and remove it afterwards.

## Execution authority and isolation

- The verifier runs as a dedicated hidden macOS account (no login shell, no
  password) started at boot by a root-owned LaunchDaemon. Its code is root-owned
  and read-only; its keys and run records live in that account's own home. The
  operator's account, and so agents running as the operator, can read the run
  records and logs but cannot change the verifier, read its keys or alter its
  records. Verifier changes are root installs by the owner.
- A separate narrow activation key is accepted by the installed authority only
  for repository `Harness-Engineering`, profile `python-meta` and a lifetime of at
  most 1800 seconds, and only from the dedicated account; the installed launcher
  runs such an activation only as that account, in its own runner root. The
  operator key path is unchanged and works only from the operator's account.
- Packet code is denied the operator's home and the verifier account's home,
  signals to processes outside its own sandbox, writes to per-user temporary and
  cache folders, and creation of warm-snapshot containers; every process of the
  verifier account that outlives a run is stopped before the next activation.
- The offline wrapper starts its runner with `python3 -I`, and the runner starts
  its network canary with `-I`, so modules planted in the checkout's `ci/`
  directory, `PYTHON*` variables and user site-packages cannot shadow the
  standard library either of them imports.
- The installed launcher sandbox additionally denies LaunchServices opens,
  Apple Events, launchd job creation and execution of `open`, `osascript`,
  `osacompile`, `launchctl`, `crontab`, `at`, `batch`, `automator`, `shortcuts`
  and `lsappinfo`. Probe evidence for these denials is an operator record and is
  repeated after macOS updates.
- The operator's GitHub CLI login used by agents is a fine-grained token without
  repository administration, so it cannot change branch protection.
- Residual risks accepted by the owner: credentials issued before the move that
  agents running as the operator could read (the earlier App key, the earlier
  administrator CLI login) stay valid until the owner revokes them, and until then
  this protection is incomplete; agents running as the operator can still pause
  verification or delay it (`PAUSE`, warm-snapshot containers); manual attempts
  rely on the `PAUSE` file; test contents remain pull-request controlled, so human
  review stays required.

## Evidence states

A `verify` success is a pull-request check on the macOS trusted offline launcher.
Source review, isolated LOCAL acceptance, merge, exact-main, installed Linux host,
native Linux (`CONF-LINUX-001`), runtime and tenant acceptance remain separate
states and are never inferred from it.

## Successor and rollback

A GCP Linux verifier in project `harness-onion` is the intended successor. It
needs its own reviewed image, launcher installation, cost limit and owner
approval; this packet grants none of them. A Linux runner policy pins the
transport bytes (`transportPins` for `ci/verify-offline.sh`, `ci/run_packet_argv.py`
and `ci/network_canary.py`) of the accepted `main` it runs, never an older value.

Rollback is a set of independent operator actions: re-enable `offline-readiness`,
unpin the `verify` check source, unload the verifier, and restore the installed
authority, launcher and policy from the owner's rollback copy (the dedicated
account move has its own root rollback script). Revert this source in its own
scoped pull request.
