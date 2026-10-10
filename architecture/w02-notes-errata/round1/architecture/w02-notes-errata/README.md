# W02 notes errata — W02a-F2, W02g-F2 and PERF-032-F (DATA_CHECK_ONLY)

Alpha 2A; 2026-10-10. Status: **ERRATA_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW**.

This directory answers the review notes that three merged packets carried forward, as one cleanup packet (owner decision,
Q-S = A and Q-F = A):
- W02a-F2: native-profile-v3 round-6 notes R6-1, R6-2 and R6-3 (MET-ENFORCE-010, `architecture/native-profile-v3/`);
- W02g-F2: I06 backend profile v2 notes R2-4, R3-1 and R3-2 (MET-ENFORCE-012, `architecture/i06-backend-profile-v2/`);
- PERF-032-F: MET-PERF-032 review round-3 findings F12 to F15.

Errata records, not successors: no contract version, schema, rule, vector or model changes, and every adopted byte stays
as merged. Each record names the adopted bytes by SHA-256 at base main `5fab673`, lists counted replacements and
publishes the effective text under `effective/`. A replacement applies only when its `old` text occurs exactly `count`
times, and the rows of one file apply in order. Items that need a rule or model change (a distinct `verityDigest`
rule for backend executables and the R3-3 import-fallback narrowing) are not here: they belong to W02-PROD in the
primary lane, which is blocked on LIC-HOST and W05.

## Files

| File | Content |
|---|---|
| `native-profile-v3-errata.json` | R6-1, R6-2 and R6-3: 9 counted replacements in the v3 README and one in the v3 model's grammar comment, plus the added vector file |
| `native-profile-v3-r6-3-vectors.json` | 35 negatives and 4 accepted cases, replayed against the adopted v3 positives through the unchanged v3 model |
| `i06-backend-profile-v2-errata.json` | R3-1, R3-2 and R2-4: 8 counted replacements in the v2 README, review brief and `criteria.json` |
| `effective/` | the effective README, brief and criteria texts; no effective model is published |
| `REVIEW_BRIEF.md` | the brief for the independent review |
| `source-index.json` | digests of the subject and of the adopted inputs |
| `../../scripts/contract_errata.py` | `check_errata` (adopted digests, counts, effective digests and files, comment-only model rows) and `replay_vectors` |
| `../../scripts/perf032_followup.py` | the F12, F14 and F15 checks on current bytes |

## Native profile v3 (W02a-F2)

**R6-1** restates the K1 guarantee in decision 2's terms. No word names a unit or carries a unit-bearing value, apart
from the maintenance unit word. `root=`, `ro` and `rw` only drive systemd's fixed root-mount units. The binding fixes the
`initrd=` files and the `root=` device, in order, but not the kernel image or UKI an entry loads. The K1 statement's
W03/T04 list adds three items: that image, with its built-in initramfs, embedded `.initrd`, Secure Boot `.cmdline` and
addons; systemd-stub's sysext and confext sidecars; and a network root. The credentials bullet says that systemd-stub
packs the `/.extra` credentials and that `global_credentials` take effect only if they decrypt. The environment
sentence covers every allowlisted key whose handler can be compiled out, `initrd=` and `security=` included. The model's
grammar comment (rows of kind COMMENT_ONLY) gets the same wording. `check_errata` requires the effective module's syntax
tree to equal the adopted one, so the executed model bytes stay the round-6 bytes. The R5-1 and R5-3 rows follow.

**R6-2** restores the SMBIOS sentence: on a non-confidential VM, systemd-boot and systemd-stub append
`kernel-cmdline-extra` words to `/proc/cmdline`. Those words are part of both declared entries and must be inside the
grammar. The R2-2 row is true again and says so.

**R6-3** adds vectors and does not change the model:
- R63-01 to R63-20 are bound pairs (MAINTENANCE = ENROLLED + the unit) of the 20 one-sided grammar and lockdown
  negatives. Each is refused by its own rule: the enrolled grammar or lockdown. R63-02 and R63-04 put the unit word in
  the enrolled entry as well, so their pair names it twice. They are refused by the enrolled grammar first, and with the
  grammar off by the twice-named rule.
- R63-21 to R63-27 are maintenance entries that differ from the enrolled one only by a grammar word (lockdown dropped,
  `ro` dropped, `quiet` added, `ro` repeated) or only by word order (two words swapped, two `root=` words swapped, two
  `initrd=` words swapped). Each is refused by the binding.
- R63-28 to R63-35 are bound pairs for `security=apparmor`, `rootfstype=`, `initrd=<addr>,<size>`, a second
  `lockdown=` value, `loglevel=8` and `root=fstab`, `tmpfs` and `gpt-auto`.
- R63-A01 to A04 accept `root=LABEL=`, `root=/dev/`, and the unit first or between two words.

The effective v3 README's Files paragraph lists every one-sided command-line negative as also breaking the binding. It also
states the overlap: the maintenance-grammar rule follows from the enrolled grammar plus the binding, and the
maintenance-target rule from the binding plus distinct command lines. So each of them is reached first only by a case
that also breaks the binding. Both rules are kept.

Each mutant that round 6 named was replayed by the author. Every one passes all 207 adopted negatives and 9 accepted
cases, and every one changes at least one errata case:

| Mutant | Errata cases that flip |
|---|---|
| order-insensitive binding | R63-24, R63-26, R63-27 |
| set-based binding | R63-24 to R63-27 |
| superset binding | R63-23 to R63-27 |
| `root=`/`initrd=` words only | R63-21, R63-22, R63-23, R63-25 |
| unit last | R63-A03, R63-A04 |
| enrolled grammar, maintenance grammar and lockdown all off | R63-01, R63-03, R63-05 to R63-20, R63-28 to R63-35 |
| lockdown rule off | R63-01 |
| `rootfstype=` admitted, any `initrd=`, `security=[a-z]+`, `lockdown=[a-z]+`, `loglevel=[0-9]+` | R63-29, R63-30, R63-28, R63-31, R63-32 |
| any `root=` value; `root=/dev/` dropped; `root=LABEL=` dropped | R63-33 to R63-35; R63-A02; R63-A01 |

## I06 backend profile v2 (W02g-F2)

- **R3-1**: the two "Round-2 findings and dispositions" headings become "W02g round-2 findings (N1-N6) and dispositions"
  and "W02g-F round-2 findings (R2-1 to R2-5) and round-3 changes". The README status pointer and the brief pointer now
  name the second heading.
- **R3-2**: the Files table lists `review-round2.json`, `round2/`, `review-round3.json` and `status.json`. "Still open"
  carries the distinct-`verityDigest` rule (R2-4) and the R3-3 import-fallback narrowing to W02-PROD.
- **R2-4**, by its documented alternative: SC08 content distinctness is by SHA-256 (`artifactDigest`). A record whose
  `verityDigest` contradicts its SHA-256 is refused by the observed backend captures, which callers compose through
  `check_qualification` (W03). `check_backend_capture` compares each executable's `contentDigest` and `measuredVerity`
  with the record (`scripts/native_qualification_v3.py` lines 566-567). The SC08 requirement in the effective
  `criteria.json` and the R2-4 disposition row say so.

## PERF-032-F

The merged MET-PERF-032 packet text is immutable, so its claims are made true by checks rather than narrowed. A later
packet layer calls the checks on its reviewed bytes:
- **F12**: route-test setup values may contain no lambda, generator, comprehension, or `map`, `filter`, `iter`, `zip`,
  `reversed`, `enumerate` or `partial` call. Every route call's receiver is a module alias, never a setup name. All 31
  current route tests (806 calls) comply. The round-3 generator and `map` probes are refused.
- **F13** (wording): `unique()`'s docstring carries the one-frame caveat. The `check_grouped_module` docstring and its
  refusal message say "the sorted, grouped and kept paths", and the RecursionError fallback is pinned by bytes only. The
  two tests that match that message follow. The master-plan PERF-032 line carries the caveat. In the PERF-032 layer,
  `UNIQUE_SHA256` still holds, because a later bridge projects the current bytes back to the reviewed ones.
- **F14**: the stubbed model's exact set of Name ids and Attribute names is pinned by digest. The four round-3 escapes
  (`json.__builtins__`, `__loader__`, `__spec__`, `RefResolver.resolve_remote`) are refused.
- **F15**: every jsonschema, referencing and jsonschema_specifications module dict, the Draft 2020-12 class dict and its
  VALIDATORS are snapshotted by value identity. `_keywords.uniq is _utils.uniq` is checked before the exec, after it and
  after the run. The round-3 `_keywords.uniq` rebinding and the deferred `_utils.uniq` rebinding are refused.

## Not claimed

- No contract version, schema, rule or model changes. The adopted native-profile-v3 and I06 v2 directories and models
  stay byte-identical, and their status records keep their carried findings, which this record answers.
- No native, kernel, cluster or distribution observation. All E01-E12 stay OPEN_UNPROVEN.
- W02-PROD (primary lane, blocked on LIC-HOST and W05) owns the rule changes: a distinct `verityDigest` rule, the R3-3
  narrowing and any change to the v3 boot-entry rules.
