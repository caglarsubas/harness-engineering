# W02 notes errata — W02a-F2, W02g-F2 and PERF-032-F (DATA_CHECK_ONLY)

Alpha 2A; 2026-10-10. Status: **ERRATA_CANDIDATE_ROUND5_AWAITING_INDEPENDENT_REVIEW**. Round 1 (`review-round1.json`, reviewed bytes in
`round1/`) returned CHANGES_REQUIRED with 5 MINOR and 6 NOTE findings, and round 2 (`review-round2.json`, `round2/`)
CHANGES_REQUIRED with 3 MINOR and 1 NOTE, round 3 (`review-round3.json`, `round3/`) CHANGES_REQUIRED with 1
MINOR and 3 NOTE, and round 4 (`review-round4.json`, `round4/`) CHANGES_REQUIRED with 1 MINOR and 1 NOTE; the findings
tables at the end answer each.

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
| `review-round1.json`, `round1/` | the verbatim round-1 review and the bytes it reviewed |
| `review-round2.json`, `round2/` | the verbatim round-2 review and the bytes it reviewed |
| `review-round3.json`, `round3/` | the verbatim round-3 review and the bytes it reviewed |
| `review-round4.json`, `round4/` | the verbatim round-4 review and the bytes it reviewed |
| `source-index.json` | digests of the subject and of the adopted inputs |
| `../../scripts/contract_errata.py` | `check_errata` (adopted digests, the added-vector digest, counts, effective digests and files, comment-only rows for Python files) and `replay_vectors`, which executes the model from the bytes it checks |
| `../../scripts/perf032_followup.py` | the F12, F14 and F15 checks on current bytes |

## Native profile v3 (W02a-F2)

**R6-1** restates the K1 guarantee in decision 2's terms. No word names a unit or carries a unit-bearing value, apart
from the maintenance unit word. `root=`, `ro` and `rw` only drive systemd's fixed root-mount units. The binding fixes the
`initrd=` files and the `root=` device, in order, but not the kernel image or UKI an entry loads. The K1 statement's
W03/T04 list adds three items: that image, with its built-in initramfs, embedded `.initrd`, Secure Boot `.cmdline` and
addons; systemd-stub's sysext and confext sidecars; and a network root. The credentials bullet keeps SMBIOS type 11
strings and qemu fw_cfg as the plain sources, and says that systemd-stub packs `/.extra/credentials` and
`/.extra/global_credentials` (systemd-boot v256 packs none), which systemd v256 imports into the encrypted, untrusted
directory, so both take effect only if they decrypt. A credential sealed with systemd's null key, which anyone able to
write the ESP can produce, decrypts unless the machine has a TPM2 and Secure Boot is on. The environment
sentence covers every allowlisted key whose handler can be compiled out, `initrd=` and `security=` included. The model's
grammar comment (rows of kind COMMENT_ONLY) gets the same wording. `check_errata` requires the effective module's token
stream without comments and blank lines, and its syntax tree, to equal the adopted ones, and never publishes an
effective Python file, so the executed model bytes stay the round-6 bytes. The R5-1 and R5-3 rows follow.

**R6-2** restores the SMBIOS sentence: on a non-confidential VM, systemd-boot (for a type #1 entry with a `linux` key)
and systemd-stub append `kernel-cmdline-extra` words to `/proc/cmdline`. Those words are part of both declared entries and must be inside the
grammar. The R2-2 row is true again and says so.

**R6-3** adds vectors and does not change the model:
- R63-01 to R63-20 are bound pairs (MAINTENANCE = ENROLLED + the unit) of the 20 one-sided grammar and lockdown
  negatives. Each is refused first by its enrolled rule: the enrolled grammar, or lockdown for R63-01, which breaks only
  that rule. The binding removes every unit word before it compares, so R63-02 and R63-04, whose enrolled entry already
  holds the unit word, cannot satisfy it; both also name the unit twice, and R63-04 also breaks the maintenance grammar
  (R63-02 does not). Every other pair holds the binding, and R63-03 and R63-05 to R63-20 break both grammar rules.
- R63-21 to R63-27 are maintenance entries that differ from the enrolled one only by a grammar word (lockdown dropped,
  `ro` dropped, `quiet` added, `ro` repeated) or only by word order (two words swapped, two `root=` words swapped, two
  `initrd=` words swapped). Each is refused by the binding.
- R63-28 to R63-35 are bound pairs, each holding the binding and breaking both grammar rules, for `security=apparmor`, `rootfstype=`, `initrd=<addr>,<size>`, a second
  `lockdown=` value, `loglevel=8` and `root=fstab`, `tmpfs` and `gpt-auto`.
- R63-A01 to A04 accept `root=LABEL=`, `root=/dev/`, and the unit first or between two words.

The effective v3 README's Files paragraph lists every one-sided command-line negative as also breaking the binding, and
states the full overlap. Under the binding, the enrolled and maintenance grammar rules are equivalent. The
maintenance-target rule is implied by the twice-named rule (exactly one unit word), and also by the binding with
distinct command lines. So the maintenance-grammar and maintenance-target rules are reached first only by cases that
also break the binding, and no errata case pins either grammar rule alone on accept or refuse. All rules are kept.

Each mutant that round 6 named was replayed by the author. Here a case "flips" when it moves between refused and
accepted. No mutant accepts an adopted negative or refuses an adopted accepted case, and each flips at least one errata
case. Two mutants also change pinned refusal messages without flipping anything:
- all three rules off changes 20 adopted messages (V38, V47, V49, V52, V53, V57, V59-V66, V69, V70, V73-V76) and the
  errata messages of R63-02 and R63-04, which then refuse by the twice-named rule;
- lockdown off changes V38's message.

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

The merged MET-PERF-032 packet text is immutable. Its findings are answered by tighter checks, and each check below
states exactly what it covers. The PERF-032 layer's byte pins stay the guard beyond that. A later packet layer calls
the checks on its reviewed bytes:
- **F12**: route-test setup values may contain no lambda, generator or comprehension; no call whose final name is
  `map`, `filter`, `iter`, `zip`, `reversed`, `enumerate` or `partial`, bare or through any module (`builtins.map`,
  `functools.partial`); no call through `getattr`, `__import__`, `eval`, `exec`, `vars`, `globals` or `locals`; and no
  call whose target is itself computed (`__builtins__["map"](...)`). That is a closed list of constructs, not a proof
  that nothing defers. Every route call's receiver is a module alias, never a setup
  name. All 31 current route tests (806 calls) comply. The round-3 generator and `map` probes are refused.
- **F13** (wording): `unique()`'s docstring carries the one-frame caveat. The `check_grouped_module` docstring and its
  refusal message say "the sorted, grouped and kept paths", and the RecursionError fallback is pinned by bytes only. The
  two tests that match that message follow. The master-plan PERF-032 line carries the caveat. In the PERF-032 layer,
  `UNIQUE_SHA256` still holds, because a later bridge projects the current bytes back to the reviewed ones.
- **F14**: the stubbed model's exact set of Name ids and Attribute names is pinned by digest, so no new name or
  attribute can appear; the four round-3 escapes (`json.__builtins__`, `__loader__`, `__spec__`,
  `RefResolver.resolve_remote`) are refused. A function built only from existing symbols can still read a local file
  (round-1 C1-7); the model's history-chain byte pin fixes its behaviour.
- **F15**: the snapshot covers every value of every jsonschema, referencing and jsonschema_specifications module dict and
  of the classes they define, the Draft 2020-12 class dict and its VALIDATORS, by identity, and for every function among
  them its code, defaults, keyword defaults, attribute dict and closure cells, each module's own identity in
  `sys.modules`, and `_keywords.uniq is _utils.uniq`. Every identified object is kept alive during the check, so no
  identity can be reused, and identities are taken with the `id` bound at import. It is checked before the exec, after
  it and after a 773-array corpus. Every answer of the reviewed `unique`, and after the corpus every answer of stock
  uniqueItems' `uniq` and of a fresh stock Draft 2020-12 validator, must equal the stock answer computed before the
  exec. Refused: the round-3 `_keywords.uniq` and deferred `_utils.uniq` rebindings; the round-1 `__code__` swap, a
  rebinding after the 7th call and one triggered by a 3-item container; the round-3 address-reuse rebuild and
  `itertools.islice` patch; and the round-4 type-checker mutation, `builtins.id` patch and `sys.modules` swap. The check
  is a tripwire for these named changes, not a proof that the executed bytes cannot alter jsonschema: they run
  in-process with full Python access. Not excluded: a change the identity snapshot cannot see (in-place mutation of an
  object's internal state, replaced interpreter internals, a patched builtin) that leaves every corpus answer unchanged,
  and any change triggered by anything other than the exec and the corpus calls (a later call such as the 800th, a call
  count, time or an input outside the corpus). The PERF-032 layer's byte pin of the reviewed bytes is the guard.
- **C1-11**: the test module docstring of `tests/test_verify_headroom.py` and repository catalogue entry 82 carry the
  same caveat.

## Round-1 findings and dispositions

| Finding | Severity | Disposition |
|---|---|---|
| C1-1 `/.extra/credentials` also encrypted | MINOR | R6-1d now says that systemd v256 imports both stub-packed directories into the encrypted, untrusted directory, so both take effect only if they decrypt; SMBIOS and fw_cfg stay the plain sources |
| C1-2 bound pairs break two rules | MINOR | "break one rule each" replaced: the pairs no longer break the binding; the full overlap is stated (grammar rules equivalent under the binding, R63-02/R63-04 twice-named, target rule implied by the twice-named rule) in the effective v3 README and here |
| C1-3 meaning of "passes" and "flip" | MINOR | Both defined; the 20 and 1 adopted message changes and R63-02/R63-04 are listed. The author's mutant report now records message changes separately |
| C1-4 Python file published | MINOR | `check_errata` refuses a PUBLISHED entry for a Python file; Python rows are COMMENT_ONLY |
| C1-5 F15 identity only, 7 cases | MINOR | Function internals added to the snapshot; the state is re-checked after a 773-array corpus whose answers are computed before the exec; the remaining limit is stated |
| C1-6 SMBIOS string scope | NOTE | "a type #1 entry with a `linux` key" |
| C1-7 F14 composition | NOTE | Stated: the pin excludes new symbols, not compositions of existing ones; the byte pin fixes behaviour |
| C1-8 F12 closed list | NOTE | Docstring and README say "the listed constructs" |
| C1-9 added-vector digest unchecked | NOTE | `check_errata` checks `addedVectors` against its file |
| C1-10 syntax-tree equality admits layout | NOTE | COMMENT_ONLY also requires an equal token stream without comments and blank lines, so only comments, blank lines and spacing between tokens may change |
| C1-11 two more unqualified sentences | NOTE | Caveat added to the test module docstring and catalogue entry 82 |

## Round-2 findings and dispositions

| Finding | Severity | Disposition |
|---|---|---|
| C2-1 R63-02 and R63-04 cannot be bound | MINOR | Stated in both READMEs: the binding strips every unit word, so these two still break it and name the unit twice; R63-04 also breaks the maintenance grammar, R63-02 does not; "breaks both grammar rules" is limited to R63-03, R63-05 to R63-20 and R63-28 to R63-35. The R63-01 to R63-20 intents say which rules each pair breaks |
| C2-2 null-key credentials | MINOR | R6-1d adds that a credential sealed with systemd's null key decrypts unless the machine has a TPM2 and Secure Boot is on |
| C2-3 F15 limit | MINOR | The limit names everything outside the exec and the corpus calls (a later call, a call count, time, other inputs); the module docstring says the findings are answered by tighter checks that state their coverage |
| C2-4 replayed model bytes | NOTE | `replay_vectors` executes the model from the exact bytes it reads and checks (`native_model`), never an imported module |

## Round-3 findings and dispositions

| Finding | Severity | Disposition |
|---|---|---|
| C3-1 F15 address reuse and patches outside the snapshot | MINOR | Every identified object is kept alive during the check, and after the corpus stock uniqueItems' `uniq` must give every pre-exec answer; the address-reuse and `itertools.islice` probes are refused. The `builtins.sorted` probe passes within the limit, which round 4 restated in general terms (C4-1) |
| C3-2 R63-04 intent | NOTE | The intent now says that R63-04 also breaks the maintenance grammar |
| C3-3 `../` in the added-vector path | NOTE | `check_errata` also requires the path to be normalized |
| C3-4 F12 exact spelling | NOTE | Deferring calls are matched by final name through any module, and calls through `getattr`, `__import__`, `eval`, `exec`, `vars`, `globals` or `locals` or to a computed target are refused; the closed-list caveat stays |

## Round-4 findings and dispositions

| Finding | Severity | Disposition |
|---|---|---|
| C4-1 F15 limit misses three changes | MINOR | The type-checker mutation is refused by a fresh stock Draft 2020-12 validator's verdict on every corpus case after the corpus; the `builtins.id` patch by the `id` bound at import; the `sys.modules` swap by each module's own identity. The limit is restated in general terms (a tripwire for the named changes, not a proof; in-process changes the snapshot cannot see that leave every corpus answer unchanged, and later triggers, are not excluded) in the README, the module docstring and here. The round-4 type-checker probe limited to arrays of 40 or more items passes, within that limit |
| C4-2 F12 aliases and unlisted functions | NOTE | Within the closed-list caveat; no change |

## Not claimed

- No contract version, schema, rule or model changes. The adopted native-profile-v3 and I06 v2 directories and models
  stay byte-identical, and their status records keep their carried findings, which this record answers.
- No native, kernel, cluster or distribution observation. All E01-E12 stay OPEN_UNPROVEN.
- W02-PROD (primary lane, blocked on LIC-HOST and W05) owns the rule changes: a distinct `verityDigest` rule, the R3-3
  narrowing and any change to the v3 boot-entry rules.
