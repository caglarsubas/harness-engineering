# Zero-Bill Policy

The shipped platform, tenant workloads, provider bindings, live campaigns and
release acceptance must not create or consume anything that can produce a
cloud, GitHub, paid-provider, metered-provider, or third-party API-key bill.
This product admission rule remains absolute, not merely a default. A later
source-only [development-CI exception](docs/alpha-2/CI_CAPACITY_EXCEPTION.md)
permits an independently operator-authorized, disposable Linux guest solely
for one exact self-hosted PR check. It is not product infrastructure or an
authorization for repository code to provision cloud resources.

The external development-CI exception requires a separate owner's numeric
all-in charge maximum and a conservative lower preflight estimate. Count guest,
disk, IP, bounded egress, logs, monitoring, control-plane operations and the
independent delete watchdog through verified cleanup. Budget alerts are not
spend caps. Neither this policy source nor a queued check approves that cost.

Public-cloud and SaaS support means deployment onto infrastructure explicitly
supplied and operated by the adopter. The software never creates cloud accounts,
clusters, load balancers, DNS zones, object stores, GPUs, hosted databases, or
paid model/provider subscriptions.

Every provider and endpoint must be classified as
`SELF_HOSTED_OPEN_SOURCE_NON_METERED` or
`TENANT_SUPPLIED_OPEN_SOURCE_NON_METERED`. Unknown cost disposition, paid or
metered endpoints, external hosted-model providers, commercial API keys, cloud
billing APIs, and external telemetry exporters are rejected by the compiler and
runtime admission controls.

GitHub workflows use only self-hosted runners and store no Actions artifacts,
caches, packages, container images, LFS objects, or scheduled monitoring jobs.
Release artifacts are written to a tenant-owned OCI registry or an offline OCI
layout. Runtime defaults are offline, have an empty host allowlist, and contain
no required third-party API keys.

The public default branch is seeded before PR work so the pinned verification
workflow exists when GitHub evaluates a pull request. A credential-free self-hosted
runner with the complete locked wheelhouse/tool cache is a hard prerequisite.
Missing runner/tool custody blocks CI; no GitHub-hosted runner, cache, artifact,
package, or online dependency-fetch fallback is permitted.

The runner is ephemeral and credential/socket-free: it has no cloud/provider
credentials, SSH agent, kubeconfig, Docker or containerd control socket, or
other ambient broker that checked-out code could use to create a bill. Workflow
execution permits only the externally installed root-owned exact-job admission
hook and narrowly scoped verifier before checkout. They fail closed on a wrong
assignment, without treating labels as job proof. After the pinned credential-free
checkout, execution is restricted to the
preinstalled, root-owned `/opt/planeon/bin/harness-offline-launch`. Checked-out
shell, Python, Make, tests, and all other repository-controlled code begin only
after that host launcher establishes OS isolation. The workflow and host-launcher
installation require protected-owner review.

Manual post-merge live certification has a separate external boundary. The only
entry point is the preinstalled, root-owned
`/opt/planeon/bin/harness-live-campaign-launch`; checked-out
`ci/verify-live-campaign.sh` is an inner runner and cannot run directly. Before
opening credentials or executing repository code, the external launcher reads
only `HARNESS_LIVE_EXECUTION_ENVELOPE`; verifies independent `PLATFORM_RELEASE`
and `TENANT_LIVE_EXECUTION` signatures over the same RFC 8785 payload; checks
every immutable file, command, trust-store, and embedded endpoint digest; and
verifies the separate digest-bound `CAPACITY_OPERATOR` authorization. Release
and tenant trust are read only from
`/etc/planeon/trust/release-trust-bundle.json` and
`/etc/planeon/trust/tenant-trust-bundle.json`. The launcher establishes host OS
deny-all-except-envelope isolation and proves that the capacity-operator-owned
server-side zero-cost mutation policy is active and cannot be bypassed by the
campaign service account.

The mutation policy limits the campaign to named namespaces, identities, verbs,
GVKs, quotas, and preallocated resources. It rejects cloud/provider resources,
load balancers, dynamic storage, autoscaling, external DNS or artifacts,
external telemetry, runtime downloads, privilege/RBAC/admission/network-policy
escalation, and unknown cost disposition. Dynamic workloads are probed only
through embedded signed `KUBERNETES_API_PROXY` or `CAMPAIGN_PROXY` endpoints,
never discovered addresses. Tenant execution approval does not imply capacity
approval; the independent capacity signature remains required. Missing capacity is
`NOT_RUN_ENV_UNAVAILABLE`, while invalid authority or an attempted boundary
bypass is `FAIL`. No cloud or billing API is queried to infer safety. See
[`docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md`](docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md).

With `HARNESS_TASK_PACKET` set to a hash-pinned packet YAML path,
`["./ci/verify-offline.sh"]` establishes an OS-level network-denied sandbox or
namespace and passes an outbound-connect canary before executing the packet's
direct argv arrays. Local-cache-only prefetch and acceptance run in that same
isolated process tree. The runner removes credential/cloud variables and the
packet path from child environments and rechecks the packet digest after every
command. The single process tree enforces `UV_OFFLINE=1`,
`UV_FROZEN=1`, and `UV_NO_SYNC=1`; it fails when the host cannot prove that
boundary.

The protected runner also supplies every canonical warm-snapshot root through
newline-delimited `HARNESS_WARM_SOURCE_ROOTS` (`NONE` is permitted only when no
snapshot is mounted). The trusted launcher rejects malformed, overlapping, or
undeclared detected roots; macOS denies read/metadata/write access and Linux
Firejail blacklists and marks each root read-only. The value is removed before
any repository or packet child starts. A runner that cannot provide the complete
root set or the required filesystem backend is blocked.

## Executable admission and evidence

`python scripts/zero_bill_scan.py .` is the packet-owned static admission gate.
It validates the policy itself, the exact self-hosted workflow, the trusted-runner
manifest schema, and every provider-module cost disposition before scanning
deployable source and configuration surfaces. It rejects cloud provisioning,
hosted runners, GitHub storage services, paid or unknown providers, provider API
keys, mutable artifacts, runtime downloads, external telemetry, billing APIs,
and implicit network package execution. Documentation, task packets, and the
negative-fixture corpus are evidence inputs rather than deployable surfaces and
are not treated as implementations.

The manifest at `tests/fixtures/zero-bill/cases.yaml` has one independently
executed negative case for every entry in `forbiddenGithub` and
`forbiddenImplementation`. Tests require exact vector closure: adding a policy
prohibition without a matching negative case fails, as does a fixture that no
longer triggers its expected scanner rule.

A positive scan proves only static source admission for the scanned tree. CI,
merge, artifact, deployment, runtime, assurance, and tenant acceptance remain
separate evidence states. The scanner never queries a cloud provider, billing
API, hosted model, telemetry service, or package registry to infer safety.
