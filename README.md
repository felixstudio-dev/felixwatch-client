# Felix Watch Client — source preview candidate

This is an unreleased source preview for review. No supported package, public
installation command, operational provisioning endpoint or production readiness
is claimed. Do not supply real credentials to the offline preparation tools.
Publication of this candidate, a distribution license, version admission and
support dates remain subject to explicit decisions. Visibility alone does not
grant an open-source license.

## Included components

- Native Go monitoring agent and its required config/protocol packages and tests.
  Shared config declarations include server-side types; no collector server is
  included. Monitoring does not confer restart, SSH, deploy or remediation rights.
- Offline Python package/config verification, retained-byte preparation,
  protected synthetic input checks and draft provisioning-consumer tests.
- A bounded Linux benchmark harness used by the agent's tests.
- Distribution, compatibility, support and security policy candidates.

The module path is adapted for this separate Client repository. The source set
has no third-party Go modules or Python packages. `SOURCE-FILES.sha256` describes
these bytes; checksums do not constitute authentication or release approval.
No private history, operational evidence, CI workflow, binary, installer,
service unit, configuration with credentials or hosting probe is included.

## Native runtime and future installation

The Go agent is intended to run natively on Linux. Docker is not a customer
runtime prerequisite. A container is currently required only by the separate
private lifecycle test harness. Full installation/removal/rollback validation
and physical host compatibility remain open.

The intended installation experience is one command without secrets, followed
by a protected key prompt. That command is not yet published. The current
`tools/prepare_native.py` only checks retained candidate bytes/configuration and
optionally a synthetic key's input format; it never installs or authenticates.
Its successful preparation exit status is 3 with installation/provisioning HELD.
It refuses unprotected input. Do not put credentials in arguments, history,
logs, examples or issue reports. Best-effort memory cleanup is not guaranteed
memory erasure.

FAC owns issuance, custody, rotation, revocation and provisioning. The offline
consumer does not authenticate a server or a token. Live/Test, tenant, scope,
expiry and revocation require an admitted server-enforced contract. A service
API key is distinct from the heartbeat HMAC secret. No issuer, vault, broker,
panel or operational FAC endpoint is supplied here.

## Developer checks (no installation)

With compatible Go and Python already installed, the source-only checks are:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test ./...
python3 -B -m unittest discover -s tools -p 'test_*.py'
```

On Linux, Go tests also require readable `/proc`, a POSIX `sh`, and the
benchmark's existing utilities: `awk`, `cat`, `date`, `find` with `-printf`,
`getconf`, `sleep`, `wc` and standard file utilities. Minimal images without
these tools are not a supported test environment; no automatic install occurs.
Python 3.10+ is required by the complete offline suite. The prompt tests require
a POSIX terminal environment and must be qualified separately. Tests use
synthetic fixtures; Go tests use local loopback test servers. Passing these
checks is not installation, FAC integration, lifecycle or physical acceptance.

See [release process](RELEASE_PROCESS.md), [compatibility](COMPATIBILITY.md),
[versioning](VERSIONING.md), [support](SUPPORT_POLICY.md),
[security](SECURITY.md) and [changelog](CHANGELOG.md).
