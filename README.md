# connectorhost

`airlock-host` is the mandatory local runtime for Airlock Go connectors. It
owns one Airlock host credential, multiplexes work to supervised connector child
processes, and keeps independent installations under an explicitly selected
state directory.

Connector children use the V1 framed stdin/stdout protocol from
`github.com/airlockrun/agentsdk/connector/protocol`. Connector stderr is written
to per-installation logs. The host does not install per-connector systemd,
launchd, or Windows service definitions.

Connector artifacts are trusted native code. They run with the same OS-user
privileges as `airlock-host`, so the child protocol isolates control flow but is
not a security sandbox. A connector can read or modify any same-user state,
including the host state directory and credential. Install artifacts only from
trusted Airlock builds and protect the host account as one trust domain.

## CLI

```text
airlock-host [--state-dir DIR] serve [--control-port PORT]
airlock-host [--state-dir DIR] enroll --airlock https://airlock.example
airlock-host [--state-dir DIR] access get
airlock-host [--state-dir DIR] access set full|update_only|none
airlock-host [--state-dir DIR] connector list
airlock-host [--state-dir DIR] connector status [ID] [--json]
airlock-host [--state-dir DIR] connector install ./connector [--name NAME] [--settings settings.json] [--sha256 HEX]
airlock-host [--state-dir DIR] connector update ID ./connector [--settings settings.json] [--sha256 HEX]
airlock-host [--state-dir DIR] connector rollback ID
airlock-host [--state-dir DIR] connector remove ID
airlock-host service install|start|stop|status|uninstall
airlock-host service enroll --airlock https://airlock.example
```

Each state root has an exclusive process lock. Run multiple host instances with
different `--state-dir` values and control ports. The serving process listens on
TCP4 `127.0.0.1:42927` by default and writes a private, authenticated runtime
descriptor under its state root. Local commands use that control endpoint first
and open the store directly only when no daemon owns it. State and connector records are atomically
written with private permissions. Artifacts live in
`connectors/<installation>/artifacts/<sha256>/`, child idempotency state lives in
`connectors/<installation>/state/`, and stderr logs live in `logs/`.

## Local access

The remote access mode defaults to `full` and is never changed by an Airlock
response. Local lifecycle commands are authorized by access to the host OS
account and state root, so they remain available in every mode.

Local lifecycle changes atomically write a bounded inventory outbox alongside
connector state. The host retries the latest mutation for each installation
until Airlock acknowledges its revision; removals remain as tombstones after
their connector directories are deleted. A new local installation enters
compact heartbeat only after its first inventory upsert is acknowledged.

- `full` allows remote shell, install, remove, update, and rollback.
- `update_only` allows update and rollback of existing installations.
- `none` rejects all remote management.
- Ordinary connector jobs and cancellations are independent of management mode.

Full shell work has all privileges of the host OS account. Managed installations
use the dedicated `airlock-host` account on Linux and the `AirlockHost` virtual
service account on Windows. Shell execution uses an explicit executable and
arguments, enforces the job deadline, terminates the process tree through a
guarded process group or Windows Job Object, and bounds aggregate stdout and
stderr.

## Artifacts

Remote artifact downloads require an exact HTTPS URL and reject redirects.
Local lifecycle commands copy a regular local file into private staging and may
pin its expected SHA-256 with `--sha256`. Both sources use the same bounded
copy, hash, manifest inspection, target validation, and activation pipeline.
When a managed service is running, the CLI streams the artifact over the
authenticated loopback control channel instead of requiring the service account
to read the invoking user's source path.
The host starts the candidate with its settings and requires a matching
readiness handshake before persisting it. Updates retain the prior binary,
manifest, settings, and storage origins as an A/B rollback slot. A failed
candidate restores and restarts the prior slot.

Windows starts connector and manifest processes suspended, assigns them to a
kill-on-close Job Object, and resumes the sole primary thread only after the
assignment succeeds. Cross-compilation verifies this Windows integration, but
Job Object assignment and suspended-thread resumption can only be exercised by
tests running on native Windows; builds without a native Windows test run retain
that runtime-verification limitation.

The V1 artifact input has no server signature field. Size and SHA-256 are the
mandatory verification boundary until the control-plane contract supplies a
signature and trust root.

## Control plane

The host uses bearer authentication and rejects redirects for all control-plane
requests under `/api/hosts/v1`: `sync`, `work/poll`, connector job events and
completion, inventory mutation, and management events and completion. Inventory
mutations use `/api/hosts/v1/connectors/inventory`, and acknowledged upserts
persist Airlock-authorized storage origins and restart the connector from that
persisted configuration while the host daemon remains available.
Enrollment uses
`/api/hosts/v1/enroll/device-code` and `/api/hosts/v1/enroll/complete`.

The host binary has no self-update path. Update `airlock-host` through the
machine's external package or service manager.

## Managed service installation

The `.deb` and `.rpm` packages install the release binary at
`/usr/bin/airlock-host`. They do not install, enable, start, or enroll the
managed service. Run the lifecycle explicitly after verifying the release
checksum:

```sh
sudo /usr/bin/airlock-host service install
sudo /usr/local/bin/airlock-host service start
sudo /usr/local/bin/airlock-host service enroll --airlock https://airlock.example
```

`service install` creates the dedicated account, machine state, and native
service definition, and copies the verified binary to its managed location. It
does not start the service. The running service waits for the explicit
`service enroll` flow before connecting to Airlock. After a package upgrade,
run `/usr/bin/airlock-host service install` again to copy the new binary into
the managed location, then restart the service explicitly.

`service uninstall` removes the systemd or Windows SCM registration but
intentionally preserves the managed binary and credential-bearing state. Delete
`/var/lib/airlock-host` or `%ProgramData%\Airlock\Host` separately only when the
host is being permanently decommissioned.

Windows ZIP archives contain `install-airlock-host.ps1`. Run it from an
elevated PowerShell session after verifying `SHA256SUMS`; it delegates native
registration and state ACL setup to `airlock-host service install` and does not
start or enroll the service. The script is also published as a separate release
artifact; place it beside the matching `airlock-host.exe` or pass
`-BinaryPath` explicitly.

The current release workflow does not Authenticode-sign the Windows executable
or PowerShell script. `SHA256SUMS` detects corruption after obtaining all files
from the same trusted GitHub Release, but it is not an independent publisher
signature.

The Linux packages are standalone GitHub Release assets, not an APT or RPM
repository, and this workflow does not package-sign them. Repository metadata
and signing are required before advertising package-manager update feeds.

Windows releases do not include an MSI. An MSI would require a pinned Windows
installer toolchain plus Authenticode signing for both the executable and final
installer. Shipping an unsigned MSI or hiding service registration in an
installer custom action would provide misleading trust and failure semantics.

## Builds and releases

CI runs the full test suite natively on Linux, macOS, and Windows, runs the Go
race detector on Linux, and uploads cross-compiled archives for Linux amd64,
arm64, and ARMv7 plus macOS and Windows amd64/arm64. It also builds `.deb` and
`.rpm` packages for every Linux architecture and validates package metadata,
archive contents, and checksums.

The `release` GitHub workflow validates the version in `version.go`, refuses to
reuse an existing tag, creates an annotated tag, and publishes those archives
with `SHA256SUMS` to a GitHub Release. `SHA256SUMS` covers archives, Linux
packages, and the Windows install script. `publish-binaries` can resume a draft
release after an upload failure, but it refuses to replace assets on a published
release.
