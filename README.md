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

Full shell work is machine-level access. Shell execution uses an explicit
executable and arguments, enforces the job deadline, terminates the process
tree through a guarded process group or Windows Job Object, and bounds aggregate
stdout and stderr.

## Artifacts

Remote artifact downloads require an exact HTTPS URL and reject redirects.
Local lifecycle commands copy a regular local file into private staging and may
pin its expected SHA-256 with `--sha256`. Both sources use the same bounded
copy, hash, manifest inspection, target validation, and activation pipeline.
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

## Builds and releases

CI runs the full test suite natively on Linux, macOS, and Windows, runs the Go
race detector on Linux, and uploads cross-compiled archives for Linux amd64,
arm64, and ARMv7 plus macOS and Windows amd64/arm64.

The `release` GitHub workflow validates the version in `version.go`, creates the
requested immutable tag, and publishes those archives with `SHA256SUMS` to a
GitHub Release. `publish-binaries` can republish an existing tag if release
uploading fails after tag creation.
