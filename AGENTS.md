# Connector Host Invariants

- `airlock-host` is the only component that sends host credentials or control-plane HTTP.
- Connector artifacts are trusted native code running as the host OS user. The child-process protocol is not an OS security boundary, and connectors can inspect same-user host state.
- Connector binaries are Go child processes using the SDK V1 framed protocol.
- A state root is single-process and independent from every other state root.
- Remote responses cannot modify the locally persisted access mode.
- Connector jobs are not management work and remain allowed in every access mode.
- Artifact activation requires exact HTTPS, size, SHA-256, manifest, and readiness verification.
- Updates retain a complete prior artifact and settings slot; the host has no self-update feature.
- Do not add per-connector system service installation or standalone connector polling.
