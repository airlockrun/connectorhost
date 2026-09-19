# Connector Host Invariants

- `airlock-host` alone sends host credentials. Enrollment uses HTTPS; runtime control uses one outbound authenticated WSS session with the explicit `airlock.host.v2` protocol.
- Heartbeat/lease renewal and inventory run independently of capacity-driven work delivery. Connector stdout writes a bounded durable output queue, never the network. Preserve exact outcome replay and fail loudly on local persistence failures.
- Connector artifacts are trusted native code running as the host OS user. The child-process protocol is not an OS security boundary, and connectors can inspect same-user host state.
- Connector binaries are Go child processes using the SDK V1 framed protocol.
- A state root is single-process and independent from every other state root.
- Each nonempty contract ID occupies one installation per state root, independent of artifact version or readiness. Admission precedes activation; removal releases the slot only after the child stops. Duplicate persisted contracts prevent startup with an actionable error.
- An installation ID awaiting removal acknowledgement cannot be reused. Admission and persistence preserve its removal tombstone; replacement installs use a new ID.
- Remote responses cannot modify the locally persisted access mode.
- Unenrollment is an explicit destructive local reset. It stops managed service work and deletes the host identity, connectors, artifacts, child state, and queued outcomes; ordinary service uninstall and package removal preserve them.
- Remote access defaults to `full` (shell and all connector lifecycle operations). `manage` permits install, update, rollback, and remove without shell, including removal of an already absent installation. `updates` permits only update and rollback of existing installations; `none` permits no remote management. Unknown modes and operations fail closed.
- Local connector lifecycle commands remain available in every access mode.
- Connector jobs are not management work and remain allowed in every access mode.
- Artifact activation requires exact HTTPS, size, SHA-256, manifest, and readiness verification.
- Updates retain a complete prior artifact and settings slot; the host has no self-update feature.
- Do not add per-connector system service installation or standalone connector polling.
