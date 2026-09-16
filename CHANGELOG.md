# Changelog

## 0.4.0

- Added an optional absolute `read_scope` to `run_shell_command` and `run_shell_batch`. A project diagnostic can now mount one directory instead of the whole read root. The scope is validated server-side: it must be a real directory, stable under `realpath`, inside the configured sandbox read roots, non-overlapping with blocked paths, and it must contain the resolved `cwd`. Omitting it preserves the previous full read-root behaviour.
- Added a structured sandbox failure contract. Failures now report `error`, `phase`, `reason`, and `retryable` from a fixed allowlist, with phases covering root validation, root-view preparation, runtime validation, cgroup setup, spawn, and command execution. Permanent environment faults such as a missing cgroup root are no longer marked retryable as timeouts, so clients stop retrying what cannot succeed.
- Added cgroup v2 readiness validation. The sandbox root is now checked for the cgroup2 magic, the required `cpu`/`memory`/`pids` controllers, an empty `cgroup.procs`, and a verified `subtree_control` write before any command is admitted.
- Added recoverable sandbox capability state. A transient startup failure marks `sandboxed_read_shell` as `degraded` instead of permanently replacing the runner; `/health` reports that state and later requests retry only the real fail-closed sandbox.
- Hardened MCP session lifecycle. Sessions are garbage-collected in the background, capacity is enforced by evicting the least recently used idle session rather than rejecting new clients outright, and disconnects and shutdown run explicit cleanup. Limits and TTL are configurable through `SHELLBRIDGE_MCP_SESSION_LIMIT` and `SHELLBRIDGE_MCP_SESSION_TTL_MS`.
- Hardened the root read view against time-of-check/time-of-use race conditions. The prepared view is snapshotted and re-verified through `/proc/self/fd` before the sandbox is spawned, and blocked-inode collection opens with `O_NOFOLLOW` and re-checks identity.
- Changed the default command timeout from 15 seconds to 60 seconds so that root-wide safety-view preparation fits inside the default budget.
- Batches now report a failed item's index and the completed results instead of collapsing the whole batch into an unavailable error.

## 0.3.0 - Public Preview

- Added Streamable HTTP MCP with Bearer authentication and single-owner OAuth.
- Added read-only, network-isolated Bubblewrap diagnostics with exact sensitive-resource masking.
- Added registered configuration reads with mandatory secret redaction.
- Added disposable project tasks, restricted text-document operations, and local Git operations.
- Added immutable, encrypted proposals for local commits and pre-existing side-effecting scripts.
- Added conservative local write kill switches, all disabled by default.
- Added Linux x86_64 platform checks, systemd templates, preflight diagnostics, CI, and public security documentation.
