# Implementation status

Implemented and covered by ordinary or privileged tests: Bearer/OAuth authentication; full Bash syntax in a read-only Bubblewrap view, both in the compatibility full-root view and in an explicit project read scope; exact credential, session, `.env`, private-key, socket, escaping-link, database, and registered-path masking; non-root execution; NoNewPrivileges; empty capabilities; PID/proc/network namespaces; network and Unix-socket seccomp; fixed-object fd mounts; cgroup/rlimit/timeout/output limits; registered configuration selection; and disposable project tasks. Generic shell never creates a write proposal.

Implemented persistent capabilities: atomic Markdown/TXT create, replace, patch, and move; local Git status, stage, unstage, and frozen commit proposals; and frozen pre-existing script execution with cancellation and replay prevention. All remain subject to local kill switches.

Sandbox commands, batches, project tasks, and MCP now share one structured error contract that distinguishes root validation, root-view preparation, runtime validation, cgroup setup, spawn, and command execution. A readiness failure no longer replaces the shell runner permanently: `/health` reports `sandboxed_read_shell` as `ready` or `degraded`, and later requests retry only the real fail-closed sandbox. Runtime logs carry phase timings and allowlisted outcomes, never command text or raw underlying errors.

Not implemented: push, pull, fetch, remote changes, arbitrary host-write shell, generic shell write proposals, source/configuration structured edits, package changes, active deployment, or service management.
