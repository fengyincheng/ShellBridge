# Implementation defaults

These are the conservative details chosen during implementation. They do not change the security boundary frozen by the ADRs.

- The root-managed service never evaluates client shell directly on the host; generic shell text enters Bubblewrap.
- Generic diagnostics use a non-root UID/GID, NoNewPrivileges, zero capabilities, new user/PID/proc/network namespaces, read-only fd mounts, private temporary filesystems, network and Unix-socket seccomp, cgroup limits, and rlimits.
- When `read_scope` is omitted, the default read view is the configured read root (`/root` in the standard root-managed deployment), presented read-only at its original paths. There is no project allowlist, and directories are not excluded wholesale by names such as hidden, cache, tmp, log, state, or config. Project diagnostics should set one absolute `read_scope`; that mode mounts only the named directory, requires `cwd` to lie inside it, and never widens to sibling projects or external dependencies. In both modes, exact deny rules and object/content checks hide credentials, login sessions, control sockets, real `.env` files, PEM private keys, ShellBridge database files, and administrator-registered sensitive paths.
- Command timeout defaults to 60 seconds, output to 32 KiB, HTTP request bodies to 256 KiB, and proposal lifetime to 10 minutes.
- Every generic shell call prepares the safety view for the current read range. An explicit project scope walks only that project plus the globally registered sensitive-object set; only an omitted `read_scope` prepares the full root-wide view. `cwd` only changes the working directory. Startup readiness performs a light root validation and does not repeat the full scan that the first real request must do.
- Sandbox failures expose only a fixed allowlist of `error` / `phase` / `reason` / `retryable`. Logs record phase timings and allowlisted outcomes, never command text, raw helper or bwrap stderr, or arbitrary exception text.
- A transient readiness failure marks `sandboxed_read_shell` as `degraded` and retries the real sandbox serially on later requests. It never falls back to a host shell. `/health` reports process liveness and that capability state separately.
- Proposal payloads are sealed with AES-256-GCM in SQLite WAL storage and belong to one stable owner principal.
- TOTP, remote Git, package modification, general network access, and opaque host code execution are not implemented.
- All write capabilities are controlled by a total local switch plus capability-specific switches, and every switch defaults to off.
- Generic shell validates only length, NUL, timeout, and output limits. It does not use a command allowlist or a restricted AST; the security boundary acts on mounts, privileges, network, and resources.
- Sensitive configuration is read only through `inspect_config` registered targets and field selectors, and string values must also match the locally registered target+selector disclosure policy. Credential fields always return status only, and a parse failure never returns the original text.
- OpenAPI consequential annotations express client expectations only. The backend always rechecks authentication, capability state, proposal integrity, expiry, and exact frozen state.
