# MCP interface

ChatGPT connects to ShellBridge over Streamable HTTP MCP at:

```text
https://shellbridge.example.com/mcp
```

The public URL is configured by `SHELLBRIDGE_PUBLIC_BASE_URL`. OAuth issuer, protected-resource metadata, and the MCP resource are derived from the same value.

Read-only tools include general sandboxed shell commands and batches, registered configuration inspection, disposable project tasks, local Git status, and proposal inspection. The shell supports full Bash syntax but sees only the configured read-only view. When inspecting one specific project, set an absolute `read_scope` on the command or batch item: the service mounts only that single directory, requires the resolved `cwd` to lie inside it, rejects a symlink scope, and never widens to sibling projects or external dependencies. Omitting `read_scope` preserves the compatibility behaviour of the configured full read root; in that mode `cwd` only changes the working directory and does not narrow the root-wide safety-view preparation. Either way, credentials, login sessions, real `.env` files, private keys, control sockets, and the ShellBridge database and key paths are masked. Inside a project scope, `.env` files, private keys, escaping links, and hard-link aliases of registered sensitive objects outside the scope stay masked as well. The shell cannot observe host PIDs, host network state, the systemd control plane, or PM2 control sockets, and it never creates a proposal. Sensitive configuration structure must go through `inspect_config`.

Persistent tools cover restricted Markdown/TXT files, local Git index changes, exact local commits, and pre-existing scripts. The total write switch and relevant capability switch must be enabled locally.

`execute_proposal` accepts only an `approval_id`. The proposal is an immutable execution plan and replay-control record, not a server-hosted approval UI. A client should show its normal confirmation UI and must stop on refusal.

OAuth supports dynamic public-client registration, Authorization Code with PKCE S256, state, RFC 8707 resource binding, `offline_access`, and refresh-token rotation. The owner consent page uses a separate secret and restricts redirects to configured hosts. Tokens are stored as SHA-256 digests, and OAuth audit records never contain token material.

Tool annotations are client hints. Enforcement remains server-side through authentication, local kill switches, typed inputs, exact path policy, read-only mounts, namespaces, seccomp, cgroup/rlimit, openat2, output redaction, and proposal validation.

## Session lifecycle

ShellBridge retains at most 64 MCP sessions by default, with a one-hour idle TTL. The limit protects genuinely concurrent sessions: at capacity the service first closes the least recently used idle session, instead of letting historical clients that never send `DELETE /mcp` hold a slot indefinitely. Only when every retained session is in flight or awaiting initialization does a new initialize return `MCP session limit reached` (429).

Besides the check before each new request, a background collector reclaims idle sessions. A normal `DELETE /mcp`, a request error, a client disconnect before the response completes, and service shutdown all run explicit cleanup. Tune the limit and TTL with `SHELLBRIDGE_MCP_SESSION_LIMIT` and `SHELLBRIDGE_MCP_SESSION_TTL_MS`; both must be positive integers.

Production logs carry structured `component=mcp_session` lifecycle events such as `initialized`, `request_started`, `request_finished`, `client_closed`, `closing`, `closed`, `limit_reached`, and `invalid_session`. Each record includes retained/active/idle/pending counts, and sessions are identified only by a short SHA-256 fingerprint — never the full session ID, an OAuth token, or a Bearer credential.

## Sandbox invocation and recovery contract

Every `run_shell_command` creates a fresh read-only Bubblewrap. With `read_scope` set, only the project scope is walked and mounted. Ordinary files outside the scope do not add to that project's scope-walk cost, although the global inode verification of registered sensitive objects can still cost separately. Only when `read_scope` is omitted does the service prepare the full root-wide safety view.

`run_shell_batch` is for a definite list of commands that each need independent, sequential isolation. It is not a performance batch: every item gets a fresh sandbox and repeats safety-view preparation, so when the commands can safely share one diagnostic shell, prefer `run_shell_command`.

Sandbox failures return `error`, `phase`, `reason`, and `retryable` from a fixed allowlist, plus `timeout_ms` where a timeout applies. `retryable=true` means an agent may reasonably retry while reducing concurrency and keeping the same security boundary; `retryable=false` means stop retrying and report the specific policy failure. The service never returns raw helper or bwrap stderr, arbitrary exception text, or sensitive paths.
