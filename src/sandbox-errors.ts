export type SandboxErrorCode =
  | "sandbox_timeout"
  | "sandbox_output_limit_exceeded"
  | "sandbox_unavailable"
  | "sandbox_policy_failure";

export type SandboxPhase =
  | "root_validation"
  | "root_view_prepare"
  | "runtime_validation"
  | "cgroup_setup"
  | "sandbox_spawn"
  | "command_execution";

export type SafeSandboxReason =
  | "root_validation_failed"
  | "root_validation_deadline_exceeded"
  | "root_view_deadline_exceeded"
  | "root_changed"
  | "nested_mount_detected"
  | "root_overlaps_blocked_path"
  | "runtime_validation_failed"
  | "runtime_validation_deadline_exceeded"
  | "runtime_overlaps_blocked_path"
  | "cgroup_controllers_failed"
  | "cgroup_root_missing"
  | "cgroup_root_invalid"
  | "cgroup_filesystem_invalid"
  | "cgroup_controllers_unavailable"
  | "cgroup_topology_invalid"
  | "cgroup_permission_denied"
  | "cgroup_read_only"
  | "cgroup_probe_failed"
  | "cgroup_create_failed"
  | "cgroup_memory_failed"
  | "cgroup_pids_failed"
  | "cgroup_cpu_failed"
  | "cgroup_attach_failed"
  | "cgroup_membership_failed"
  | "sandbox_spawn_failed"
  | "sandbox_pid_unavailable"
  | "sandbox_blocker_unavailable"
  | "sandbox_setup_failed"
  | "cgroup_setup_deadline_exceeded"
  | "sandbox_spawn_deadline_exceeded"
  | "command_deadline_exceeded"
  | "output_limit_exceeded";

export interface PublicSandboxError {
  error: SandboxErrorCode;
  phase: SandboxPhase;
  reason: SafeSandboxReason;
  retryable: boolean;
  timeout_ms?: number;
}

export class SandboxFailure extends Error {
  constructor(readonly publicError: PublicSandboxError, internalMessage?: string) {
    super(internalMessage ?? (publicError.error === "sandbox_unavailable"
      ? `${publicError.error}:${publicError.reason}`
      : publicError.error));
    this.name = "SandboxFailure";
  }
}

const unavailableReasons: Partial<Record<string, { phase: SandboxPhase; reason: SafeSandboxReason }>> = {
  sandbox_root_validation_failed: { phase: "root_validation", reason: "root_validation_failed" },
  cgroup_controllers_failed: { phase: "cgroup_setup", reason: "cgroup_controllers_failed" },
  cgroup_root_missing: { phase: "cgroup_setup", reason: "cgroup_root_missing" },
  cgroup_root_invalid: { phase: "cgroup_setup", reason: "cgroup_root_invalid" },
  cgroup_filesystem_invalid: { phase: "cgroup_setup", reason: "cgroup_filesystem_invalid" },
  cgroup_controllers_unavailable: { phase: "cgroup_setup", reason: "cgroup_controllers_unavailable" },
  cgroup_topology_invalid: { phase: "cgroup_setup", reason: "cgroup_topology_invalid" },
  cgroup_permission_denied: { phase: "cgroup_setup", reason: "cgroup_permission_denied" },
  cgroup_read_only: { phase: "cgroup_setup", reason: "cgroup_read_only" },
  cgroup_probe_failed: { phase: "cgroup_setup", reason: "cgroup_probe_failed" },
  cgroup_create_failed: { phase: "cgroup_setup", reason: "cgroup_create_failed" },
  cgroup_memory_failed: { phase: "cgroup_setup", reason: "cgroup_memory_failed" },
  cgroup_pids_failed: { phase: "cgroup_setup", reason: "cgroup_pids_failed" },
  cgroup_cpu_failed: { phase: "cgroup_setup", reason: "cgroup_cpu_failed" },
  cgroup_attach_failed: { phase: "cgroup_setup", reason: "cgroup_attach_failed" },
  cgroup_membership_failed: { phase: "cgroup_setup", reason: "cgroup_membership_failed" },
  sandbox_spawn_failed: { phase: "sandbox_spawn", reason: "sandbox_spawn_failed" },
  sandbox_pid_unavailable: { phase: "sandbox_spawn", reason: "sandbox_pid_unavailable" },
  sandbox_blocker_unavailable: { phase: "sandbox_spawn", reason: "sandbox_blocker_unavailable" },
  sandbox_setup_failed: { phase: "sandbox_spawn", reason: "sandbox_setup_failed" },
};

const permanentUnavailableReasons = new Set<SafeSandboxReason>([
  "cgroup_root_missing",
  "cgroup_root_invalid",
  "cgroup_filesystem_invalid",
  "cgroup_controllers_unavailable",
  "cgroup_topology_invalid",
  "cgroup_permission_denied",
  "cgroup_read_only",
]);

const policyReasons: Partial<Record<string, { phase: SandboxPhase; reason: SafeSandboxReason; retryable: boolean }>> = {
  sandbox_root_changed: { phase: "root_view_prepare", reason: "root_changed", retryable: true },
  sandbox_root_contains_nested_mount: { phase: "root_view_prepare", reason: "nested_mount_detected", retryable: false },
  sandbox_root_overlaps_blocked_path: { phase: "root_validation", reason: "root_overlaps_blocked_path", retryable: false },
  sandbox_runtime_validation_failed: { phase: "runtime_validation", reason: "runtime_validation_failed", retryable: false },
  sandbox_runtime_overlaps_blocked_path: { phase: "runtime_validation", reason: "runtime_overlaps_blocked_path", retryable: false },
};

export function publicSandboxError(
  error: unknown,
  context: { phase: SandboxPhase; timeoutMs?: number; fallbackPhase?: SandboxPhase },
): PublicSandboxError {
  if (error instanceof SandboxFailure) {
    return error.publicError.error === "sandbox_timeout"
      && error.publicError.timeout_ms === undefined
      && context.timeoutMs !== undefined
      ? { ...error.publicError, timeout_ms: context.timeoutMs }
      : error.publicError;
  }
  const message = error instanceof Error ? error.message : "";
  if (message === "sandbox_timeout" || message === "sandbox_private_key_scan_failed") {
    const phase = message === "sandbox_private_key_scan_failed" ? "root_view_prepare" : context.phase;
    const timeoutReason: SafeSandboxReason = phase === "root_validation" ? "root_validation_deadline_exceeded"
      : phase === "root_view_prepare" ? "root_view_deadline_exceeded"
        : phase === "runtime_validation" ? "runtime_validation_deadline_exceeded"
          : phase === "cgroup_setup" ? "cgroup_setup_deadline_exceeded"
            : phase === "sandbox_spawn" ? "sandbox_spawn_deadline_exceeded"
              : "command_deadline_exceeded";
    return {
      error: "sandbox_timeout",
      phase,
      reason: timeoutReason,
      retryable: true,
      ...(context.timeoutMs === undefined ? {} : { timeout_ms: context.timeoutMs }),
    };
  }
  if (message === "sandbox_output_limit_exceeded") {
    return {
      error: "sandbox_output_limit_exceeded",
      phase: "command_execution",
      reason: "output_limit_exceeded",
      retryable: false,
    };
  }
  const policy = policyReasons[message];
  if (policy) return { error: "sandbox_policy_failure", ...policy };
  const unavailableKey = message.startsWith("sandbox_unavailable:")
    ? message.slice("sandbox_unavailable:".length)
    : message;
  const unavailable = unavailableReasons[unavailableKey];
  if (unavailable) {
    const retryable = !permanentUnavailableReasons.has(unavailable.reason);
    return { error: "sandbox_unavailable", ...unavailable, retryable };
  }
  return {
    error: "sandbox_unavailable",
    phase: context.fallbackPhase ?? "sandbox_spawn",
    reason: "sandbox_setup_failed",
    retryable: true,
  };
}
