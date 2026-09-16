import { spawn, type ChildProcess } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import { mkdir, readFile, rmdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { redact } from "./redactor.js";
import { createRootReadViewPlan, PrivateKeyIndex, verifyRootReadViewPlan, type RootViewEntry } from "./root-read-view.js";
import { publicSandboxError, SandboxFailure, type PublicSandboxError, type SandboxPhase } from "./sandbox-errors.js";

export interface SandboxObservation {
  outcome: "completed" | "failed";
  profile: SandboxProfile;
  read_scope_mode: "global" | "explicit";
  total_ms: number;
  root_validation_ms?: number;
  root_view_prepare_ms?: number;
  root_view_verify_ms?: number;
  blocked_targets_scanned?: number;
  runtime_validation_ms?: number;
  cgroup_setup_ms?: number;
  spawn_to_ready_ms?: number;
  command_execution_ms?: number;
  protected_files_scanned?: number;
  protected_directories_scanned?: number;
  protected_inodes_collected?: number;
  scope_files_scanned?: number;
  scope_directories_scanned?: number;
  private_key_cache_hits?: number;
  private_key_cache_misses?: number;
  rewrite_parents?: number;
  rewrite_entries?: number;
  protected_scan_ms?: number;
  scope_walk_ms?: number;
  rewrite_ms?: number;
  error?: PublicSandboxError["error"];
  phase?: PublicSandboxError["phase"];
  reason?: PublicSandboxError["reason"];
}

type SandboxTimings = Omit<SandboxObservation, "outcome" | "profile" | "read_scope_mode" | "total_ms" | "error" | "phase" | "reason">;

interface SandboxedShellOptions {
  helperPath: string;
  seccompPath: string;
  bwrapPath: string;
  readRoots: string[];
  blockedPaths: string[];
  observerUid: number;
  observerGid: number;
  cgroupRoot: string;
  requireCgroup: boolean;
  setupPhaseTimeoutMs?: number;
  observe?: (observation: SandboxObservation) => void;
}

export interface SandboxedShellResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  truncated: boolean;
}

export interface SandboxRunRequest {
  command: string;
  cwd: string;
  readScope?: string;
  timeoutMs: number;
  maxOutputBytes: number;
  profile?: SandboxProfile;
}

export type SandboxProfile = "diagnostic" | "project_task";

const sandboxRequestErrorCodes = new Set([
  "invalid_command",
  "invalid_timeout",
  "invalid_output_limit",
  "cwd_outside_sandbox_roots",
  "read_scope_invalid",
  "read_scope_outside_sandbox_roots",
  "read_scope_overlaps_blocked_path",
]);

export function isSandboxRequestError(error: unknown): boolean {
  return error instanceof Error && sandboxRequestErrorCodes.has(error.message);
}

const runtimeSources = [
  "/usr",
  "/opt/node-v22.11.0-linux-x64",
  "/etc/ld.so.cache",
  "/etc/passwd",
  "/etc/group",
  "/etc/nsswitch.conf",
  "/etc/hosts",
  "/etc/localtime",
  "/etc/alternatives",
];

function inside(target: string, root: string): boolean {
  return target === root || target.startsWith(`${root}${path.sep}`);
}

function resolveExplicitReadScope(requested: string, roots: string[]): string {
  if (!path.isAbsolute(requested) || requested.includes("\0")) throw new Error("read_scope_invalid");
  const lexical = path.resolve(requested);
  let metadata: fs.Stats;
  try { metadata = fs.lstatSync(lexical); } catch { throw new Error("read_scope_invalid"); }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error("read_scope_invalid");
  let canonical: string;
  try { canonical = fs.realpathSync(lexical); } catch { throw new Error("read_scope_invalid"); }
  if (canonical !== lexical) throw new Error("read_scope_invalid");
  if (!roots.some((root) => inside(canonical, root))) throw new Error("read_scope_outside_sandbox_roots");
  return canonical;
}

function resolveBlockedPaths(targets: string[]): string[] {
  return targets.map((target) => {
    const resolved = path.resolve(target);
    try { return fs.realpathSync(resolved); } catch { return resolved; }
  });
}

function validateRootFd(helperPath: string, rootFd: number, parentFd: number, filesystemFd: number, rootName: string, timeoutMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(helperPath, ["validate-tree-fd", rootName], {
      env: {},
      stdio: ["ignore", "ignore", "pipe", rootFd, parentFd, filesystemFd],
    });
    let stderrBytes = 0;
    child.stderr?.on("data", (chunk: Buffer) => {
      stderrBytes += chunk.length;
      if (stderrBytes > 16 * 1024) child.kill("SIGKILL");
    });
    let settled = false;
    let timer: NodeJS.Timeout;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve();
    };
    child.once("error", () => finish(new Error("sandbox_root_validation_failed")));
    child.once("exit", (code) => finish(code === 0 ? undefined : new Error("sandbox_root_validation_failed")));
    timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(new Error("sandbox_timeout"));
    }, timeoutMs);
  });
}

function validateRuntimeDisjointFds(
  helperPath: string,
  runtimeFds: number[],
  blockedFds: number[],
  timeoutMs: number,
): Promise<void> {
  if (runtimeFds.length === 0 || blockedFds.length === 0) return Promise.reject(new Error("sandbox_runtime_validation_failed"));
  return new Promise((resolve, reject) => {
    const child = spawn(
      helperPath,
      ["validate-disjoint-fds", String(runtimeFds.length), String(blockedFds.length)],
      { env: {}, stdio: ["ignore", "ignore", "pipe", ...runtimeFds, ...blockedFds] },
    );
    let settled = false;
    let timer: NodeJS.Timeout;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve();
    };
    child.once("error", () => finish(new Error("sandbox_runtime_validation_failed")));
    child.once("exit", (code) => finish(code === 0 ? undefined : new Error("sandbox_runtime_validation_failed")));
    timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(new Error("sandbox_timeout"));
    }, timeoutMs);
  });
}

function directoryArguments(target: string): string[] {
  const parts = target.split(path.sep).filter(Boolean);
  const result: string[] = [];
  let current = "";
  for (const part of parts) {
    current += `/${part}`;
    result.push("--dir", current);
  }
  return result;
}

function cgroupSignal(deadlineMs: number): AbortSignal {
  const remainingMs = deadlineMs - Date.now();
  if (remainingMs <= 0) throw new Error("sandbox_timeout");
  return AbortSignal.timeout(remainingMs);
}

function cgroupErrno(error: unknown): string {
  return error && typeof error === "object" && "code" in error
    ? String((error as NodeJS.ErrnoException).code)
    : "";
}

function cgroupFailure(error: unknown, code: string, deadlineMs: number): Error {
  if (Date.now() >= deadlineMs
      || (error instanceof Error && (error.name === "AbortError" || error.name === "TimeoutError"))) {
    return new Error("sandbox_timeout");
  }
  const errno = cgroupErrno(error);
  if (errno === "EACCES" || errno === "EPERM") return new Error("cgroup_permission_denied");
  if (errno === "EROFS") return new Error("cgroup_read_only");
  return new Error(code);
}

async function cgroupWrite(target: string, value: string, code: string, deadlineMs: number): Promise<void> {
  try {
    await writeFile(target, value, { signal: cgroupSignal(deadlineMs) });
  } catch (error) {
    throw cgroupFailure(error, code, deadlineMs);
  }
}

async function cgroupRead(target: string, code: string, deadlineMs: number): Promise<string> {
  try {
    return await readFile(target, { encoding: "utf8", signal: cgroupSignal(deadlineMs) });
  } catch (error) {
    throw cgroupFailure(error, code, deadlineMs);
  }
}

const cgroup2SuperMagic = 0x63677270;
const requiredCgroupControllers = ["cpu", "memory", "pids"] as const;

async function validateCgroupRoot(root: string, deadlineMs: number): Promise<void> {
  let metadata: fs.Stats;
  try {
    metadata = fs.lstatSync(root);
  } catch (error) {
    const errno = cgroupErrno(error);
    if (errno === "ENOENT") throw new Error("cgroup_root_missing");
    throw cgroupFailure(error, "cgroup_root_invalid", deadlineMs);
  }
  if (!metadata.isDirectory()) throw new Error("cgroup_root_invalid");
  try {
    if (fs.statfsSync(root).type !== cgroup2SuperMagic) throw new Error("cgroup_filesystem_invalid");
  } catch (error) {
    if (error instanceof Error && error.message === "cgroup_filesystem_invalid") throw error;
    throw cgroupFailure(error, "cgroup_filesystem_invalid", deadlineMs);
  }

  const controllers = await cgroupRead(path.join(root, "cgroup.controllers"), "cgroup_root_invalid", deadlineMs);
  if (requiredCgroupControllers.some((controller) => !controllers.split(/\s+/).includes(controller))) {
    throw new Error("cgroup_controllers_unavailable");
  }
  const processes = await cgroupRead(path.join(root, "cgroup.procs"), "cgroup_root_invalid", deadlineMs);
  if (processes.trim()) throw new Error("cgroup_topology_invalid");
  await cgroupWrite(path.join(root, "cgroup.subtree_control"), "+cpu +memory +pids", "cgroup_controllers_failed", deadlineMs);
  const enabled = await cgroupRead(path.join(root, "cgroup.subtree_control"), "cgroup_root_invalid", deadlineMs);
  if (requiredCgroupControllers.some((controller) => !enabled.split(/\s+/).includes(controller))) {
    throw new Error("cgroup_controllers_failed");
  }
}

async function configureCgroup(root: string, pid: number, profile: SandboxProfile, deadlineMs: number): Promise<string> {
  await validateCgroupRoot(root, deadlineMs);
  if (Date.now() >= deadlineMs) throw new Error("sandbox_timeout");
  const job = path.join(root, `job-${pid}-${crypto.randomUUID()}`);
  try {
    await mkdir(job, { mode: 0o700 });
  } catch (error) {
    throw cgroupFailure(error, "cgroup_create_failed", deadlineMs);
  }
  try {
    if (Date.now() >= deadlineMs) throw new Error("sandbox_timeout");
    await cgroupWrite(path.join(job, "memory.max"), profile === "project_task" ? "2147483648" : "268435456", "cgroup_memory_failed", deadlineMs);
    await cgroupWrite(path.join(job, "pids.max"), profile === "project_task" ? "512" : "64", "cgroup_pids_failed", deadlineMs);
    await cgroupWrite(path.join(job, "cpu.max"), profile === "project_task" ? "200000 100000" : "100000 100000", "cgroup_cpu_failed", deadlineMs);
    await cgroupWrite(path.join(job, "cgroup.procs"), String(pid), "cgroup_attach_failed", deadlineMs);
    let membership: string;
    try {
      membership = await readFile(`/proc/${pid}/cgroup`, { encoding: "utf8", signal: cgroupSignal(deadlineMs) });
    } catch (error) {
      throw cgroupFailure(error, "cgroup_membership_failed", deadlineMs);
    }
    if (!membership.includes(path.basename(job))) throw new Error("cgroup_membership_failed");
    return job;
  } catch (error) {
    await cleanupCgroup(job);
    throw error;
  }
}

function waitForSpawn(child: ChildProcess, deadlineMs: number): Promise<void> {
  if (child.pid) return Promise.resolve();
  return new Promise((resolve, reject) => {
    let timer: NodeJS.Timeout | undefined;
    const finish = (error?: Error) => {
      if (timer) clearTimeout(timer);
      child.removeListener("spawn", onSpawn);
      child.removeListener("error", onError);
      if (error) reject(error);
      else resolve();
    };
    const onSpawn = () => finish();
    const onError = () => finish(new Error("cgroup_probe_failed"));
    child.once("spawn", onSpawn);
    child.once("error", onError);
    const remainingMs = deadlineMs - Date.now();
    if (remainingMs <= 0) {
      finish(new Error("sandbox_timeout"));
      return;
    }
    timer = setTimeout(() => finish(new Error("sandbox_timeout")), remainingMs);
  });
}

function waitForExit(child: ChildProcess, deadlineMs: number): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    let timer: NodeJS.Timeout | undefined;
    const finish = () => {
      if (timer) clearTimeout(timer);
      child.removeListener("exit", finish);
      child.removeListener("error", finish);
      resolve();
    };
    child.once("exit", finish);
    child.once("error", finish);
    const remainingMs = Math.max(1, deadlineMs - Date.now());
    timer = setTimeout(finish, remainingMs);
  });
}

async function probeCgroup(root: string, deadlineMs: number): Promise<void> {
  const child = spawn("/bin/sh", ["-c", "read -r _; true"], {
    detached: true,
    env: {},
    stdio: ["pipe", "ignore", "ignore"],
  });
  let job: string | undefined;
  try {
    await waitForSpawn(child, deadlineMs);
    if (!Number.isInteger(child.pid) || Number(child.pid) <= 0) throw new Error("cgroup_probe_failed");
    job = await configureCgroup(root, Number(child.pid), "diagnostic", deadlineMs);
    if (!child.stdin || typeof child.stdin.end !== "function") throw new Error("cgroup_probe_failed");
    child.stdin.end("probe\n");
    await waitForExit(child, deadlineMs);
    if (child.exitCode !== 0) throw new Error("cgroup_probe_failed");
  } finally {
    await cleanupCgroup(job);
    if (!job) killGroup(child);
    await waitForExit(child, deadlineMs);
  }
}

async function cleanupCgroup(job: string | undefined): Promise<void> {
  if (!job) return;
  await writeFile(path.join(job, "cgroup.kill"), "1").catch(() => undefined);
  for (let attempt = 0; attempt < 5; attempt += 1) {
    try {
      await rmdir(job);
      return;
    } catch {
      if (attempt < 4) await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }
}

function killGroup(child: ChildProcess): void {
  if (!child.pid) return;
  try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
}

export class SandboxedShell {
  private readonly roots: string[];
  private readonly blocked: string[];
  private readonly canonicalBlocked: string[];
  private readonly privateKeyIndexes = new Map<string, PrivateKeyIndex>();
  private readonly setupPhaseTimeoutMs: number;

  private static readonly maxPrivateKeyIndexes = 32;

  constructor(private readonly options: SandboxedShellOptions) {
    if (!Number.isInteger(options.observerUid) || !Number.isInteger(options.observerGid)
        || options.observerUid <= 0 || options.observerGid <= 0) throw new Error("invalid_observer_identity");
    this.setupPhaseTimeoutMs = options.setupPhaseTimeoutMs ?? 15_000;
    if (!Number.isInteger(this.setupPhaseTimeoutMs) || this.setupPhaseTimeoutMs < 1) {
      throw new Error("invalid_setup_phase_timeout");
    }
    this.roots = options.readRoots.map((root) => fs.realpathSync(root));
    this.blocked = options.blockedPaths.map((target) => path.resolve(target));
    this.canonicalBlocked = resolveBlockedPaths(this.blocked);
    for (const root of this.roots) {
      if (this.canonicalBlocked.some((target) => inside(root, target))) {
        throw new Error("sandbox_root_overlaps_blocked_path");
      }
    }
    for (const source of runtimeSources.filter((item) => fs.existsSync(item))) {
      const canonical = fs.realpathSync(source);
      if (this.canonicalBlocked.some((target) => inside(canonical, target) || inside(target, canonical))) {
        throw new Error("sandbox_runtime_overlaps_blocked_path");
      }
      const sourceMetadata = fs.statSync(canonical);
      for (const target of this.canonicalBlocked) {
        try {
          const targetMetadata = fs.statSync(target);
          if (sourceMetadata.dev === targetMetadata.dev && sourceMetadata.ino === targetMetadata.ino) {
            throw new Error("sandbox_runtime_overlaps_blocked_path");
          }
        } catch (error) {
          if (error instanceof Error && error.message === "sandbox_runtime_overlaps_blocked_path") throw error;
        }
      }
    }
  }

  async initialize(timeoutMs = 60_000): Promise<void> {
    const deadlineMs = Date.now() + timeoutMs;
    if (this.options.requireCgroup) {
      try {
        await validateCgroupRoot(this.options.cgroupRoot, Math.min(deadlineMs, Date.now() + this.setupPhaseTimeoutMs));
        await probeCgroup(this.options.cgroupRoot, deadlineMs);
      } catch (error) {
        if (error instanceof SandboxFailure) throw error;
        const message = error instanceof Error ? error.message : "";
        if (message === "sandbox_timeout") {
          throw new SandboxFailure(publicSandboxError(error, { phase: "cgroup_setup", timeoutMs }));
        }
        const reason = message.startsWith("cgroup_") ? message : "cgroup_probe_failed";
        throw new SandboxFailure(publicSandboxError(new Error(`sandbox_unavailable:${reason}`), {
          phase: "cgroup_setup",
          timeoutMs,
        }));
      }
    }
    for (const root of this.roots) {
      const rootFd = fs.openSync(root, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      const parentFd = fs.openSync(path.dirname(root), fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      const filesystemFd = fs.openSync("/", fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      try {
        const remainingMs = deadlineMs - Date.now();
        if (remainingMs <= 0) {
          throw new SandboxFailure(publicSandboxError(new Error("sandbox_timeout"), {
            phase: "root_validation",
            timeoutMs,
          }));
        }
        await validateRootFd(
          this.options.helperPath,
          rootFd,
          parentFd,
          filesystemFd,
          path.basename(root),
          Math.min(remainingMs, this.setupPhaseTimeoutMs),
        );
      } finally {
        fs.closeSync(filesystemFd);
        fs.closeSync(parentFd);
        fs.closeSync(rootFd);
      }
    }
  }

  async run(request: SandboxRunRequest): Promise<SandboxedShellResult> {
    const startedAt = Date.now();
    const profile = request.profile ?? "diagnostic";
    const timings: SandboxTimings = {};
    try {
      const result = await this.runInternal(request, timings);
      this.options.observe?.({
        outcome: "completed",
        profile,
        read_scope_mode: request.readScope === undefined ? "global" : "explicit",
        ...timings,
        total_ms: Date.now() - startedAt,
      });
      return result;
    } catch (error) {
      const failure = publicSandboxError(error, { phase: "command_execution", timeoutMs: request.timeoutMs });
      this.options.observe?.({
        outcome: "failed",
        profile,
        read_scope_mode: request.readScope === undefined ? "global" : "explicit",
        ...timings,
        total_ms: Date.now() - startedAt,
        error: failure.error,
        phase: failure.phase,
        reason: failure.reason,
      });
      throw error;
    }
  }

  private async runInternal(
    request: SandboxRunRequest,
    timings: SandboxTimings,
  ): Promise<SandboxedShellResult> {
    const profile = request.profile ?? "diagnostic";
    const timeoutMaximum = profile === "project_task" ? 10 * 60_000 : 60_000;
    const outputMaximum = profile === "project_task" ? 1024 * 1024 : 128 * 1024;
    if (typeof request.command !== "string" || request.command.length === 0 || request.command.length > (profile === "project_task" ? 16 * 1024 : 4096) || request.command.includes("\0")) {
      throw new Error("invalid_command");
    }
    if (!Number.isInteger(request.timeoutMs) || request.timeoutMs < 1 || request.timeoutMs > timeoutMaximum) throw new Error("invalid_timeout");
    if (!Number.isInteger(request.maxOutputBytes) || request.maxOutputBytes < 1 || request.maxOutputBytes > outputMaximum) throw new Error("invalid_output_limit");
    const deadlineMs = Date.now() + request.timeoutMs;
    const cwd = fs.realpathSync(request.cwd);
    const root = request.readScope === undefined
      ? this.roots.find((candidate) => inside(cwd, candidate))
      : resolveExplicitReadScope(request.readScope, this.roots);
    if (!root) throw new Error("cwd_outside_sandbox_roots");
    if (!inside(cwd, root)) throw new Error("cwd_outside_sandbox_roots");
    const canonicalBlocked = resolveBlockedPaths(this.blocked);
    if (canonicalBlocked.some((target) => inside(root, target))) {
      throw new Error(request.readScope === undefined
        ? "sandbox_root_overlaps_blocked_path"
        : "read_scope_overlaps_blocked_path");
    }
    if (canonicalBlocked.some((target) => inside(cwd, target))) throw new Error("cwd_outside_sandbox_roots");
    const openedFds: number[] = [];
    const trackedOpen = (target: string, flags: number) => {
      const descriptor = fs.openSync(target, flags);
      openedFds.push(descriptor);
      return descriptor;
    };
    let child: ChildProcess;
    let preparationPhase: SandboxPhase = "root_validation";
    let spawnRequestedAt = 0;
    try {
      const hostNet = fs.statSync("/proc/self/ns/net").ino;
      const hostPid = fs.statSync("/proc/self/ns/pid").ino;
      const seccompFd = trackedOpen(this.options.seccompPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
      const rootFd = trackedOpen(root, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      const rootParent = path.dirname(root);
      const parentFd = trackedOpen(rootParent, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      const filesystemFd = trackedOpen("/", fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      const helperFd = trackedOpen(this.options.helperPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
      const rootValidationStartedAt = Date.now();
      try {
        await validateRootFd(
          this.options.helperPath,
          rootFd,
          parentFd,
          filesystemFd,
          path.basename(root),
          Math.max(1, Math.min(deadlineMs - Date.now(), this.setupPhaseTimeoutMs)),
        );
      } finally {
        timings.root_validation_ms = Date.now() - rootValidationStartedAt;
      }
      preparationPhase = "root_view_prepare";
      const rootMetadata = fs.statSync(root);
      const indexKey = `${root}:${rootMetadata.dev}:${rootMetadata.ino}`;
      const privateKeyIndex = this.privateKeyIndexes.get(indexKey) ?? new PrivateKeyIndex();
      this.privateKeyIndexes.delete(indexKey);
      this.privateKeyIndexes.set(indexKey, privateKeyIndex);
      while (this.privateKeyIndexes.size > SandboxedShell.maxPrivateKeyIndexes) {
        const oldest = this.privateKeyIndexes.keys().next().value;
        if (oldest === undefined) break;
        this.privateKeyIndexes.delete(oldest);
      }
      const rootViewStartedAt = Date.now();
      let viewPlan;
      try {
        viewPlan = createRootReadViewPlan(
          root,
          [...this.blocked, ...canonicalBlocked],
          { index: privateKeyIndex, deadlineMs },
        );
      } finally {
        timings.root_view_prepare_ms = Date.now() - rootViewStartedAt;
      }
      timings.blocked_targets_scanned = viewPlan.diagnostics.blocked_targets_scanned;
      timings.protected_files_scanned = viewPlan.diagnostics.protected_files_scanned;
      timings.protected_directories_scanned = viewPlan.diagnostics.protected_directories_scanned;
      timings.protected_inodes_collected = viewPlan.diagnostics.protected_inodes_collected;
      timings.scope_files_scanned = viewPlan.diagnostics.scope_files_scanned;
      timings.scope_directories_scanned = viewPlan.diagnostics.scope_directories_scanned;
      timings.private_key_cache_hits = viewPlan.diagnostics.private_key_cache_hits;
      timings.private_key_cache_misses = viewPlan.diagnostics.private_key_cache_misses;
      timings.rewrite_parents = viewPlan.diagnostics.rewrite_parents;
      timings.rewrite_entries = viewPlan.diagnostics.rewrite_entries;
      timings.protected_scan_ms = viewPlan.diagnostics.protected_scan_ms;
      timings.scope_walk_ms = viewPlan.diagnostics.scope_walk_ms;
      timings.rewrite_ms = viewPlan.diagnostics.rewrite_ms;
      const runtimeBindings = runtimeSources.flatMap((source) => {
        if (!fs.existsSync(source)) return [];
        const canonical = fs.realpathSync(source);
        const fd = trackedOpen(canonical, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
          | (fs.statSync(canonical).isDirectory() ? fs.constants.O_DIRECTORY : 0));
        return [{ fd, target: source }];
      });
      const rewrittenBindings: Array<{ fd: number; entry: RootViewEntry }> = [];
      for (const rewrite of viewPlan.rewrites) {
        for (const entry of rewrite.entries) {
          const current = fs.lstatSync(entry.source);
          if (BigInt(current.dev) !== entry.device || BigInt(current.ino) !== entry.inode
              || (entry.kind === "symlink" && fs.readlinkSync(entry.source) !== entry.linkTarget)) {
            throw new Error("sandbox_root_changed");
          }
          if (entry.kind === "symlink") continue;
          const fd = trackedOpen(
            entry.source,
            fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
              | (entry.kind === "directory" ? fs.constants.O_DIRECTORY : 0),
          );
          const opened = fs.fstatSync(fd);
          if (BigInt(opened.dev) !== entry.device || BigInt(opened.ino) !== entry.inode) {
            throw new Error("sandbox_root_changed");
          }
          rewrittenBindings.push({
            fd,
            entry,
          });
        }
      }
      const blockedFileBindings = viewPlan.masks.flatMap(({ target, kind }) => {
        if (kind === "directory") return [];
        return [{ fd: trackedOpen("/dev/null", fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW), target }];
      });
      const blockedFds = canonicalBlocked.flatMap((target) => {
        if (!fs.existsSync(target)) return [];
        const canonical = fs.realpathSync(target);
        const metadata = fs.statSync(canonical);
        if (!metadata.isFile() && !metadata.isDirectory()) return [];
        return [trackedOpen(
          canonical,
          fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
            | (metadata.isDirectory() ? fs.constants.O_DIRECTORY : 0),
        )];
      });
      preparationPhase = "runtime_validation";
      const runtimeValidationStartedAt = Date.now();
      try {
        await validateRuntimeDisjointFds(
          this.options.helperPath,
          runtimeBindings.map(({ fd }) => fd),
          blockedFds,
          Math.max(1, Math.min(deadlineMs - Date.now(), this.setupPhaseTimeoutMs)),
        );
      } finally {
        timings.runtime_validation_ms = Date.now() - runtimeValidationStartedAt;
      }
      preparationPhase = "root_view_prepare";
      const rootViewVerifyStartedAt = Date.now();
      try {
        verifyRootReadViewPlan(root, viewPlan, rootFd);
      } finally {
        timings.root_view_verify_ms = Date.now() - rootViewVerifyStartedAt;
      }
      preparationPhase = "sandbox_spawn";
      const args = [
        "--unshare-all", "--unshare-user",
        ...(profile === "diagnostic" ? ["--disable-userns", "--assert-userns-disabled"] : []),
        "--uid", String(this.options.observerUid), "--gid", String(this.options.observerGid),
        "--cap-drop", "ALL", "--die-with-parent", "--new-session", "--hostname", "shellbridge-sandbox",
        "--clearenv", "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
        "--setenv", "HOME", "/nonexistent", "--setenv", "LANG", "C.UTF-8", "--setenv", "LC_ALL", "C.UTF-8",
        "--setenv", "TMPDIR", "/tmp",
        "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
        "--proc", "/proc", "--dev", "/dev",
        "--dir", "/etc", "--dir", "/opt",
      ];
      runtimeBindings.forEach((binding, index) => args.push("--ro-bind-fd", String(7 + index), binding.target));
      args.push("--size", profile === "project_task" ? "1073741824" : "16777216", "--tmpfs", "/tmp", "--chmod", "1777", "/tmp");
      args.push(...directoryArguments(root));
      args.push("--ro-bind-fd", "5", root);
      for (const rewrite of viewPlan.rewrites) {
        args.push("--tmpfs", rewrite.target, "--chmod", "755", rewrite.target);
        for (const entry of rewrite.entries) {
          if (entry.kind === "symlink") {
            args.push("--symlink", entry.linkTarget!, entry.target);
            continue;
          }
          const bindingIndex = rewrittenBindings.findIndex((binding) => binding.entry === entry);
          if (bindingIndex < 0) throw new Error("sandbox_root_changed");
          args.push("--ro-bind-fd", String(7 + runtimeBindings.length + bindingIndex), entry.target);
        }
        args.push("--remount-ro", rewrite.target);
      }
      for (const { target, kind } of viewPlan.masks) {
        if (kind === "directory") args.push("--tmpfs", target, "--chmod", "000", target);
      }
      blockedFileBindings.forEach((binding, index) => {
        args.push(
          "--perms", "000", "--ro-bind-data",
          String(7 + runtimeBindings.length + rewrittenBindings.length + index),
          binding.target,
        );
      });
      args.push("--dir", "/opt", "--dir", "/opt/shellbridge", "--ro-bind-fd", "6", "/opt/shellbridge/sandbox-init");
      args.push("--seccomp", "4", "--chdir", cwd);
      args.push(
        "--", "/opt/shellbridge/sandbox-init", "sandbox-init",
        String(this.options.observerUid), String(this.options.observerGid),
        String(hostNet), String(hostPid),
        profile === "project_task" ? "600" : "10",
        profile === "project_task" ? "68719476736" : "2147483648",
        profile === "project_task" ? "1024" : "64",
        profile === "project_task" ? "1073741824" : "1048576",
        profile === "project_task" ? "256" : "64",
        request.command,
      );

      spawnRequestedAt = Date.now();
      child = spawn(this.options.helperPath, ["cgroup-exec", this.options.bwrapPath, "--", ...args], {
        detached: true,
        env: {},
        stdio: [
          "ignore", "pipe", "pipe", "pipe", seccompFd, rootFd, helperFd,
          ...runtimeBindings.map(({ fd }) => fd),
          ...rewrittenBindings.map(({ fd }) => fd),
          ...blockedFileBindings.map(({ fd }) => fd),
        ],
      });
    } catch (error) {
      if (error instanceof SandboxFailure) throw error;
      if (Date.now() >= deadlineMs) {
        throw new SandboxFailure(publicSandboxError(new Error("sandbox_timeout"), {
          phase: preparationPhase,
          timeoutMs: request.timeoutMs,
        }));
      }
      const internalMessage = error instanceof Error && /^(?:sandbox|cgroup)_[a-z_]+$/.test(error.message)
        ? error.message
        : undefined;
      throw new SandboxFailure(publicSandboxError(error, {
        phase: preparationPhase,
        timeoutMs: request.timeoutMs,
        fallbackPhase: preparationPhase,
      }), internalMessage);
    } finally {
      openedFds.forEach((descriptor) => {
        try { fs.closeSync(descriptor); } catch { /* already closed */ }
      });
    }
    const spawned = new Promise<void>((resolve, reject) => {
      child.once("spawn", resolve);
      child.once("error", () => reject(new Error("sandbox_spawn_failed")));
    });
    const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null; spawnFailed?: true }>((resolve) => {
      child.once("error", () => resolve({ code: null, signal: null, spawnFailed: true }));
      child.once("exit", (code, signal) => resolve({ code, signal }));
    });

    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let outputBytes = 0;
    let outputExceeded = false;
    const capture = (destination: Buffer[]) => (chunk: Buffer) => {
      outputBytes += chunk.length;
      if (outputBytes > request.maxOutputBytes) {
        outputExceeded = true;
        if (profile === "diagnostic") killGroup(child);
        return;
      }
      destination.push(chunk);
    };
    child.stdout?.on("data", capture(stdout));
    child.stderr?.on("data", capture(stderr));

    let cgroupJob: string | undefined;
    try {
      await spawned;
      if (!Number.isInteger(child.pid) || Number(child.pid) <= 0) throw new Error("sandbox_pid_unavailable");
      const cgroupStartedAt = Date.now();
      try {
        if (this.options.requireCgroup) {
          cgroupJob = await configureCgroup(this.options.cgroupRoot, Number(child.pid), profile, deadlineMs);
        }
        if (Date.now() >= deadlineMs) throw new Error("sandbox_timeout");
        const blocker = child.stdio[3];
        if (!blocker || typeof (blocker as NodeJS.WritableStream).write !== "function") throw new Error("sandbox_blocker_unavailable");
        (blocker as NodeJS.WritableStream).write(Buffer.from([1]));
        (blocker as NodeJS.WritableStream).end();
        timings.spawn_to_ready_ms = Date.now() - spawnRequestedAt;
      } finally {
        timings.cgroup_setup_ms = Date.now() - cgroupStartedAt;
      }
    } catch (error) {
      killGroup(child);
      await exited;
      await cleanupCgroup(cgroupJob);
      const errno = error && typeof error === "object" && "code" in error ? String((error as NodeJS.ErrnoException).code) : "";
      const reason = error instanceof Error && /^[a-z_]+$/.test(error.message)
        ? error.message
        : /^[A-Z_]+$/.test(errno) ? errno.toLowerCase() : "sandbox_setup_failed";
      if (reason === "sandbox_timeout") {
        throw new SandboxFailure(publicSandboxError(error, {
          phase: "cgroup_setup",
          timeoutMs: request.timeoutMs,
        }));
      }
      throw new SandboxFailure(publicSandboxError(new Error(`sandbox_unavailable:${reason}`), {
        phase: reason.startsWith("cgroup_") ? "cgroup_setup" : "sandbox_spawn",
        timeoutMs: request.timeoutMs,
      }));
    }

    const remainingMs = deadlineMs - Date.now();
    if (remainingMs <= 0) {
      killGroup(child);
      await exited;
      await cleanupCgroup(cgroupJob);
      throw new SandboxFailure(publicSandboxError(new Error("sandbox_timeout"), {
        phase: "command_execution",
        timeoutMs: request.timeoutMs,
      }));
    }
    const commandStartedAt = Date.now();
    const timer = setTimeout(() => killGroup(child), remainingMs);
    let exit: Awaited<typeof exited>;
    try {
      exit = await exited;
    } finally {
      clearTimeout(timer);
      await cleanupCgroup(cgroupJob);
      timings.command_execution_ms = Date.now() - commandStartedAt;
    }

    const stdoutText = redact(Buffer.concat(stdout).toString("utf8"));
    const stderrText = redact(Buffer.concat(stderr).toString("utf8"));
    if (outputExceeded && profile === "diagnostic") {
      throw new SandboxFailure(publicSandboxError(new Error("sandbox_output_limit_exceeded"), { phase: "command_execution" }));
    }
    if (exit.spawnFailed) {
      throw new SandboxFailure(publicSandboxError(new Error("sandbox_unavailable:sandbox_spawn_failed"), { phase: "sandbox_spawn" }));
    }
    if (exit.signal === "SIGKILL" && profile === "diagnostic") {
      throw new SandboxFailure(publicSandboxError(new Error("sandbox_timeout"), {
        phase: "command_execution",
        timeoutMs: request.timeoutMs,
      }));
    }
    if (stderrText.includes("shellbridge_helper:") || stderrText.startsWith("bwrap:")) {
      throw new SandboxFailure(publicSandboxError(new Error("sandbox_unavailable:sandbox_setup_failed"), { phase: "sandbox_spawn" }));
    }
    return { stdout: stdoutText, stderr: stderrText, exitCode: exit.signal === "SIGKILL" ? 124 : exit.code ?? 1, truncated: outputExceeded };
  }
}
