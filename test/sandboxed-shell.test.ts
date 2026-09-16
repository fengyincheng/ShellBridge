import { execFile } from "node:child_process";
import { link, mkdir, mkdtemp, readFile, rm, rmdir, stat, symlink, writeFile } from "node:fs/promises";
import { promisify } from "node:util";
import net from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { registerExactRedactionSecrets } from "../src/redactor.js";
import { SandboxedShell } from "../src/sandboxed-shell.js";

const temporaryPaths: string[] = [];
const execFileAsync = promisify(execFile);

afterEach(async () => {
  await Promise.all(temporaryPaths.splice(0).map((target) => rm(target, { recursive: true, force: true })));
});

describe.skipIf(process.env.SHELLBRIDGE_NATIVE_ACCEPTANCE !== "1")("SandboxedShell", () => {
  test("mounts only an explicit project scope and masks external links and protected hard-link aliases", async () => {
    const parent = await mkdtemp(path.join(process.cwd(), ".shellbridge-explicit-scope-"));
    const project = path.join(parent, "project");
    const sibling = path.join(parent, "sibling");
    const protectedSource = path.join(parent, "protected");
    temporaryPaths.push(parent);
    await mkdir(project);
    await mkdir(sibling);
    await mkdir(protectedSource);
    await writeFile(path.join(project, "visible.txt"), "project-visible\n");
    await writeFile(path.join(sibling, "secret.txt"), "sibling-secret\n");
    await symlink("../sibling/secret.txt", path.join(project, "escape.txt"));
    const protectedFile = path.join(protectedSource, "credential.txt");
    await writeFile(protectedFile, "protected\n");
    await link(protectedFile, path.join(project, "ordinary-name.txt"));

    const shell = new SandboxedShell({
      helperPath: path.resolve("dist/native/shellbridge-helper"),
      seccompPath: path.resolve("dist/native/network-deny.bpf"),
      bwrapPath: "/usr/bin/bwrap",
      readRoots: [parent],
      blockedPaths: [protectedSource, "/etc/shadow"],
      observerUid: 65534,
      observerGid: 65534,
      cgroupRoot: "/sys/fs/cgroup/unused",
      requireCgroup: false,
    });
    const result = await shell.run({
      command: [
        "set -eu",
        "test \"$(cat visible.txt)\" = project-visible",
        "test ! -r ../sibling/secret.txt",
        "test ! -r escape.txt",
        "test ! -r ordinary-name.txt",
      ].join("\n"),
      cwd: project,
      readScope: project,
      timeoutMs: 10_000,
      maxOutputBytes: 16 * 1024,
    });

    expect(result, JSON.stringify(result)).toMatchObject({ exitCode: 0, stdout: "", stderr: "" });
  });

  test("presents a complete read-only root while masking exact sensitive descendants", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "shellbridge-root-view-"));
    temporaryPaths.push(root);
    await mkdir(path.join(root, ".cache", "tool"), { recursive: true });
    await mkdir(path.join(root, "project", "node_modules", ".cache"), { recursive: true });
    await mkdir(path.join(root, "project", "dist"), { recursive: true });
    await mkdir(path.join(root, "project", "logs"), { recursive: true });
    await mkdir(path.join(root, ".ssh"), { recursive: true });
    await writeFile(path.join(root, ".cache", "tool", "index"), "cache-visible\n");
    await writeFile(path.join(root, "project", "node_modules", ".cache", "entry"), "dependency-cache-visible\n");
    await writeFile(path.join(root, "project", "dist", "bundle.js"), "build-visible\n");
    await writeFile(path.join(root, "project", "logs", "app.log"), "log-visible\n");
    await writeFile(path.join(root, ".ssh", "id_ed25519"), "registered-secret\n");
    await writeFile(path.join(root, "gateway.db"), "database-secret\n");
    const protectedPath = path.join(root, ".cache", "tool", "index");
    const before = await stat(protectedPath);

    const shell = new SandboxedShell({
      helperPath: path.resolve("dist/native/shellbridge-helper"),
      seccompPath: path.resolve("dist/native/network-deny.bpf"),
      bwrapPath: "/usr/bin/bwrap",
      readRoots: [root],
      blockedPaths: [path.join(root, ".ssh"), path.join(root, "gateway.db"), "/etc/shadow"],
      observerUid: 65534,
      observerGid: 65534,
      cgroupRoot: "/sys/fs/cgroup/unused",
      requireCgroup: false,
    });
    const result = await shell.run({
      command: [
        "set -eu",
        "test -d .cache",
        "test \"$(cat .cache/tool/index)\" = cache-visible",
        "test \"$(cat project/node_modules/.cache/entry)\" = dependency-cache-visible",
        "test \"$(cat project/dist/bundle.js)\" = build-visible",
        "test \"$(cat project/logs/app.log)\" = log-visible",
        "test ! -r .ssh/id_ed25519",
        "test ! -r gateway.db",
        "if printf changed 2>/dev/null > .cache/tool/index; then exit 31; fi",
        "if rm .cache/tool/index 2>/dev/null; then exit 32; fi",
        "if mv .cache/tool/index .cache/tool/moved 2>/dev/null; then exit 33; fi",
        "if chmod 600 .cache/tool/index 2>/dev/null; then exit 34; fi",
      ].join("\n"),
      cwd: root,
      timeoutMs: 10_000,
      maxOutputBytes: 16 * 1024,
    });

    expect(result, JSON.stringify(result)).toMatchObject({ exitCode: 0, stdout: "", stderr: "" });
    const after = await stat(protectedPath);
    expect(await readFile(protectedPath, "utf8")).toBe("cache-visible\n");
    expect({ ino: after.ino, mtimeMs: after.mtimeMs, mode: after.mode }).toEqual({
      ino: before.ino,
      mtimeMs: before.mtimeMs,
      mode: before.mode,
    });
  });

  test("keeps ordinary hidden state and caches visible while masking discovered credentials", async () => {
    const knownCredential = "native-known-credential-47N9VfQx";
    registerExactRedactionSecrets([knownCredential]);
    const root = await mkdtemp(path.join(tmpdir(), "shellbridge-sensitive-view-"));
    temporaryPaths.push(root);
    await mkdir(path.join(root, ".claude", "cache"), { recursive: true });
    await mkdir(path.join(root, ".claude", "session-env"), { recursive: true });
    await mkdir(path.join(root, ".codex", "plugins", "cache"), { recursive: true });
    await mkdir(path.join(root, ".config", "gh"), { recursive: true });
    await mkdir(path.join(root, ".pm2", "logs"), { recursive: true });
    await mkdir(path.join(root, "project"), { recursive: true });
    await writeFile(path.join(root, ".claude", "cache", "changelog.md"), "claude-cache-visible\n");
    await writeFile(path.join(root, ".claude", "session-env", "active"), "session-secret\n");
    await writeFile(path.join(root, ".codex", "plugins", "cache", "catalog.json"), "plugin-cache-visible\n");
    await writeFile(path.join(root, ".codex", "auth.json"), "codex-auth-secret\n");
    await writeFile(path.join(root, ".config", "gh", "config.yml"), "git_protocol: ssh\n");
    await writeFile(path.join(root, ".config", "gh", "hosts.yml"), "github-token-secret\n");
    await writeFile(path.join(root, ".pm2", "logs", "app.log"), `pm2-log-visible ${knownCredential}\n`);
    await writeFile(path.join(root, "project", ".env"), "PROJECT_TOKEN=env-secret\n");
    await writeFile(path.join(root, "project", ".env.production"), "PROJECT_TOKEN=production-secret\n");
    await writeFile(path.join(root, "project", ".env.example"), "PROJECT_TOKEN=replace-me\n");
    await writeFile(path.join(root, "project", "private.pem"), "-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----\n");
    await link(path.join(root, "project", "private.pem"), path.join(root, "project", "ordinary-copy.txt"));
    await writeFile(
      path.join(root, "project", "signing-material"),
      "-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----\n",
    );
    await writeFile(path.join(root, "project", "real-auth.db"), "registered-symlink-secret\n");
    await link(path.join(root, "project", "real-auth.db"), path.join(root, "project", "auth-alias.txt"));
    await writeFile(path.join(root, "project", "fixture.key"), "ordinary-config-key-name\n");
    await symlink("/etc/passwd", path.join(root, "project", "escape"));
    const socketPath = path.join(root, ".pm2", "rpc.sock");
    const server = net.createServer();
    await new Promise<void>((resolve, reject) => server.listen(socketPath, resolve).once("error", reject));

    try {
      const shell = new SandboxedShell({
        helperPath: path.resolve("dist/native/shellbridge-helper"),
        seccompPath: path.resolve("dist/native/network-deny.bpf"),
        bwrapPath: "/usr/bin/bwrap",
        readRoots: [root],
        blockedPaths: [
          path.join(root, ".claude", "session-env"),
          path.join(root, ".codex", "auth.json"),
          path.join(root, ".config", "gh", "hosts.yml"),
          path.join(root, "project", "registered-auth"),
          socketPath,
          "/etc/shadow",
        ],
        observerUid: 65534,
        observerGid: 65534,
        cgroupRoot: "/sys/fs/cgroup/unused",
        requireCgroup: false,
      });
      await symlink("real-auth.db", path.join(root, "project", "registered-auth"));
      const result = await shell.run({
        command: [
          "set -eu",
          "test \"$(cat .claude/cache/changelog.md)\" = claude-cache-visible",
          "test \"$(cat .codex/plugins/cache/catalog.json)\" = plugin-cache-visible",
          "grep -q 'git_protocol' .config/gh/config.yml",
          "cat .pm2/logs/app.log",
          "grep -q replace-me project/.env.example",
          "test \"$(cat project/fixture.key)\" = ordinary-config-key-name",
          "for secret in .claude/session-env/active .codex/auth.json .config/gh/hosts.yml project/.env project/.env.production project/private.pem project/ordinary-copy.txt project/signing-material project/real-auth.db project/registered-auth project/auth-alias.txt .pm2/rpc.sock project/escape; do",
          "  if test -r \"$secret\"; then printf 'unexpected readable path: %s\\n' \"$secret\"; exit 41; fi",
          "done",
        ].join("\n"),
        cwd: root,
        timeoutMs: 10_000,
        maxOutputBytes: 16 * 1024,
      });
      expect(result.exitCode, JSON.stringify(result)).toBe(0);
      expect(result.stdout).toContain("pm2-log-visible");
      expect(result.stdout).toContain(`[REDACTED length=${knownCredential.length}]`);
      expect(result.stdout).not.toContain(knownCredential);
      expect(result.stderr).toBe("");
      await writeFile(
        path.join(root, "project", "late-private-material"),
        "-----BEGIN PRIVATE KEY-----\nlate-private\n-----END PRIVATE KEY-----\n",
      );
      await writeFile(
        path.join(root, "project", "fixture.key"),
        "-----BEGIN PRIVATE KEY-----\nchanged-private\n-----END PRIVATE KEY-----\n",
      );
      const afterChange = await shell.run({
        command: [
          "set -eu",
          "test ! -r project/late-private-material",
          "test ! -r project/fixture.key",
          "test \"$(cat .claude/cache/changelog.md)\" = claude-cache-visible",
        ].join("\n"),
        cwd: root,
        timeoutMs: 10_000,
        maxOutputBytes: 16 * 1024,
      });
      expect(afterChange, JSON.stringify(afterChange)).toMatchObject({ exitCode: 0, stderr: "" });
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  test("runs full Bash diagnostics while denying host writes, secrets, and sockets", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "shellbridge-sandbox-"));
    temporaryPaths.push(root);
    await writeFile(path.join(root, "alpha.txt"), "alpha\n");
    const cgroupRoot = `/sys/fs/cgroup/shellbridge-test-${process.pid}`;
    await mkdir(cgroupRoot);

    try {
      const shell = new SandboxedShell({
        helperPath: path.resolve("dist/native/shellbridge-helper"),
        seccompPath: path.resolve("dist/native/network-deny.bpf"),
        bwrapPath: "/usr/bin/bwrap",
        readRoots: [root],
        blockedPaths: ["/etc/shadow", "/root/.ssh", path.resolve(".")],
        observerUid: 65534,
        observerGid: 65534,
        cgroupRoot,
        requireCgroup: true,
      });
      const result = await shell.run({
        command: [
          "set -eu",
          "for value in alpha beta; do printf '%s:' \"$value\"; done",
          "find . -maxdepth 1 -name '*.txt' -print | sed 's#^./##'",
          "printf '1\\n2\\n3\\n' | awk '{ total += $1 } END { print total }'",
          "python3 -c \"print(sum([2, 3]))\"",
          "node -e \"process.stdout.write(String([3,4].reduce((a,b)=>a+b,0)) + '\\\\n')\"",
          "if touch persisted.txt 2>/dev/null; then exit 21; fi",
          "test ! -e /etc/shadow",
          "python3 -c \"import socket; socket.socket()\" >/dev/null 2>&1 && exit 22 || true",
          "python3 -c \"import ctypes, errno; r=ctypes.CDLL(None, use_errno=True).syscall(425, 0, 0); assert r == -1 and ctypes.get_errno() == errno.EPERM\"",
        ].join("\n"),
        cwd: root,
        timeoutMs: 10_000,
        maxOutputBytes: 16 * 1024,
      });

      expect(result.exitCode, JSON.stringify(result)).toBe(0);
      expect(result.stdout).toContain("alpha:beta:alpha.txt");
      expect(result.stdout).toContain("\n6\n5\n7\n");
      await expect(readFile(path.join(root, "alpha.txt"), "utf8")).resolves.toBe("alpha\n");
      await expect(readFile(path.join(root, "persisted.txt"), "utf8")).rejects.toThrow();
    } finally {
      await rmdir(cgroupRoot);
    }
  });

  test("masks control sockets and links that escape the root without hiding the root", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "shellbridge-unsafe-root-"));
    temporaryPaths.push(root);
    const socketPath = path.join(root, "control.sock");
    const server = net.createServer();
    await new Promise<void>((resolve, reject) => server.listen(socketPath, resolve).once("error", reject));
    await symlink("/etc/passwd", path.join(root, "escape"));
    try {
      const shell = new SandboxedShell({
        helperPath: path.resolve("dist/native/shellbridge-helper"),
        seccompPath: path.resolve("dist/native/network-deny.bpf"),
        bwrapPath: "/usr/bin/bwrap",
        readRoots: [root],
        blockedPaths: ["/etc/shadow", "/root/.ssh", path.resolve(".")],
        observerUid: 65534,
        observerGid: 65534,
        cgroupRoot: "/sys/fs/cgroup/unused",
        requireCgroup: false,
      });
      const result = await shell.run({
        command: "test ! -r control.sock && test ! -r escape",
        cwd: root,
        timeoutMs: 1_000,
        maxOutputBytes: 1024,
      });
      expect(result.exitCode, JSON.stringify(result)).toBe(0);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  test("masks hard-link aliases to blocked resources and refuses nested mounts", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "shellbridge-alias-root-"));
    const outside = await mkdtemp(path.join(tmpdir(), "shellbridge-blocked-source-"));
    temporaryPaths.push(root, outside);
    const outsideSecret = path.join(outside, "secret.txt");
    await writeFile(outsideSecret, "never-visible\n");
    await link(outsideSecret, path.join(root, "hardlink.txt"));
    const shell = new SandboxedShell({
      helperPath: path.resolve("dist/native/shellbridge-helper"),
      seccompPath: path.resolve("dist/native/network-deny.bpf"),
      bwrapPath: "/usr/bin/bwrap",
      readRoots: [root],
      blockedPaths: [outside],
      observerUid: 65534,
      observerGid: 65534,
      cgroupRoot: "/sys/fs/cgroup/unused",
      requireCgroup: false,
    });
    const hardLinkResult = await shell.run({
      command: "test ! -r hardlink.txt",
      cwd: root,
      timeoutMs: 1_000,
      maxOutputBytes: 1024,
    });
    expect(hardLinkResult.exitCode, JSON.stringify(hardLinkResult)).toBe(0);

    await rm(path.join(root, "hardlink.txt"));
    const fileMountpoint = path.join(root, "file-mount.txt");
    await writeFile(fileMountpoint, "");
    await execFileAsync("/usr/bin/mount", ["--bind", outsideSecret, fileMountpoint]);
    try {
      await expect(shell.run({ command: "cat file-mount.txt", cwd: root, timeoutMs: 1_000, maxOutputBytes: 1024 }))
        .rejects.toThrow("sandbox_root_validation_failed");
    } finally {
      await execFileAsync("/usr/bin/umount", [fileMountpoint]);
    }

    const mountpoint = path.join(root, "mounted");
    await mkdir(mountpoint);
    await execFileAsync("/usr/bin/mount", ["--bind", outside, mountpoint]);
    try {
      await expect(shell.run({ command: "cat mounted/secret.txt", cwd: root, timeoutMs: 1_000, maxOutputBytes: 1024 }))
        .rejects.toThrow("sandbox_root_validation_failed");
    } finally {
      await execFileAsync("/usr/bin/umount", [mountpoint]);
    }

    await execFileAsync("/usr/bin/mount", ["--bind", outside, root]);
    try {
      await expect(shell.run({ command: "cat secret.txt", cwd: root, timeoutMs: 1_000, maxOutputBytes: 1024 }))
        .rejects.toThrow("sandbox_root_validation_failed");
    } finally {
      await execFileAsync("/usr/bin/umount", [root]);
    }

    const alias = await mkdtemp(path.join(tmpdir(), "shellbridge-ancestor-alias-"));
    temporaryPaths.push(alias);
    const nested = path.join(outside, "nested");
    await mkdir(nested);
    await writeFile(path.join(nested, "nested-secret.txt"), "never-visible\n");
    await execFileAsync("/usr/bin/mount", ["--bind", outside, alias]);
    try {
      const ancestorAlias = new SandboxedShell({
        helperPath: path.resolve("dist/native/shellbridge-helper"),
        seccompPath: path.resolve("dist/native/network-deny.bpf"),
        bwrapPath: "/usr/bin/bwrap",
        readRoots: [path.join(alias, "nested")],
        blockedPaths: [outside],
        observerUid: 65534,
        observerGid: 65534,
        cgroupRoot: "/sys/fs/cgroup/unused",
        requireCgroup: false,
      });
      await expect(ancestorAlias.run({
        command: "cat nested-secret.txt",
        cwd: path.join(alias, "nested"),
        timeoutMs: 1_000,
        maxOutputBytes: 1024,
      })).rejects.toThrow("sandbox_root_validation_failed");
    } finally {
      await execFileAsync("/usr/bin/umount", [alias]);
    }
  });

  test("fails closed on setup, timeout, output, and runtime-policy failures", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "shellbridge-fail-closed-"));
    temporaryPaths.push(root);
    const options = {
      helperPath: path.resolve("dist/native/shellbridge-helper"),
      seccompPath: path.resolve("dist/native/network-deny.bpf"),
      bwrapPath: "/usr/bin/bwrap",
      readRoots: [root],
      blockedPaths: ["/etc/shadow", path.resolve(".")],
      observerUid: 65534,
      observerGid: 65534,
      cgroupRoot: "/sys/fs/cgroup/does-not-exist",
      requireCgroup: false,
    };
    const shell = new SandboxedShell(options);
    await expect(shell.run({ command: "sleep 2", cwd: root, timeoutMs: 50, maxOutputBytes: 1024 }))
      .rejects.toThrow("sandbox_timeout");
    await expect(shell.run({ command: "yes output", cwd: root, timeoutMs: 2_000, maxOutputBytes: 128 }))
      .rejects.toThrow("sandbox_output_limit_exceeded");

    const unavailable = new SandboxedShell({ ...options, requireCgroup: true });
    const hostMarker = path.join(tmpdir(), `shellbridge-no-fallback-${process.pid}`);
    await rm(hostMarker, { force: true });
    await expect(unavailable.run({
      command: `printf unsafe > ${JSON.stringify(hostMarker)}`,
      cwd: root,
      timeoutMs: 1_000,
      maxOutputBytes: 1024,
    })).rejects.toThrow("sandbox_unavailable");
    await expect(readFile(hostMarker, "utf8")).rejects.toThrow();

    expect(() => new SandboxedShell({ ...options, blockedPaths: ["/usr/share"] }))
      .toThrow("sandbox_runtime_overlaps_blocked_path");
  });
});
