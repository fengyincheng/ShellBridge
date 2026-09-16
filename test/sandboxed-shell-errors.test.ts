import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { publicSandboxError } from "../src/sandbox-errors.js";
import { SandboxedShell, type SandboxObservation } from "../src/sandboxed-shell.js";

const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryPaths.splice(0).map((target) => rm(target, { recursive: true, force: true })));
});

async function fixtureShell(helperBody: string, observe: (value: SandboxObservation) => void, requireCgroup = false) {
  const root = await mkdtemp(path.join(tmpdir(), "shellbridge-timeout-phase-"));
  temporaryPaths.push(root);
  const helperPath = path.join(root, "helper.sh");
  await writeFile(helperPath, `#!/bin/sh\n${helperBody}\n`, "utf8");
  await chmod(helperPath, 0o755);
  return {
    root,
    shell: new SandboxedShell({
      helperPath,
      seccompPath: helperPath,
      bwrapPath: "/usr/bin/bwrap",
      readRoots: [root],
      blockedPaths: ["/etc/shadow"],
      observerUid: 65534,
      observerGid: 65534,
      cgroupRoot: path.join(root, "cgroup"),
      requireCgroup,
      setupPhaseTimeoutMs: 30,
      observe,
    }),
  };
}

describe("sandbox setup timeout phases", () => {
  test("fails readiness when the required cgroup root is missing", async () => {
    const { shell } = await fixtureShell("exit 0", () => undefined, true);

    await expect(shell.initialize()).rejects.toMatchObject({
      publicError: {
        error: "sandbox_unavailable",
        phase: "cgroup_setup",
        reason: "cgroup_root_missing",
        retryable: false,
      },
    });
  });

  test("reports a cgroup-specific reason when cgroup setup reaches the deadline", () => {
    expect(publicSandboxError(new Error("sandbox_timeout"), {
      phase: "cgroup_setup",
      timeoutMs: 1_000,
    })).toEqual({
      error: "sandbox_timeout",
      phase: "cgroup_setup",
      reason: "cgroup_setup_deadline_exceeded",
      retryable: true,
      timeout_ms: 1_000,
    });
  });

  test("classifies root validation helper timeout as a retryable timeout", async () => {
    let observation: SandboxObservation | undefined;
    const { root, shell } = await fixtureShell("sleep 2", (value) => { observation = value; });

    await expect(shell.run({ command: "printf test", cwd: root, timeoutMs: 1_000, maxOutputBytes: 1024 }))
      .rejects.toMatchObject({
        publicError: {
          error: "sandbox_timeout",
          phase: "root_validation",
          reason: "root_validation_deadline_exceeded",
          retryable: true,
          timeout_ms: 1_000,
        },
      });
    expect(observation).toMatchObject({
      outcome: "failed",
      error: "sandbox_timeout",
      phase: "root_validation",
      reason: "root_validation_deadline_exceeded",
    });
  });

  test("classifies runtime helper timeout as a retryable timeout", async () => {
    let observation: SandboxObservation | undefined;
    const helper = "if [ \"$1\" = validate-tree-fd ]; then exit 0; fi\nif [ \"$1\" = validate-disjoint-fds ]; then sleep 2; exit 0; fi\nexit 1";
    const { root, shell } = await fixtureShell(helper, (value) => { observation = value; });

    await expect(shell.run({ command: "printf test", cwd: root, timeoutMs: 1_000, maxOutputBytes: 1024 }))
      .rejects.toMatchObject({
        publicError: {
          error: "sandbox_timeout",
          phase: "runtime_validation",
          reason: "runtime_validation_deadline_exceeded",
          retryable: true,
          timeout_ms: 1_000,
        },
      });
    expect(observation).toMatchObject({
      outcome: "failed",
      error: "sandbox_timeout",
      phase: "runtime_validation",
      reason: "runtime_validation_deadline_exceeded",
    });
  });
});
