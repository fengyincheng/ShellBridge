import fs, { type Stats } from "node:fs";
import { afterEach, describe, expect, test, vi } from "vitest";
import type { GatewayConfig } from "../src/config.js";
import { getApprovalSmokeState } from "../src/policy.js";

const directory = "/srv/shellbridge/approval-smoke";
const enabledFile = `${directory}/enabled`;
const config = {
  approvalSmokeDirectory: directory,
  approvalSmokeEnabledFile: enabledFile,
} as GatewayConfig;

function metadata(overrides: Partial<Stats> & { directory?: boolean } = {}): Stats {
  const { directory: isDirectory = false, ...values } = overrides;
  return {
    uid: 0,
    mode: isDirectory ? 0o40700 : 0o100600,
    dev: 11,
    ino: isDirectory ? 22 : 33,
    mtimeMs: 44,
    isDirectory: () => isDirectory,
    isFile: () => !isDirectory,
    ...values,
  } as Stats;
}

function mockFileSystem(options: {
  resolvedEnabledFile?: string;
  directoryStat?: Stats;
  enabledStat?: Stats;
} = {}): void {
  const resolvedEnabledFile = options.resolvedEnabledFile ?? enabledFile;
  const directoryStat = options.directoryStat ?? metadata({ directory: true });
  const enabledStat = options.enabledStat ?? metadata();
  vi.spyOn(fs, "realpathSync").mockImplementation((target) => (
    String(target) === directory ? directory : resolvedEnabledFile
  ));
  vi.spyOn(fs, "statSync").mockImplementation((target) => (
    String(target) === directory ? directoryStat : enabledStat
  ));
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("approval smoke policy", () => {
  test("returns immutable state for a root-owned, non-writable regular file", () => {
    mockFileSystem();

    expect(getApprovalSmokeState(config)).toEqual({
      directory,
      enabled_file: enabledFile,
      enabled_dev: 11,
      enabled_ino: 33,
      enabled_mtime_ms: 44,
    });
  });

  test("rejects an enabled file outside the smoke directory", () => {
    mockFileSystem({ resolvedEnabledFile: "/srv/shellbridge/other/enabled" });

    expect(() => getApprovalSmokeState(config)).toThrow("approval_smoke_disabled");
  });

  test.each([
    ["non-root-owned directory", metadata({ directory: true, uid: 1000 }), metadata()],
    ["non-root-owned enabled file", metadata({ directory: true }), metadata({ uid: 1000 })],
    ["group-writable directory", metadata({ directory: true, mode: 0o40720 }), metadata()],
    ["world-writable enabled file", metadata({ directory: true }), metadata({ mode: 0o100602 })],
    ["non-regular enabled path", metadata({ directory: true }), metadata({ directory: true })],
  ])("rejects a %s", (_description, directoryStat, enabledStat) => {
    mockFileSystem({ directoryStat, enabledStat });

    expect(() => getApprovalSmokeState(config)).toThrow("approval_smoke_disabled");
  });
});
