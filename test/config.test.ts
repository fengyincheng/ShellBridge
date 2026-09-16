import { describe, expect, test } from "vitest";
import { createConfig } from "../src/config.js";
import { COMMAND_TIMEOUT_DEFAULT_MS } from "../src/domain.js";

describe("generic read shell configuration", () => {
  test("gives the root-view preparation enough default time", () => {
    expect(COMMAND_TIMEOUT_DEFAULT_MS).toBe(60_000);
  });

  test("defaults to the complete /root view with a precise sensitive-resource denylist", () => {
    const config = createConfig({
      token: "test-token",
      encryptionKey: Buffer.alloc(32, 9),
      oauthOwnerSecret: "test-owner-secret",
      databasePath: "/root/runtime/gateway.db",
      inspectConfigTargets: ["/root/.claude/settings.json"],
    });

    expect(config.defaultCwd).toBe("/root");
    expect(config.sandboxReadRoots).toEqual(["/root"]);
    expect(config.sandboxBlockedPaths).toEqual(expect.arrayContaining([
      "/root/.ssh",
      "/root/.gnupg",
      "/root/.cloudflared",
      "/root/.docker/config.json",
      "/root/.config/gh/hosts.yml",
      "/root/.codex/auth.json",
      "/root/.gemini/oauth_creds.json",
      "/root/.pm2/rpc.sock",
      "/root/.pm2/pub.sock",
      "/root/.bash_history",
      "/root/runtime/gateway.db",
      "/root/runtime/gateway.db-wal",
      "/root/runtime/gateway.db-shm",
      "/root/.claude/settings.json",
    ]));
    expect(config.sandboxBlockedPaths).not.toEqual(expect.arrayContaining([
      "/root/example-project",
      "/root/.claude",
      "/root/.codex",
      "/root/.config",
      "/root/.cache",
      "/root/.pm2",
    ]));
  });

  test("normalizes the public base URL and rejects query or fragment state", () => {
    const common = {
      token: "test-token",
      encryptionKey: Buffer.alloc(32, 9),
      oauthOwnerSecret: "test-owner-secret",
    };
    expect(createConfig({ ...common, publicBaseUrl: "https://bridge.example.test/" }).publicBaseUrl)
      .toBe("https://bridge.example.test");
    expect(() => createConfig({ ...common, publicBaseUrl: "https://bridge.example.test/?mode=test" }))
      .toThrow("must not contain a query or fragment");
    expect(() => createConfig({ ...common, publicBaseUrl: "https://bridge.example.test/#state" }))
      .toThrow("must not contain a query or fragment");
    expect(createConfig({ ...common, listenPort: 18_765 }).listenPort).toBe(18_765);
    expect(() => createConfig({ ...common, listenPort: 0 }))
      .toThrow("must be an integer from 1 to 65535");
  });
});
