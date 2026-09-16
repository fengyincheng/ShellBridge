import { link, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { createRootReadViewPlan, PrivateKeyIndex, verifyRootReadViewPlan, type RootReadViewPlan } from "../src/root-read-view.js";

const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryPaths.splice(0).map((target) => rm(target, { recursive: true, force: true })));
});

describe("root read view planning", () => {
  test("walks only the explicit scope while still collecting protected inode aliases", async () => {
    const parent = await mkdtemp(path.join(tmpdir(), "shellbridge-scoped-plan-"));
    const scope = path.join(parent, "project");
    const sibling = path.join(parent, "sibling");
    const protectedSource = await mkdtemp(path.join(tmpdir(), "shellbridge-protected-plan-"));
    temporaryPaths.push(parent, protectedSource);
    await mkdir(scope);
    await mkdir(sibling);
    await writeFile(path.join(scope, "visible.txt"), "visible\n");
    await writeFile(path.join(sibling, "ignored-1.txt"), "ignored\n");
    await writeFile(path.join(sibling, "ignored-2.txt"), "ignored\n");
    const protectedFile = path.join(protectedSource, "credential.txt");
    await writeFile(protectedFile, "credential\n");
    await link(protectedFile, path.join(scope, "ordinary-name.txt"));

    const index = new PrivateKeyIndex();
    const plan = createRootReadViewPlan(
      scope,
      [protectedSource],
      { index, deadlineMs: Date.now() + 5_000 },
    );

    expect(plan.diagnostics).toMatchObject({
      scope_files_scanned: 2,
      scope_directories_scanned: 1,
      protected_files_scanned: 1,
      protected_directories_scanned: 1,
    });
    expect(plan.masks.map(({ target }) => target)).toContain(path.join(scope, "ordinary-name.txt"));

    const warmPlan = createRootReadViewPlan(
      scope,
      [protectedSource],
      { index, deadlineMs: Date.now() + 5_000 },
    );
    expect(warmPlan.diagnostics).toMatchObject({ private_key_cache_hits: 2, private_key_cache_misses: 0 });

    await writeFile(path.join(scope, ".env"), "NEW_SECRET=secret\n");
    expect(() => verifyRootReadViewPlan(scope, plan)).toThrow("sandbox_root_changed");
  });

  test("deduplicates identical blocked targets without dropping a distinct lexical alias", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "shellbridge-root-plan-"));
    temporaryPaths.push(root);
    const blocked = path.join(root, "blocked");
    const alias = path.join(root, "blocked-alias");
    await mkdir(blocked);
    await writeFile(path.join(blocked, "secret.txt"), "secret\n");
    await symlink("blocked", alias);

    const plan = createRootReadViewPlan(
      root,
      [blocked, blocked, alias, blocked, alias],
      { index: new PrivateKeyIndex(), deadlineMs: Date.now() + 5_000 },
    ) as RootReadViewPlan & { diagnostics?: { blocked_targets_scanned: number } };

    expect(plan.diagnostics?.blocked_targets_scanned).toBe(2);
    const rootRewrite = plan.rewrites.find((rewrite) => rewrite.target === root);
    expect(rootRewrite).toBeDefined();
    expect(rootRewrite!.entries.every((entry) => entry.source !== alias && entry.source !== blocked)).toBe(true);
  });
});
