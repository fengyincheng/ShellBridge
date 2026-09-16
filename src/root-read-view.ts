import fs from "node:fs";
import path from "node:path";

export interface RootViewEntry {
  source: string;
  target: string;
  kind: "file" | "directory" | "symlink";
  device: bigint;
  inode: bigint;
  linkTarget?: string;
}

export interface RootViewRewrite {
  target: string;
  entries: RootViewEntry[];
}

export interface RootViewSnapshotEntry extends RootViewEntry {
  size: number;
  mtimeMs: number;
  ctimeMs: number;
  mode: number;
  masked: boolean;
}

export interface RootReadViewPlan {
  masks: Array<{ target: string; kind: "file" | "directory" }>;
  rewrites: RootViewRewrite[];
  snapshot: RootViewSnapshotEntry[];
  diagnostics: {
    blocked_targets_scanned: number;
    protected_files_scanned: number;
    protected_directories_scanned: number;
    protected_inodes_collected: number;
    scope_files_scanned: number;
    scope_directories_scanned: number;
    private_key_cache_hits: number;
    private_key_cache_misses: number;
    rewrite_parents: number;
    rewrite_entries: number;
    protected_scan_ms: number;
    scope_walk_ms: number;
    rewrite_ms: number;
  };
}

interface PrivateKeyClassificationDiagnostics {
  private_key_cache_hits: number;
  private_key_cache_misses: number;
}

interface PrivateKeyCacheEntry {
  size: number;
  mtimeMs: number;
  ctimeMs: number;
  privateKey: boolean;
}

interface ProtectedTargetSnapshot {
  device: number;
  inode: number;
  kind: "file" | "directory";
}

export class PrivateKeyIndex {
  private readonly entries = new Map<string, PrivateKeyCacheEntry>();

  classify(target: string, metadata: fs.Stats, diagnostics?: PrivateKeyClassificationDiagnostics): boolean {
    const key = inodeKey(metadata);
    const cached = this.entries.get(key);
    if (cached && cached.size === metadata.size
        && cached.mtimeMs === metadata.mtimeMs && cached.ctimeMs === metadata.ctimeMs) {
      if (diagnostics) diagnostics.private_key_cache_hits += 1;
      return cached.privateKey;
    }
    if (diagnostics) diagnostics.private_key_cache_misses += 1;
    const privateKey = startsWithPrivateKey(target, metadata);
    this.entries.set(key, {
      size: metadata.size,
      mtimeMs: metadata.mtimeMs,
      ctimeMs: metadata.ctimeMs,
      privateKey,
    });
    return privateKey;
  }

  retain(inodes: Set<string>): void {
    for (const key of this.entries.keys()) {
      if (!inodes.has(key)) this.entries.delete(key);
    }
  }
}

const PRIVATE_KEY_HEADER = /^-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----/m;
const ENV_EXAMPLE = /^\.env\.(?:example|sample|template)(?:\.|$)/i;

function inside(target: string, root: string): boolean {
  return target === root || target.startsWith(`${root}${path.sep}`);
}

function isSecretEnvFile(name: string): boolean {
  return (name === ".env" || name.startsWith(".env.")) && !ENV_EXAMPLE.test(name);
}

function inodeKey(metadata: fs.Stats): string {
  return `${metadata.dev}:${metadata.ino}`;
}

function isMissingPathError(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error
    && (error as { code?: unknown }).code === "ENOENT";
}

function snapshotEntry(
  source: string,
  metadata: fs.Stats,
  kind: RootViewEntry["kind"],
  masked: boolean,
  linkTarget?: string,
): RootViewSnapshotEntry {
  return {
    source,
    target: source,
    kind,
    device: BigInt(metadata.dev),
    inode: BigInt(metadata.ino),
    ...(linkTarget === undefined ? {} : { linkTarget }),
    size: metadata.size,
    mtimeMs: metadata.mtimeMs,
    ctimeMs: metadata.ctimeMs,
    mode: metadata.mode,
    masked,
  };
}

function collectBlockedInodes(
  target: string,
  destination: Set<string>,
  deadlineMs: number,
  diagnostics: RootReadViewPlan["diagnostics"],
  actualTarget = target,
): void {
  if (Date.now() >= deadlineMs) throw new Error("sandbox_private_key_scan_failed");
  let metadata: fs.Stats;
  try { metadata = fs.lstatSync(actualTarget, { bigint: false }); } catch (error) {
    if (isMissingPathError(error)) return;
    throw new Error("sandbox_private_key_scan_failed");
  }
  if (metadata.isSymbolicLink()) return;
  if (metadata.isFile()) {
    const descriptor = fs.openSync(actualTarget, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    try {
      const opened = fs.fstatSync(descriptor);
      if (opened.dev !== metadata.dev || opened.ino !== metadata.ino) throw new Error("sandbox_root_changed");
    } finally {
      fs.closeSync(descriptor);
    }
    diagnostics.protected_files_scanned += 1;
    const sizeBefore = destination.size;
    destination.add(inodeKey(metadata));
    if (destination.size !== sizeBefore) diagnostics.protected_inodes_collected += 1;
    return;
  }
  if (!metadata.isDirectory()) return;
  diagnostics.protected_directories_scanned += 1;
  const descriptor = fs.openSync(
    actualTarget,
    fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW,
  );
  try {
    const opened = fs.fstatSync(descriptor);
    if (opened.dev !== metadata.dev || opened.ino !== metadata.ino) throw new Error("sandbox_root_changed");
    const fixedDirectory = `/proc/self/fd/${descriptor}`;
    for (const name of fs.readdirSync(fixedDirectory)) {
      collectBlockedInodes(
        path.join(target, name), destination, deadlineMs, diagnostics, path.join(fixedDirectory, name),
      );
    }
  } finally {
    fs.closeSync(descriptor);
  }
}

function assertProtectedTargetStable(target: string, expected: ProtectedTargetSnapshot | undefined): void {
  if (!expected) return;
  let metadata: fs.Stats;
  try { metadata = fs.lstatSync(target, { bigint: false }); } catch { throw new Error("sandbox_root_changed"); }
  const kind = metadata.isDirectory() ? "directory" : metadata.isFile() ? "file" : undefined;
  if (kind !== expected.kind || metadata.dev !== expected.device || metadata.ino !== expected.inode) {
    throw new Error("sandbox_root_changed");
  }
}

function startsWithPrivateKey(target: string, metadata: fs.Stats): boolean {
  if (metadata.size <= 0) return false;
  const descriptor = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const opened = fs.fstatSync(descriptor);
    if (opened.dev !== metadata.dev || opened.ino !== metadata.ino) throw new Error("sandbox_root_changed");
    const buffer = Buffer.allocUnsafe(Math.min(metadata.size, 4096));
    const count = fs.readSync(descriptor, buffer, 0, buffer.length, 0);
    return PRIVATE_KEY_HEADER.test(buffer.subarray(0, count).toString("utf8"));
  } finally {
    fs.closeSync(descriptor);
  }
}

function depth(target: string): number {
  return target.split(path.sep).filter(Boolean).length;
}

function inspectSymlink(target: string, root: string, blockedPaths: string[]): {
  linkTarget: string;
  unsafe: boolean;
} {
  const linkTarget = fs.readlinkSync(target);
  let resolved: string;
  try { resolved = fs.realpathSync(target); } catch { resolved = ""; }
  return {
    linkTarget,
    unsafe: !resolved || !inside(resolved, root)
      || blockedPaths.some((blocked) => inside(resolved, blocked)),
  };
}

export function createRootReadViewPlan(
  root: string,
  blockedPaths: string[],
  privateKeys: {
    index: PrivateKeyIndex;
    deadlineMs: number;
  },
): RootReadViewPlan {
  const rootMetadata = fs.statSync(root);
  const lexicalBlocked = [...new Set(blockedPaths.map((target) => path.resolve(target)))];
  const diagnostics: RootReadViewPlan["diagnostics"] = {
    blocked_targets_scanned: lexicalBlocked.length,
    protected_files_scanned: 0,
    protected_directories_scanned: 0,
    protected_inodes_collected: 0,
    scope_files_scanned: 0,
    scope_directories_scanned: 0,
    private_key_cache_hits: 0,
    private_key_cache_misses: 0,
    rewrite_parents: 0,
    rewrite_entries: 0,
    protected_scan_ms: 0,
    scope_walk_ms: 0,
    rewrite_ms: 0,
  };
  const blockedInodes = new Set<string>();
  const regularFilesByInode = new Map<string, string[]>();
  const snapshotByPath = new Map<string, RootViewSnapshotEntry>([
    [root, snapshotEntry(root, rootMetadata, "directory", false)],
  ]);
  const allProtectedTargets = [...new Set(lexicalBlocked.map((target) => {
    try { return fs.realpathSync(target); } catch (error) {
      if (isMissingPathError(error)) return target;
      throw new Error("sandbox_private_key_scan_failed");
    }
  }))];
  const protectedScanTargets = allProtectedTargets.filter((target) => !allProtectedTargets.some(
    (parent) => parent !== target && inside(target, parent),
  ));
  const protectedTargetSnapshots = new Map<string, ProtectedTargetSnapshot>();
  for (const target of protectedScanTargets) {
    let metadata: fs.Stats;
    try { metadata = fs.lstatSync(target, { bigint: false }); } catch (error) {
      if (isMissingPathError(error)) continue;
      throw new Error("sandbox_private_key_scan_failed");
    }
    if (metadata.isDirectory()) {
      protectedTargetSnapshots.set(target, { device: metadata.dev, inode: metadata.ino, kind: "directory" });
    } else if (metadata.isFile()) {
      protectedTargetSnapshots.set(target, { device: metadata.dev, inode: metadata.ino, kind: "file" });
    }
  }
  const masks = new Map<string, "file" | "directory">();
  const blockedDirectories = new Set<string>();
  const unsafeLinks = new Map<string, { device: bigint; inode: bigint; linkTarget: string }>();

  for (const target of lexicalBlocked) {
    if (!inside(target, root) || target === root) continue;
    let metadata: fs.Stats;
    try { metadata = fs.lstatSync(target); } catch { continue; }
    if (metadata.isSymbolicLink()) {
      snapshotByPath.set(target, snapshotEntry(target, metadata, "symlink", true, fs.readlinkSync(target)));
      unsafeLinks.set(target, {
        device: BigInt(metadata.dev),
        inode: BigInt(metadata.ino),
        linkTarget: fs.readlinkSync(target),
      });
    } else {
      const kind = metadata.isDirectory() ? "directory" : "file";
      snapshotByPath.set(target, snapshotEntry(target, metadata, kind, true));
      masks.set(target, kind);
      if (kind === "directory") blockedDirectories.add(target);
    }
  }

  const walk = (directory: string): void => {
    diagnostics.scope_directories_scanned += 1;
    for (const name of fs.readdirSync(directory)) {
      if (Date.now() >= privateKeys.deadlineMs) {
        throw new Error("sandbox_private_key_scan_failed");
      }
      const target = path.join(directory, name);
      if ([...blockedDirectories].some((blocked) => inside(target, blocked))) continue;
      const metadata = fs.lstatSync(target);
      if (metadata.dev !== rootMetadata.dev) throw new Error("sandbox_root_contains_nested_mount");
      if (metadata.isSymbolicLink()) {
        const link = inspectSymlink(target, root, lexicalBlocked);
        snapshotByPath.set(target, snapshotEntry(target, metadata, "symlink", link.unsafe, link.linkTarget));
        if (link.unsafe) {
          unsafeLinks.set(target, {
            device: BigInt(metadata.dev),
            inode: BigInt(metadata.ino),
            linkTarget: link.linkTarget,
          });
        }
        continue;
      }
      if (metadata.isDirectory()) {
        snapshotByPath.set(target, snapshotEntry(target, metadata, "directory", false));
        walk(target);
        continue;
      }
      if (!metadata.isFile()) {
        snapshotByPath.set(target, snapshotEntry(target, metadata, "file", true));
        masks.set(target, "file");
        continue;
      }
      diagnostics.scope_files_scanned += 1;
      const key = inodeKey(metadata);
      const aliases = regularFilesByInode.get(key) ?? [];
      aliases.push(target);
      regularFilesByInode.set(key, aliases);
      snapshotByPath.set(target, snapshotEntry(target, metadata, "file", false));
      if (isSecretEnvFile(name)) blockedInodes.add(key);
      if (privateKeys.index.classify(target, metadata, diagnostics)) {
        blockedInodes.add(key);
      }
    }
  };
  const scopeWalkStartedAt = Date.now();
  walk(root);
  diagnostics.scope_walk_ms = Date.now() - scopeWalkStartedAt;
  const protectedScanStartedAt = Date.now();
  protectedScanTargets.forEach((target) => {
    const expected = protectedTargetSnapshots.get(target);
    assertProtectedTargetStable(target, expected);
    collectBlockedInodes(target, blockedInodes, privateKeys.deadlineMs, diagnostics);
    assertProtectedTargetStable(target, expected);
  });
  diagnostics.protected_scan_ms = Date.now() - protectedScanStartedAt;
  privateKeys.index.retain(new Set(regularFilesByInode.keys()));
  for (const key of blockedInodes) {
    for (const target of regularFilesByInode.get(key) ?? []) {
      masks.set(target, "file");
      const entry = snapshotByPath.get(target);
      if (entry) entry.masked = true;
    }
  }

  const rewriteStartedAt = Date.now();
  const rewrittenParents = [...new Set([...unsafeLinks.keys()].map((target) => path.dirname(target)))]
    .sort((left, right) => depth(left) - depth(right) || left.localeCompare(right));
  const directOmissions = new Set([...masks.keys(), ...unsafeLinks.keys()]);
  const rewrites = rewrittenParents.map((target): RootViewRewrite => {
    const entries: RootViewEntry[] = [];
    for (const name of fs.readdirSync(target)) {
      const source = path.join(target, name);
      if (directOmissions.has(source)) continue;
      const metadata = fs.lstatSync(source);
      if (metadata.isSymbolicLink()) {
        const link = inspectSymlink(source, root, lexicalBlocked);
        if (link.unsafe) continue;
        entries.push({
          source,
          target: source,
          kind: "symlink",
          device: BigInt(metadata.dev),
          inode: BigInt(metadata.ino),
          linkTarget: link.linkTarget,
        });
      } else if (metadata.isDirectory() || metadata.isFile()) {
        entries.push({
          source,
          target: source,
          kind: metadata.isDirectory() ? "directory" : "file",
          device: BigInt(metadata.dev),
          inode: BigInt(metadata.ino),
        });
      }
    }
    return { target, entries };
  });
  diagnostics.rewrite_parents = rewrites.length;
  diagnostics.rewrite_entries = rewrites.reduce((count, rewrite) => count + rewrite.entries.length, 0);
  diagnostics.rewrite_ms = Date.now() - rewriteStartedAt;

  const maskedDirectories = [...snapshotByPath.values()].filter((entry) => entry.kind === "directory" && entry.masked);
  const snapshot = [...snapshotByPath.values()].filter((entry) => !maskedDirectories.some(
    (directory) => directory.source !== entry.source && inside(entry.source, directory.source),
  ));

  const rewrittenDirectChildren = new Set(rewrittenParents.flatMap((parent) => (
    [...masks.keys()].filter((target) => path.dirname(target) === parent)
  )));
  return {
    masks: [...masks]
      .filter(([target]) => !rewrittenDirectChildren.has(target))
      .map(([target, kind]) => ({ target, kind })),
    rewrites,
    snapshot,
    diagnostics,
  };
}

function snapshotKind(metadata: fs.Stats): RootViewEntry["kind"] {
  if (metadata.isSymbolicLink()) return "symlink";
  return metadata.isDirectory() ? "directory" : "file";
}

function matchesSnapshot(
  expected: RootViewSnapshotEntry,
  target: string,
  metadata: fs.Stats,
  actualTarget = target,
): boolean {
  return expected.source === target
    && expected.kind === snapshotKind(metadata)
    && expected.device === BigInt(metadata.dev)
    && expected.inode === BigInt(metadata.ino)
    && expected.size === metadata.size
    && expected.mtimeMs === metadata.mtimeMs
    && expected.ctimeMs === metadata.ctimeMs
    && expected.mode === metadata.mode
    && (expected.kind !== "symlink" || expected.linkTarget === fs.readlinkSync(actualTarget));
}

export function verifyRootReadViewPlan(root: string, plan: RootReadViewPlan, fixedRootFd?: number): void {
  const expected = new Map(plan.snapshot.map((entry) => [entry.source, entry]));
  const rootEntry = expected.get(root);
  if (!rootEntry) throw new Error("sandbox_root_changed");
  let rootMetadata: fs.Stats;
  try { rootMetadata = fs.lstatSync(root); } catch { throw new Error("sandbox_root_changed"); }
  if (fixedRootFd !== undefined) {
    let fixedRootMetadata: fs.Stats;
    try { fixedRootMetadata = fs.fstatSync(fixedRootFd); } catch { throw new Error("sandbox_root_changed"); }
    if (fixedRootMetadata.dev !== rootMetadata.dev
        || fixedRootMetadata.ino !== rootMetadata.ino
        || !fixedRootMetadata.isDirectory()) {
      throw new Error("sandbox_root_changed");
    }
  }
  if (!matchesSnapshot(rootEntry, root, rootMetadata)) throw new Error("sandbox_root_changed");

  const observed = new Set<string>([root]);
  const actualRoot = fixedRootFd === undefined ? root : `/proc/self/fd/${fixedRootFd}`;
  const walk = (directory: string, actualDirectory: string): void => {
    let names: string[];
    try { names = fs.readdirSync(actualDirectory); } catch { throw new Error("sandbox_root_changed"); }
    for (const name of names) {
      const target = path.join(directory, name);
      const actualTarget = path.join(actualDirectory, name);
      const entry = expected.get(target);
      if (!entry) throw new Error("sandbox_root_changed");
      let metadata: fs.Stats;
      try { metadata = fs.lstatSync(actualTarget); } catch { throw new Error("sandbox_root_changed"); }
      if (!matchesSnapshot(entry, target, metadata, actualTarget)) throw new Error("sandbox_root_changed");
      observed.add(target);
      if (entry.kind === "directory" && !entry.masked) walk(target, actualTarget);
    }
  };
  walk(root, actualRoot);
  if (observed.size !== expected.size) throw new Error("sandbox_root_changed");
}
