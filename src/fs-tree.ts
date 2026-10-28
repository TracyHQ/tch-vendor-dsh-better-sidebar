/**
 * Single-level directory listing for the sidebar explorer.
 *
 * The hot path here IS the explorer's latency budget, so the implementation is
 * deliberately allocation-shy: one `readdir(withFileTypes)` call (no
 * `opendir` stream), rows built only for the capped slice, paths composed by
 * string concatenation, and a hand-rolled case-insensitive sort (see
 * {@link compareEntries} — `localeCompare` alone costs ~15ms/10k rows, ~40x
 * the whole listing budget). A short TTL cache ({@link DIRECTORY_CACHE_TTL_MS})
 * absorbs the repeat listings a tree view makes on every re-render.
 *
 * Row semantics are unchanged: directories first, case-insensitive name order
 * with a deterministic tie-break, POSIX-hidden entries flagged for dimming,
 * symlinks stat'ed once so a link to a directory expands like a directory and
 * a dangling one is flagged broken.
 */
import { readdir, realpath, stat } from 'node:fs/promises'
import { basename, dirname, isAbsolute, resolve, sep } from 'node:path'
import { SidebarError } from './wire.ts'

/** One explorer row. */
export interface SidebarFsEntry {
  name: string
  path: string
  isDir: boolean
  hidden: boolean
  /** Whether the row is a symlink; `isDir` then describes the link's target. */
  isSymlink: boolean
  /** For symlinks: the target is missing or unreadable (stat failed). */
  broken: boolean
}

/** One listed level. */
export interface SidebarFsListing {
  path: string
  entries: SidebarFsEntry[]
  truncated: boolean
}

/**
 * Directory-first, case-insensitive name ordering (VSCode explorer order).
 *
 * `toLowerCase()` + code-point comparison instead of `localeCompare`: measured
 * at ~0.35ms/10k rows against ~14.6ms for the collator, and the tie-break on
 * the ORIGINAL name keeps the order total and deterministic for names that
 * only differ in case (`A` before `a`).
 */
export function compareEntries(a: SidebarFsEntry, b: SidebarFsEntry): number {
  if (a.isDir !== b.isDir) return a.isDir ? -1 : 1
  const la = a.name.toLowerCase()
  const lb = b.name.toLowerCase()
  if (la !== lb) return la < lb ? -1 : 1
  if (a.name === b.name) return 0
  return a.name < b.name ? -1 : 1
}

/** How many symlink target stats run in flight during one level listing. */
const SYMLINK_PROBE_CONCURRENCY = 32

/**
 * How long one listed level stays valid. Short on purpose: it absorbs the
 * re-listing a re-render (or a burst of tree opens) causes without hiding
 * changes for perceptibly long, and every writer invalidates it explicitly
 * anyway (see {@link invalidateDirectoryCache}).
 */
export const DIRECTORY_CACHE_TTL_MS = 1_500

/**
 * The level cache, keyed by `"<absoluteDir>\0<cap>"`.
 *
 * Keyed by ABSOLUTE PATH, not by session: a listing is a pure function of the
 * path plus the cap, and its rows already carry absolute paths, so sharing an
 * entry between two sessions that read the same directory is correct (and
 * desirable — one directory read serves both). Nothing session-scoped is
 * stored, so no session's data can leak into another's listing.
 */
const directoryCache = new Map<string, { at: number; listing: SidebarFsListing }>()

/** Cache key of one level read. The containment root is part of the key:
 *  symlink rows are only followed when their target lies inside it, so the
 *  same directory can list differently for two (nested) workspaces. */
function cacheKey(path: string, maxEntries: number, root: string | undefined): string {
  return `${path}\0${maxEntries}\0${root ?? ''}`
}

/**
 * Drop the cached level(s) for one directory (and, when called with no
 * argument, everything). Writers call this after any mutation: `fs.write`,
 * `fs.rename`, `fs.remove`, `fs.mkdir`, the upload route and the fs-watch
 * notifier all funnel here, so a stale level is never served past the write
 * that changed it.
 * @param path - absolute (or session-relative) directory to invalidate; absent
 *  clears the whole cache.
 */
export function invalidateDirectoryCache(path?: string): void {
  if (path === undefined) {
    directoryCache.clear()
    return
  }
  const target = resolve(path)
  const prefix = `${target}\0`
  for (const key of directoryCache.keys()) {
    if (key.startsWith(prefix)) directoryCache.delete(key)
  }
}

/** Max entries tracked in the TTL cache before the oldest are evicted. */
const DIRECTORY_CACHE_MAX = 512

/** Read one level through the cache when it is fresh. */
async function listDirectoryCached(path: string, maxEntries: number, root: string | undefined): Promise<SidebarFsListing> {
  const key = cacheKey(path, maxEntries, root)
  const now = Date.now()
  const hit = directoryCache.get(key)
  if (hit !== undefined && now - hit.at < DIRECTORY_CACHE_TTL_MS) return hit.listing
  const listing = await readDirectory(path, maxEntries, root)
  // Bounded: a deep walk of many directories must not grow this map without
  // limit (entries are tiny, but an unbounded map in a long-lived host is a
  // leak). Map iteration order is insertion order, so the first key is oldest.
  if (directoryCache.size >= DIRECTORY_CACHE_MAX) {
    const oldest = directoryCache.keys().next().value
    if (oldest !== undefined) directoryCache.delete(oldest)
  }
  directoryCache.set(key, { at: now, listing })
  return listing
}

/**
 * List one directory level (cached for {@link DIRECTORY_CACHE_TTL_MS}).
 * @param path - absolute directory path.
 * @param maxEntries - row bound of one level (extra rows flag `truncated`).
 * @param root - canonical containment root (the session workspace). When set,
 *  a symlink row is only followed (stat'ed) when its canonical target lies
 *  inside it; a link leading out is kept as a row but reported the way the
 *  client shows a link it cannot open (`isDir: false`, `broken: true`).
 * @returns the sorted listing.
 * @throws {SidebarError} fs-error when the level is unreadable or not a directory.
 */
export async function listDirectory(path: string, maxEntries = 1000, root?: string): Promise<SidebarFsListing> {
  return await listDirectoryCached(path, maxEntries, root)
}

/**
 * Re-spell a listing read at its canonical path in the caller's spelling:
 * the level path and every row path get `display` as their prefix. The
 * cached listing is never mutated (a fresh object is returned).
 * @param listing - the listing as read (and cached) at the canonical path.
 * @param display - the caller's spelling of the same directory.
 * @returns the listing as the client should see it.
 */
export function respellListing(listing: SidebarFsListing, display: string): SidebarFsListing {
  if (listing.path === display) return listing
  const prefix = display.endsWith(sep) ? display : `${display}${sep}`
  return {
    path: display,
    truncated: listing.truncated,
    entries: listing.entries.map(entry => ({ ...entry, path: `${prefix}${entry.name}` })),
  }
}

/** Read one level straight from the filesystem (the cache's slow path). */
async function readDirectory(path: string, maxEntries: number, root: string | undefined): Promise<SidebarFsListing> {
  let dirents
  try {
    // One syscall batch instead of an `opendir` stream: `readdir` with types is
    // roughly half the wall time of `for await (const dirent of await opendir())`
    // and gives the same Dirent objects.
    dirents = await readdir(path, { withFileTypes: true })
  } catch (error) {
    throw new SidebarError('fs-error', `cannot list "${path}": ${messageOf(error)}`, 400)
  }
  const truncated = dirents.length > maxEntries
  // Build rows ONLY for the rows that survive the cap: composing a row costs
  // ~0.3µs (path concat + three flags), so an uncapped 10k level would spend
  // ~3ms on rows nobody will see.
  const kept = truncated ? dirents.slice(0, maxEntries) : dirents
  const prefix = path.endsWith(sep) ? path : `${path}${sep}`
  const rows: SidebarFsEntry[] = new Array(kept.length)
  for (let index = 0; index < kept.length; index += 1) {
    const dirent = kept[index]!
    // String concat over `path.join`: ~10x faster on 10k rows, and the
    // separator stays platform-correct (`sep`).
    rows[index] = {
      name: dirent.name,
      path: `${prefix}${dirent.name}`,
      isDir: dirent.isDirectory(),
      isSymlink: dirent.isSymbolicLink(),
      broken: false,
      hidden: dirent.name.startsWith('.'),
    }
  }
  // Probe symlink targets AFTER the read, with bounded concurrency: a
  // symlink-heavy level (UNC/network targets) would otherwise serialize up to
  // maxEntries stat calls and stall the explorer. Non-symlink rows are skipped,
  // so levels without links stay as cheap as before.
  await probeSymlinkTargets(rows, root)
  rows.sort(compareEntries)
  return { path, entries: rows, truncated }
}

/** Probe each symlink row's target once (bounded concurrency, order-preserving). */
async function probeSymlinkTargets(rows: SidebarFsEntry[], root: string | undefined, concurrency = SYMLINK_PROBE_CONCURRENCY): Promise<void> {
  let next = 0
  const workers = Array.from({ length: Math.min(concurrency, rows.length) }, async () => {
    for (;;) {
      const index = next
      next += 1
      if (index >= rows.length) return
      const row = rows[index]!
      if (!row.isSymlink) continue
      // stat follows the chain; any failure (missing target, ELOOP, permission)
      // leaves the row as a broken file-shaped link the editor refuses to read.
      // With a containment root the target is resolved first and only stat'ed
      // (canonically) when it lies inside the root: a link leading out is
      // reported the same broken, file-shaped way, without touching its target.
      let target = row.path
      if (root !== undefined) {
        const real = await realpath(row.path).catch(() => undefined)
        if (real === undefined || !isWithin(root, real)) {
          row.isDir = false
          row.broken = true
          continue
        }
        target = real
      }
      const info = await stat(target).catch(() => undefined)
      row.isDir = info !== undefined ? info.isDirectory() : row.isDir
      row.broken = info === undefined
    }
  })
  await Promise.all(workers)
}

/** The root row label of a listing: the last path segment (or the full path at the filesystem root). */
export function rootLabel(path: string): string {
  const base = basename(path)
  return base !== '' ? base : path
}

/** Parent of a path, or undefined at the filesystem root (the explorer's "up" target). */
export function parentOf(path: string): string | undefined {
  const parent = dirname(path)
  return parent === path ? undefined : parent
}

/**
 * Normalize a caller-supplied path to an absolute, resolved path or throw
 * fs-error. `path.isAbsolute()` is the OS's own notion of absolute: POSIX
 * roots (`/...`), Windows drive letters (`C:\...`) and — on win32 — UNC
 * network shares (`\\server\share\...`); drive-relative forms (`C:foo`)
 * stay rejected.
 */
export function requireAbsolute(path: string): string {
  if (!isAbsolute(path)) {
    throw new SidebarError('fs-error', `"${path}" is not an absolute path`, 400)
  }
  return resolve(path)
}

/**
 * Whether `target` lies under `base` (or equals it), tolerant of separator
 * style and — on Windows, where the filesystem is case-insensitive — of
 * letter case.
 *
 * Lexical by itself: path-security.ts calls it on REALPATH-canonicalized
 * paths, which is what makes it the workspace containment check.
 * @param platform - filesystem semantics; injectable so both branches are
 *  unit-testable on any host.
 */
export function isWithin(base: string, target: string, platform: NodeJS.Platform = process.platform): boolean {
  const norm = (value: string): string => value.replace(/[\\/]+/g, '/').replace(/\/$/, '')
  const b = norm(base)
  const t = norm(target)
  if (platform === 'win32') {
    const lb = b.toLowerCase()
    const lt = t.toLowerCase()
    return lt === lb || lt.startsWith(`${lb}/`)
  }
  return t === b || t.startsWith(`${b}/`)
}

/** Message text of an unknown thrown value. */
export function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}
