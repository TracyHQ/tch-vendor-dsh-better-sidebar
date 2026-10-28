/**
 * Workspace containment for the sidebar's filesystem routes.
 *
 * Every route that touches the host filesystem resolves the client's target
 * through this module: the (possibly WSL-projected) path is made absolute,
 * and refused with 403 when its `realpath` is not under the session
 * workspace's `realpath` (so a symlink inside the workspace cannot lead out of
 * it, and Windows short names / letter case cannot fool the comparison).
 * Every function returns BOTH forms ({@link WorkspacePath}): the canonical
 * path that was checked, which every filesystem operation must use (closing
 * the check-then-use gap a swapped symlink component would open), and the
 * caller's spelling, used only for values returned to the client. The workspace itself is the session's own
 * recorded cwd (see `sessionCwdOf` in index.ts) — never a client value.
 *
 * Commit 5c95002 once removed this guard to "open up" the routes; that let an
 * unauthenticated caller read and write any host file, so the guard is back
 * and unconditional. The legitimate parts of that change stay: the fast
 * `fs.tree` listing, the batch `fs.trees` route, and WSL path projection.
 */
import { realpath } from 'node:fs/promises'
import { basename, dirname, join } from 'node:path'
import { isWithin, requireAbsolute } from './fs-tree.ts'
import { resolveSessionPath } from './session-path.ts'
import { SidebarError } from './wire.ts'

/** Resolve a path and convert filesystem resolution failures to an API error. */
async function resolveRealPath(path: string, label: string): Promise<string> {
  try {
    return await realpath(path)
  } catch (error) {
    throw new SidebarError('fs-error', `cannot resolve ${label} "${path}": ${error instanceof Error ? error.message : String(error)}`, 400)
  }
}

/** Reject a canonical path whose real filesystem target escapes the workspace. */
export function assertWithinWorkspace(workspace: string, target: string): void {
  if (!isWithin(workspace, target)) {
    throw new SidebarError('forbidden', `path "${target}" is outside workspace`, 403)
  }
}

/** Whether two canonical paths name the same location (platform case rules). */
export function samePath(left: string, right: string): boolean {
  return isWithin(left, right) && isWithin(right, left)
}

/** The canonical (symlink-free) session workspace root. */
export async function realWorkspace(cwd: string): Promise<string> {
  return resolveRealPath(requireAbsolute(cwd), 'workspace')
}

/**
 * One contained path in its two spellings.
 *
 * `real` is the canonical path the containment check approved: EVERY
 * filesystem operation (read, write, mkdir, rename, rm, upload stream, watch,
 * listing and its cache) must use it, so a symlink component swapped after
 * the check cannot redirect the operation. `display` is the caller's own
 * spelling of the same location: use it ONLY for values handed back to the
 * client (response paths, client-visible watch keys), never for I/O.
 */
export interface WorkspacePath {
  /** Canonical, containment-checked path: the only form used for I/O. */
  real: string
  /** The caller's spelling (lexical absolute path): responses only. */
  display: string
}

/**
 * Resolve an existing path and enforce containment.
 *
 * @param cwd - Session workspace directory (the server's own record).
 * @param target - Client-supplied absolute path in the session's namespace.
 * @returns the canonical path (`real`, for I/O) and the caller's spelling
 *  (`display`, for responses).
 * @throws SidebarError `forbidden` (403) when the target lies outside the workspace.
 */
export async function ensureWorkspacePath(cwd: string, target: string): Promise<WorkspacePath> {
  const display = requireAbsolute(resolveSessionPath(cwd, target))
  const [realCwd, real] = await Promise.all([
    realWorkspace(cwd),
    resolveRealPath(display, 'target'),
  ])
  assertWithinWorkspace(realCwd, real)
  return { real, display }
}

/**
 * Validate a write destination, including destinations that do not exist yet.
 * The canonical form of an existing target is its realpath (catching a
 * symlink that leads out); of a missing target, the realpath of its nearest
 * existing ancestor plus the missing segments — so the write never passes
 * through an unchecked symlink.
 *
 * @param cwd - Session workspace directory (the server's own record).
 * @param target - Client-supplied absolute destination path in the session's namespace.
 * @returns the canonical destination (`real`, for I/O) and the caller's
 *  spelling (`display`, for responses).
 * @throws SidebarError `forbidden` (403) when the destination lies outside the workspace.
 */
export async function ensureWorkspaceWritePath(cwd: string, target: string): Promise<WorkspacePath> {
  const display = requireAbsolute(resolveSessionPath(cwd, target))
  const [realCwd, real] = await Promise.all([realWorkspace(cwd), canonicalDestination(display)])
  assertWithinWorkspace(realCwd, real)
  return { real, display }
}

/**
 * The canonical form of a possibly-missing path: realpath of the nearest
 * existing ancestor joined with the missing segments.
 */
async function canonicalDestination(absolute: string): Promise<string> {
  let existingPath = absolute
  const missingSegments: string[] = []
  for (;;) {
    let realTarget: string
    try {
      realTarget = await realpath(existingPath)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw new SidebarError('fs-error', `cannot resolve target "${existingPath}": ${error instanceof Error ? error.message : String(error)}`, 400)
      }
      const parent = dirname(existingPath)
      if (parent === existingPath) {
        throw new SidebarError('fs-error', `cannot resolve target "${absolute}"`, 400)
      }
      missingSegments.unshift(basename(existingPath))
      existingPath = parent
      continue
    }
    return missingSegments.reduce((path, segment) => join(path, segment), realTarget)
  }
}

/**
 * Resolve an existing entry for a link-aware mutation (rename / remove): the
 * PARENT is canonicalized and must lie inside the workspace, the last segment
 * is kept as written so a symlink row addresses the link itself, not its
 * target.
 *
 * @param cwd - Session workspace directory (the server's own record).
 * @param target - Client-supplied absolute path of the row.
 * @returns `real`: canonical parent + the row's own name (for I/O and the
 *  "is this the root" comparison against `realCwd`); `display`: the caller's
 *  spelling (responses only).
 */
export async function ensureWorkspaceEntry(cwd: string, target: string): Promise<WorkspacePath & { realCwd: string }> {
  const display = requireAbsolute(resolveSessionPath(cwd, target))
  const realCwd = await realWorkspace(cwd)
  const parent = dirname(display)
  const real = parent === display
    ? await resolveRealPath(display, 'target')
    : join(await resolveRealPath(parent, 'target'), basename(display))
  assertWithinWorkspace(realCwd, real)
  return { real, display, realCwd }
}
