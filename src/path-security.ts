/**
 * Workspace containment for the sidebar's filesystem routes.
 *
 * Every route that touches the host filesystem resolves the client's target
 * through this module: the (possibly WSL-projected) path is made absolute,
 * canonicalized through `realpath` (so a symlink inside the workspace cannot
 * lead out of it), and refused with 403 when the canonical target is not under
 * the canonical session workspace. The workspace itself is the session's own
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

/** The canonical (symlink-free) session workspace root. */
export async function realWorkspace(cwd: string): Promise<string> {
  return resolveRealPath(requireAbsolute(cwd), 'workspace')
}

/**
 * Resolve an existing path through symlinks and enforce containment.
 *
 * @param cwd - Session workspace directory (the server's own record).
 * @param target - Client-supplied absolute path in the session's namespace.
 * @returns The canonical absolute path used for the filesystem operation.
 * @throws SidebarError `forbidden` (403) when the target lies outside the workspace.
 */
export async function ensureWorkspacePath(cwd: string, target: string): Promise<string> {
  const absolute = requireAbsolute(resolveSessionPath(cwd, target))
  const [realCwd, realTarget] = await Promise.all([
    realWorkspace(cwd),
    resolveRealPath(absolute, 'target'),
  ])
  assertWithinWorkspace(realCwd, realTarget)
  return realTarget
}

/**
 * Validate a write destination, including destinations that do not exist yet.
 * Existing targets are resolved to catch symlinks; missing targets are checked
 * against the realpath of their nearest existing ancestor before the caller
 * creates or renames. The returned path is rebuilt from that canonical
 * ancestor, so an existing symlink is never left in the path passed to the
 * write operation.
 *
 * @param cwd - Session workspace directory (the server's own record).
 * @param target - Client-supplied absolute destination path in the session's namespace.
 * @returns A canonical path for an existing target or its nearest existing ancestor.
 * @throws SidebarError `forbidden` (403) when the destination lies outside the workspace.
 */
export async function ensureWorkspaceWritePath(cwd: string, target: string): Promise<string> {
  const absolute = requireAbsolute(resolveSessionPath(cwd, target))
  const realCwd = await realWorkspace(cwd)
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
    const destination = missingSegments.reduce((path, segment) => join(path, segment), realTarget)
    assertWithinWorkspace(realCwd, destination)
    return destination
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
 * @returns the canonical entry path and the canonical workspace root.
 */
export async function ensureWorkspaceEntry(cwd: string, target: string): Promise<{ entry: string; realCwd: string }> {
  const absolute = requireAbsolute(resolveSessionPath(cwd, target))
  const realCwd = await realWorkspace(cwd)
  const parent = dirname(absolute)
  const entry = parent === absolute
    ? absolute
    : join(await resolveRealPath(parent, 'target'), basename(absolute))
  assertWithinWorkspace(realCwd, entry)
  return { entry, realCwd }
}
