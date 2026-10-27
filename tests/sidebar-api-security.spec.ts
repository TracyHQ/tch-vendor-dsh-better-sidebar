/**
 * Security regression: the /sidebar/* routes must not let a caller read or
 * write host files outside a real session's workspace, and must sit behind
 * the host Connection's authenticated admission check.
 *
 * Drives the REAL plugin through a real node:http server: the registered route
 * handlers, the JSON body parser, the Host/Origin fence, the path functions and
 * real file I/O. Only the host services the routes consume are faked (session
 * store, Connection admission, webServer registration).
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { spawnSync } from 'node:child_process'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import type { Duplex } from 'node:stream'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import WebSocket from 'ws'
import { apply } from '../src/index.ts'
import type { SidebarWebRoute, SidebarWebUpgradeRoute } from '../src/context-types.ts'

const AUTH_COOKIE = 'dsh-test-auth=ok'
const SESSION = 's-real'

/** Symlink creation may require elevated privileges on Windows. */
const canCreateSymlink = (() => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-sidebar-sec-probe-'))
  try {
    mkdirSync(join(dir, 'target'))
    symlinkSync(join(dir, 'target'), join(dir, 'link'))
    return true
  } catch {
    return false
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})()

let root: string
let workspace: string
let outside: string
let server: Server
let base: string
const effects: Array<() => void> = []

beforeAll(async () => {
  root = realpathSync(mkdtempSync(join(tmpdir(), 'dsh-sidebar-sec-')))
  workspace = join(root, 'workspace')
  outside = join(root, 'outside')
  mkdirSync(workspace)
  mkdirSync(outside)
  writeFileSync(join(workspace, 'inside.txt'), 'inside marker')
  writeFileSync(join(outside, 'secret.txt'), 'outside marker')
  if (canCreateSymlink) {
    symlinkSync(join(outside, 'secret.txt'), join(workspace, 'link-file'))
    symlinkSync(outside, join(workspace, 'link-dir'))
  }

  const routes: SidebarWebRoute[] = []
  const upgrades: SidebarWebUpgradeRoute[] = []
  const ctx = {
    webRuntime: { trustedHosts: [] },
    // The host Connection's admission check: a signed browser cookie
    // authenticates; anything else is 401 (the real one also runs the fence).
    connection: {
      requestRejection: (req: { headers: Record<string, unknown> }) =>
        req.headers.cookie === AUTH_COOKIE ? undefined : 401,
    },
    webServer: {
      register: (route: SidebarWebRoute) => { routes.push(route); return () => {} },
      registerUpgrade: (route: SidebarWebUpgradeRoute) => { upgrades.push(route); return () => {} },
    },
    sessions: { get: (id: string) => (id === SESSION ? { header: { cwd: workspace } } : undefined) },
    tools: { register: () => () => {} },
    effect: (fn: () => void | (() => void)) => {
      const cleanup = fn()
      if (typeof cleanup === 'function') effects.push(cleanup)
    },
    inject: () => () => {},
    on: () => () => {},
    get: () => undefined,
    logger: { warn: () => {} },
  }
  apply(ctx as never)

  const match = (pathname: string): SidebarWebRoute | undefined =>
    routes.find(route => route.kind === 'exact' ? route.path === pathname : pathname === route.path || pathname.startsWith(`${route.path}/`))
  server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const route = match(new URL(req.url ?? '/', 'http://x').pathname)
    if (route === undefined) {
      res.writeHead(404)
      res.end()
      return
    }
    void route.handler(req as never, res as never)
  })
  server.on('upgrade', (req: IncomingMessage, socket: Duplex, head: Buffer) => {
    const route = upgrades.find(candidate => candidate.path === new URL(req.url ?? '/', 'http://x').pathname)
    if (route === undefined) {
      socket.destroy()
      return
    }
    void route.handler(req as never, socket as never, head as never)
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('no port')
  base = `http://127.0.0.1:${address.port}`
})

afterAll(async () => {
  for (const cleanup of effects) cleanup()
  server.closeAllConnections()
  await new Promise<void>(resolve => server.close(() => resolve()))
  rmSync(root, { recursive: true, force: true })
})

async function call(method: string, payload: unknown, auth = true): Promise<{ status: number; body: { ok: boolean; value?: unknown; error?: { code: string } } }> {
  const response = await fetch(`${base}/sidebar/api/${method}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(auth ? { cookie: AUTH_COOKIE } : {}) },
    body: JSON.stringify(payload),
  })
  return { status: response.status, body: await response.json() as never }
}

describe('/sidebar routes: admission', () => {
  it('refuses an unauthenticated loopback request with no Origin', async () => {
    const result = await call('fs.read', { sessionId: SESSION, path: join(workspace, 'inside.txt') }, false)
    expect(result.status).toBe(401)
    expect(result.body.ok).toBe(false)
  })

  it('refuses an unauthenticated media request', async () => {
    const url = `${base}/sidebar/file?sessionId=${SESSION}&path=${encodeURIComponent(join(workspace, 'inside.txt'))}`
    const response = await fetch(url)
    expect(response.status).toBe(401)
    await response.arrayBuffer()
  })

  it('keeps the Host/Origin fence as an extra layer for authenticated requests', async () => {
    const response = await fetch(`${base}/sidebar/api/fs.read`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: AUTH_COOKIE, origin: 'https://evil.example' },
      body: JSON.stringify({ sessionId: SESSION, path: join(workspace, 'inside.txt') }),
    })
    expect(response.status).toBe(403)
    await response.arrayBuffer()
  })

  it('refuses an unauthenticated WebSocket upgrade', async () => {
    const ws = new WebSocket(`${base.replace('http', 'ws')}/sidebar/ws/fs-watch?sessionId=${SESSION}`)
    const outcome = await new Promise<string>((resolve) => {
      ws.once('open', () => resolve('open'))
      ws.once('error', () => resolve('error'))
      ws.once('unexpected-response', (_req, res) => resolve(`status ${res.statusCode}`))
    })
    ws.terminate()
    expect(outcome).not.toBe('open')
  })

  it('accepts an authenticated WebSocket upgrade', async () => {
    const ws = new WebSocket(`${base.replace('http', 'ws')}/sidebar/ws/fs-watch?sessionId=${SESSION}`, { headers: { cookie: AUTH_COOKIE } })
    const outcome = await new Promise<string>((resolve) => {
      ws.once('open', () => resolve('open'))
      ws.once('error', () => resolve('error'))
    })
    ws.close()
    expect(outcome).toBe('open')
  })
})

describe('/sidebar routes: session and workspace containment', () => {
  it('refuses a nonexistent session even when the caller supplies a cwd', async () => {
    const result = await call('fs.read', { sessionId: 's-missing', cwd: outside, path: join(outside, 'secret.txt') })
    expect(result.body.ok).toBe(false)
    expect(result.status).toBeGreaterThanOrEqual(400)
    expect(JSON.stringify(result.body)).not.toContain('outside marker')
  })

  it('ignores a client cwd for a real session', async () => {
    const result = await call('session.cwd', { sessionId: SESSION, cwd: outside })
    expect(result.status).toBe(200)
    expect((result.body.value as { cwd: string }).cwd).toBe(workspace)
  })

  it('refuses reading an absolute path outside the workspace', async () => {
    const result = await call('fs.read', { sessionId: SESSION, path: join(outside, 'secret.txt') })
    expect(result.status).toBe(403)
    expect(JSON.stringify(result.body)).not.toContain('outside marker')
  })

  it('refuses a dot-dot escape', async () => {
    const result = await call('fs.read', { sessionId: SESSION, path: `${workspace}/../outside/secret.txt` })
    expect(result.status).toBe(403)
  })

  it('refuses writing a path outside the workspace and creates nothing', async () => {
    const target = join(outside, 'created.txt')
    const result = await call('fs.write', { sessionId: SESSION, path: target, content: 'pwned' })
    expect(result.status).toBe(403)
    expect(existsSync(target)).toBe(false)
  })

  it('refuses listing a directory outside the workspace', async () => {
    const result = await call('fs.tree', { sessionId: SESSION, path: outside })
    expect(result.status).toBe(403)
  })

  it('refuses a media read outside the workspace', async () => {
    const url = `${base}/sidebar/file?sessionId=${SESSION}&path=${encodeURIComponent(join(outside, 'secret.txt'))}`
    const response = await fetch(url, { headers: { cookie: AUTH_COOKIE } })
    expect(response.status).toBe(403)
    expect(await response.text()).not.toContain('outside marker')
  })

  it.skipIf(!canCreateSymlink)('refuses reading through a symlink that leaves the workspace', async () => {
    const result = await call('fs.read', { sessionId: SESSION, path: join(workspace, 'link-file') })
    expect(result.status).toBe(403)
  })

  it.skipIf(!canCreateSymlink)('refuses writing through a symlinked directory that leaves the workspace', async () => {
    const result = await call('fs.write', { sessionId: SESSION, path: join(workspace, 'link-dir', 'new', 'x.txt'), content: 'pwned' })
    expect(result.status).toBe(403)
    expect(existsSync(join(outside, 'new'))).toBe(false)
  })

  it.skipIf(!canCreateSymlink)('refuses overwriting a file through a symlink that leaves the workspace', async () => {
    const result = await call('fs.write', { sessionId: SESSION, path: join(workspace, 'link-file'), content: 'pwned' })
    expect(result.status).toBe(403)
    expect(readFileSync(join(outside, 'secret.txt'), 'utf8')).toBe('outside marker')
  })
})

describe('/sidebar routes: normal use inside the workspace', () => {
  it('reads and writes files inside the session workspace', async () => {
    const read = await call('fs.read', { sessionId: SESSION, path: join(workspace, 'inside.txt') })
    expect(read.status).toBe(200)
    expect(read.body.value).toEqual({ kind: 'text', content: 'inside marker', truncated: false })

    const target = join(workspace, 'sub', 'dir', 'new.txt')
    const write = await call('fs.write', { sessionId: SESSION, path: target, content: 'hello' })
    expect(write.status).toBe(200)
    expect(readFileSync(target, 'utf8')).toBe('hello')

    const tree = await call('fs.tree', { sessionId: SESSION })
    expect(tree.status).toBe(200)
  })
})

describe('/sidebar git routes: workspace containment (nested session in a repository)', () => {
  // A real repository whose session cwd is the `sub/` directory: files at
  // the repository top level lie OUTSIDE the session workspace.
  let repo: string
  let sub: string
  let api: SidebarWebRoute
  const GIT_SESSION = 's-git'

  const git = (...args: string[]): string => {
    const result = spawnSync('git', ['-C', repo, ...args], { encoding: 'utf8' })
    if (result.status !== 0) throw new Error(`git ${args.join(' ')}: ${result.stderr}`)
    return result.stdout
  }

  const post = async (method: string, payload: unknown): Promise<{ status: number; body: { ok: boolean; value?: unknown; error?: { code?: string } } }> => {
    const body = Buffer.from(JSON.stringify(payload))
    const req = {
      method: 'POST',
      url: `/sidebar/api/${method}`,
      headers: { host: '127.0.0.1:3080' },
      [Symbol.asyncIterator]: async function* () { yield body },
    } as never
    const out = { status: 200, text: '' }
    const res = {
      writeHead: (status: number) => { out.status = status },
      end: (chunk: unknown) => { out.text += String(chunk ?? '') },
    } as never
    await api.handler(req, res)
    return { status: out.status, body: JSON.parse(out.text) as never }
  }

  beforeAll(() => {
    repo = realpathSync(mkdtempSync(join(tmpdir(), 'dsh-sidebar-git-sec-')))
    sub = join(repo, 'sub')
    mkdirSync(sub)
    git('init', '-q')
    git('config', 'user.email', 'test@example.invalid')
    git('config', 'user.name', 'test')
    git('config', 'commit.gpgsign', 'false')
    writeFileSync(join(repo, 'top.txt'), 'top original\n')
    writeFileSync(join(sub, 'inner.txt'), 'inner original\n')
    git('add', '-A')
    git('commit', '-q', '-m', 'init')
    const routes: SidebarWebRoute[] = []
    apply({
      webRuntime: { trustedHosts: [] },
      connection: { requestRejection: () => undefined },
      webServer: {
        register: (route: SidebarWebRoute) => { routes.push(route); return () => {} },
        registerUpgrade: () => () => {},
      },
      sessions: { get: (id: string) => (id === GIT_SESSION ? { header: { cwd: sub } } : undefined) },
      tools: { register: () => () => {} },
      effect: (fn: () => void | (() => void)) => {
        const cleanup = fn()
        if (typeof cleanup === 'function') effects.push(cleanup)
      },
      inject: () => () => {},
      on: () => () => {},
      get: () => undefined,
      logger: { warn: () => {} },
    } as never)
    api = routes.find(route => route.path === '/sidebar/api')!
  })

  afterAll(() => {
    rmSync(repo, { recursive: true, force: true })
  })

  beforeEach(() => {
    // Clean index, both tracked files modified in the worktree before every case.
    git('reset', '-q')
    writeFileSync(join(repo, 'top.txt'), 'top modified\n')
    writeFileSync(join(sub, 'inner.txt'), 'inner modified\n')
  })

  it('refuses git.diff for a tracked file above the session workspace', async () => {
    for (const path of [join(repo, 'top.txt'), 'top.txt', '../top.txt']) {
      const result = await post('git.diff', { sessionId: GIT_SESSION, path, staged: false })
      expect(result.status, path).toBe(403)
      expect(JSON.stringify(result.body)).not.toContain('top modified')
    }
  })

  it('refuses git.discard for a tracked file above the session workspace', async () => {
    for (const path of [join(repo, 'top.txt'), 'top.txt']) {
      const result = await post('git.discard', { sessionId: GIT_SESSION, path })
      expect(result.status, path).toBe(403)
      expect(readFileSync(join(repo, 'top.txt'), 'utf8')).toBe('top modified\n')
    }
  })

  it('refuses git.stage / git.unstage / git.show for a path above the session workspace', async () => {
    expect((await post('git.stage', { sessionId: GIT_SESSION, path: 'top.txt' })).status).toBe(403)
    expect(git('diff', '--cached', '--name-only')).toBe('')
    expect((await post('git.unstage', { sessionId: GIT_SESSION, path: join(repo, 'top.txt') })).status).toBe(403)
    const shown = await post('git.show', { sessionId: GIT_SESSION, rev: 'HEAD', path: 'top.txt' })
    expect(shown.status).toBe(403)
    expect(JSON.stringify(shown.body)).not.toContain('top original')
    expect((await post('git.show', { sessionId: GIT_SESSION, rev: 'HEAD', path: 'sub/../top.txt' })).status).toBe(403)
  })

  it('keeps diff, stage, unstage, show and discard working for a tracked file inside the workspace', async () => {
    for (const path of [join(sub, 'inner.txt'), 'sub/inner.txt']) {
      const diff = await post('git.diff', { sessionId: GIT_SESSION, path, staged: false })
      expect(diff.status, path).toBe(200)
      expect((diff.body.value as { diff: string }).diff).toContain('+inner modified')
    }
    const shown = await post('git.show', { sessionId: GIT_SESSION, rev: 'HEAD', path: 'sub/inner.txt' })
    expect(shown.status).toBe(200)
    expect((shown.body.value as { content: string }).content).toBe('inner original\n')

    expect((await post('git.stage', { sessionId: GIT_SESSION, path: 'sub/inner.txt' })).status).toBe(200)
    expect(git('diff', '--cached', '--name-only').trim()).toBe('sub/inner.txt')
    expect((await post('git.unstage', { sessionId: GIT_SESSION, path: 'sub/inner.txt' })).status).toBe(200)
    expect(git('diff', '--cached', '--name-only')).toBe('')

    const discard = await post('git.discard', { sessionId: GIT_SESSION, path: join(sub, 'inner.txt') })
    expect(discard.status).toBe(200)
    expect(readFileSync(join(sub, 'inner.txt'), 'utf8')).toBe('inner original\n')
  })

  it('discards a tracked file deleted inside the workspace (target need not exist)', async () => {
    rmSync(join(sub, 'inner.txt'))
    const discard = await post('git.discard', { sessionId: GIT_SESSION, path: 'sub/inner.txt' })
    expect(discard.status).toBe(200)
    expect(readFileSync(join(sub, 'inner.txt'), 'utf8')).toBe('inner original\n')
  })
})
