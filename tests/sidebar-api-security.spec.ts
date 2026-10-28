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
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { spawnSync } from 'node:child_process'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import type { Duplex } from 'node:stream'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import WebSocket from 'ws'
import { apply } from '../src/index.ts'
import { invalidateDirectoryCache } from '../src/fs-tree.ts'
import type { SidebarWebRoute, SidebarWebUpgradeRoute } from '../src/context-types.ts'

const AUTH_COOKIE = 'dsh-test-auth=ok'

/** OS-opener launches (`open.external`) are recorded, never run; git passes through. */
const opened = vi.hoisted(() => [] as Array<{ command: string; args: string[] }>)
vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:child_process')>()
  const { EventEmitter } = await import('node:events')
  const openers = new Set(['xdg-open', 'open', 'explorer.exe', 'rundll32.exe'])
  const spawn = ((command: string, args: string[], options: unknown) => {
    if (!openers.has(command)) return (actual.spawn as (...a: unknown[]) => unknown)(command, args, options)
    opened.push({ command, args: [...args] })
    return Object.assign(new EventEmitter(), { unref: () => {} })
  }) as typeof actual.spawn
  return { ...actual, spawn, default: { ...actual, spawn } }
})
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

  it.skipIf(!canCreateSymlink)('lists symlink rows to outside targets as links it cannot open, without following them', async () => {
    mkdirSync(join(workspace, 'inner-dir'), { recursive: true })
    const innerLink = join(workspace, 'inner-link')
    symlinkSync(join(workspace, 'inner-dir'), innerLink, 'junction')
    try {
      invalidateDirectoryCache()
      const tree = await call('fs.tree', { sessionId: SESSION })
      expect(tree.status).toBe(200)
      const rows = (tree.body.value as { entries: Array<{ name: string; isDir: boolean; broken: boolean; isSymlink: boolean }> }).entries
      const row = (name: string) => rows.find(entry => entry.name === name)
      // Outside targets: kept as rows, reported like an unopenable link.
      expect(row('link-dir')).toMatchObject({ isSymlink: true, isDir: false, broken: true })
      expect(row('link-file')).toMatchObject({ isSymlink: true, isDir: false, broken: true })
      // An in-workspace link is followed as today.
      expect(row('inner-link')).toMatchObject({ isSymlink: true, isDir: true, broken: false })
    } finally {
      rmSync(innerLink, { force: true })
      rmSync(join(workspace, 'inner-dir'), { recursive: true, force: true })
      invalidateDirectoryCache()
    }
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

describe('/sidebar routes: open.external', () => {
  beforeEach(() => { opened.length = 0 })

  it('refuses to reveal a path outside the workspace and launches nothing', async () => {
    // An existing system file that is absolute on the running platform: it
    // resolves, so the refusal is the workspace check itself (403).
    const systemFile = process.platform === 'win32'
      ? join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'drivers', 'etc', 'hosts')
      : '/etc/passwd'
    for (const path of [join(outside, 'secret.txt'), systemFile, `${workspace}/../outside/secret.txt`]) {
      const result = await call('open.external', { sessionId: SESSION, action: 'reveal', path })
      expect(result.status, path).toBe(403)
    }
    if (process.platform === 'win32') {
      // The POSIX spelling has no drive on Windows: it resolves to a
      // nonexistent `C:\etc\passwd` and is refused (400) before the
      // workspace check — still a refusal, still nothing launched.
      expect((await call('open.external', { sessionId: SESSION, action: 'reveal', path: '/etc/passwd' })).status).toBe(400)
    }
    expect((await call('open.external', { action: 'reveal', path: join(workspace, 'inside.txt') })).status).toBe(400)
    expect(opened).toEqual([])
  })

  it.skipIf(!canCreateSymlink)('refuses to reveal through a symlink that leaves the workspace', async () => {
    const result = await call('open.external', { sessionId: SESSION, action: 'reveal', path: join(workspace, 'link-file') })
    expect(result.status).toBe(403)
    expect(opened).toEqual([])
  })

  it('reveals a path inside the workspace with its canonical path', async () => {
    const result = await call('open.external', { sessionId: SESSION, action: 'reveal', path: join(workspace, 'inside.txt') })
    expect(result.status).toBe(200)
    expect(opened).toHaveLength(1)
    expect(opened[0]!.args.join(' ')).toContain(process.platform === 'linux' ? workspace : 'inside.txt')
  })

  it('refuses file: and drive-letter URLs (they open local files) and launches nothing', async () => {
    for (const url of ['file:///etc/passwd', 'FILE:///etc/passwd', '  file:///etc/passwd  ', 'File://localhost/etc/passwd', 'c://Windows/System32/calc.exe']) {
      const result = await call('open.external', { action: 'url', url })
      expect(result.status, url).toBe(400)
    }
    expect(opened).toEqual([])
  })

  it('keeps editor and custom-scheme URLs working', async () => {
    for (const url of ['vscode://file/home/u/a.ts', 'cursor://file/home/u/a.ts:3', 'zed://file/home/u/a.ts', 'myapp://open?x=1']) {
      const result = await call('open.external', { action: 'url', url })
      expect(result.status, url).toBe(200)
    }
    expect(opened.map(entry => entry.args.at(-1))).toEqual(['vscode://file/home/u/a.ts', 'cursor://file/home/u/a.ts:3', 'zed://file/home/u/a.ts', 'myapp://open?x=1'])
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

describe('/sidebar git routes: repository containment (nested session in a repository)', () => {
  // A real repository whose session cwd is the `sub/` directory. Git actions
  // cover the WHOLE repository (owner decision): files at the repository top
  // level are in scope, anything outside the repository root is not.
  let parent: string
  let repo: string
  let outside: string
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
    parent = realpathSync.native(mkdtempSync(join(tmpdir(), 'dsh-sidebar-git-sec-')))
    repo = join(parent, 'repo')
    sub = join(repo, 'sub')
    outside = join(parent, 'outside.txt')
    mkdirSync(sub, { recursive: true })
    writeFileSync(outside, 'outside content\n')
    git('init', '-q')
    git('config', 'user.email', 'test@example.invalid')
    git('config', 'user.name', 'test')
    git('config', 'commit.gpgsign', 'false')
    // Windows runners default to core.autocrlf=true, which would make the
    // discard/checkout cases write CRLF; the cases compare exact bytes.
    git('config', 'core.autocrlf', 'false')
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
    rmSync(parent, { recursive: true, force: true })
  })

  beforeEach(() => {
    // Clean index, both tracked files modified in the worktree before every case.
    git('reset', '-q')
    writeFileSync(join(repo, 'top.txt'), 'top modified\n')
    writeFileSync(join(sub, 'inner.txt'), 'inner modified\n')
  })

  it('acts on a tracked file above the session cwd but inside the repository', async () => {
    for (const path of [join(repo, 'top.txt'), 'top.txt', '../top.txt']) {
      const diff = await post('git.diff', { sessionId: GIT_SESSION, path, staged: false })
      expect(diff.status, path).toBe(200)
      expect((diff.body.value as { diff: string }).diff, path).toContain('+top modified')
    }
    const shown = await post('git.show', { sessionId: GIT_SESSION, rev: 'HEAD', path: 'top.txt' })
    expect(shown.status).toBe(200)
    expect((shown.body.value as { content: string }).content).toBe('top original\n')
    expect((await post('git.stage', { sessionId: GIT_SESSION, path: 'top.txt' })).status).toBe(200)
    expect(git('diff', '--cached', '--name-only').trim()).toBe('top.txt')
    expect((await post('git.unstage', { sessionId: GIT_SESSION, path: join(repo, 'top.txt') })).status).toBe(200)
    expect(git('diff', '--cached', '--name-only')).toBe('')
    expect((await post('git.discard', { sessionId: GIT_SESSION, path: 'top.txt' })).status).toBe(200)
    expect(readFileSync(join(repo, 'top.txt'), 'utf8')).toBe('top original\n')
  })

  it('refuses paths that leave the repository root (.., absolute outside)', async () => {
    for (const path of ['../../outside.txt', outside]) {
      for (const method of ['git.diff', 'git.stage', 'git.unstage', 'git.discard']) {
        const result = await post(method, { sessionId: GIT_SESSION, path, staged: false })
        expect(result.status, `${method} ${path}`).toBe(403)
      }
    }
    for (const path of ['../outside.txt', 'sub/../../outside.txt', outside]) {
      expect((await post('git.show', { sessionId: GIT_SESSION, rev: 'HEAD', path })).status, path).toBe(403)
    }
    expect(readFileSync(outside, 'utf8')).toBe('outside content\n')
  })

  it.skipIf(!canCreateSymlink)('refuses a symlink inside the repository that points outside it', async () => {
    const link = join(repo, 'out-link')
    symlinkSync(parent, link, 'junction')
    try {
      for (const method of ['git.diff', 'git.stage', 'git.discard']) {
        const result = await post(method, { sessionId: GIT_SESSION, path: join(link, 'outside.txt'), staged: false })
        expect(result.status, method).toBe(403)
      }
      expect((await post('git.show', { sessionId: GIT_SESSION, rev: 'HEAD', path: 'out-link/outside.txt' })).status).toBe(403)
    } finally {
      rmSync(link, { force: true, recursive: false })
    }
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

describe('/sidebar routes: returned paths keep the caller\'s spelling', () => {
  // The session workspace is reached through a symlink, so its realpath is
  // spelled differently from the cwd the session records — the Linux stand-in
  // for a Windows 8.3 short name (`RUNNER~1` vs `runneradmin`). Containment
  // compares realpaths; everything the routes hand back must keep the
  // caller's spelling.
  let base: string
  let real: string
  let linked: string
  let api: SidebarWebRoute
  let upload: SidebarWebRoute
  const SPELL_SESSION = 's-spelling'

  const send = async (route: SidebarWebRoute, url: string, payload: unknown): Promise<{ status: number; body: { ok: boolean; value?: unknown; error?: { code?: string } } }> => {
    const body = Buffer.from(typeof payload === 'string' ? payload : JSON.stringify(payload))
    const req = {
      method: 'POST',
      url,
      headers: { host: '127.0.0.1:3080' },
      [Symbol.asyncIterator]: async function* () { yield body },
    } as never
    const out = { status: 200, text: '' }
    const res = {
      writeHead: (status: number) => { out.status = status },
      end: (chunk: unknown) => { out.text += String(chunk ?? '') },
    } as never
    await route.handler(req, res)
    return { status: out.status, body: JSON.parse(out.text) as never }
  }
  const post = (method: string, payload: unknown) => send(api, `/sidebar/api/${method}`, payload)

  beforeAll(() => {
    if (!canCreateSymlink) return
    base = realpathSync(mkdtempSync(join(tmpdir(), 'dsh-sidebar-spelling-')))
    real = join(base, 'real-workspace')
    linked = join(base, 'linked-workspace')
    mkdirSync(join(real, 'src'), { recursive: true })
    writeFileSync(join(real, 'src', 'a.txt'), 'a')
    writeFileSync(join(base, 'outside.txt'), 'outside')
    symlinkSync(real, linked)
    const routes: SidebarWebRoute[] = []
    apply({
      webRuntime: { trustedHosts: [] },
      connection: { requestRejection: () => undefined },
      webServer: {
        register: (route: SidebarWebRoute) => { routes.push(route); return () => {} },
        registerUpgrade: () => () => {},
      },
      sessions: { get: (id: string) => (id === SPELL_SESSION ? { header: { cwd: linked } } : undefined) },
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
    upload = routes.find(route => route.path === '/sidebar/upload')!
  })

  afterAll(() => {
    if (base !== undefined) rmSync(base, { recursive: true, force: true })
  })

  it.skipIf(!canCreateSymlink)('fs.tree / fs.trees answer with the requested spelling', async () => {
    const tree = await post('fs.tree', { sessionId: SPELL_SESSION, path: join(linked, 'src') })
    expect(tree.status).toBe(200)
    expect((tree.body.value as { path: string }).path).toBe(join(linked, 'src'))
    const trees = await post('fs.trees', { sessionId: SPELL_SESSION, paths: [linked, join(linked, 'src')] })
    expect(trees.status).toBe(200)
    expect((trees.body.value as { levels: Array<{ path: string }> }).levels.map(level => level.path))
      .toEqual([linked, join(linked, 'src')])
  })

  it.skipIf(!canCreateSymlink)('fs.mkdir / fs.rename / upload return the requested spelling', async () => {
    const made = await post('fs.mkdir', { sessionId: SPELL_SESSION, path: join(linked, 'src'), name: 'fresh' })
    expect(made.status).toBe(200)
    expect((made.body.value as { path: string }).path).toBe(join(linked, 'src', 'fresh'))
    const renamed = await post('fs.rename', { sessionId: SPELL_SESSION, path: join(linked, 'src', 'fresh'), name: 'renamed' })
    expect(renamed.status).toBe(200)
    expect((renamed.body.value as { path: string }).path).toBe(join(linked, 'src', 'renamed'))
    const params = new URLSearchParams({ sessionId: SPELL_SESSION, dir: join(linked, 'src'), relativePath: 'up.txt' })
    const uploaded = await send(upload, `/sidebar/upload?${params.toString()}`, 'bytes')
    expect(uploaded.status).toBe(200)
    expect((uploaded.body.value as { path: string }).path).toBe(join(linked, 'src', 'up.txt'))
    expect(readFileSync(join(real, 'src', 'up.txt'), 'utf8')).toBe('bytes')
  })

  it.skipIf(!canCreateSymlink)('still refuses the workspace root itself and paths outside it', async () => {
    // Through its canonical spelling the root is refused as the root; rename/remove
    // are link-aware, so the LINK itself (the session cwd spelling) is a row
    // outside the canonical workspace and refused as such. Nothing is removed.
    expect((await post('fs.remove', { sessionId: SPELL_SESSION, path: real })).body.error?.code).toBe('fs-error')
    expect((await post('fs.remove', { sessionId: SPELL_SESSION, path: linked })).status).toBe(403)
    expect((await post('fs.rename', { sessionId: SPELL_SESSION, path: join(linked, 'src', '..'), name: 'x' })).status).toBe(403)
    expect(existsSync(join(real, 'src'))).toBe(true)
    expect(existsSync(linked)).toBe(true)
    expect((await post('fs.read', { sessionId: SPELL_SESSION, path: join(linked, '..', 'outside.txt') })).status).toBe(403)
    expect((await post('fs.write', { sessionId: SPELL_SESSION, path: join(base, 'new.txt'), content: 'x' })).status).toBe(403)
    expect(existsSync(join(base, 'new.txt'))).toBe(false)
  })
})
