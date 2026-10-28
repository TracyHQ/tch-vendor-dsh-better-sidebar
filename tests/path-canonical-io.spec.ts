/**
 * Check-then-use regression: every filesystem operation behind the /sidebar
 * routes must act on the CANONICAL path the containment check approved, never
 * on the caller's spelling — otherwise a symlink component swapped between the
 * check and the operation would redirect the operation outside the workspace.
 * Responses (and client-visible watch keys) keep the caller's spelling.
 *
 * The session workspace is reached through a symlink, so the two spellings
 * differ (`linked-workspace/…` as the caller writes it, `real-workspace/…` as
 * realpath resolves it). Because both spellings reach the same files, the
 * outcome alone cannot tell them apart: the I/O primitives are wrapped
 * (pass-through) to record the path each one receives, and every recorded
 * path must be canonical.
 */
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { spawnSync } from 'node:child_process'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import type { Duplex } from 'node:stream'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, sep } from 'node:path'
import WebSocket from 'ws'
import { apply } from '../src/index.ts'
import { invalidateDirectoryCache } from '../src/fs-tree.ts'
import type { SidebarWebRoute, SidebarWebUpgradeRoute } from '../src/context-types.ts'

/** The I/O recorder shared with the hoisted module mocks. */
const io = vi.hoisted(() => ({ recording: false, calls: [] as Array<{ fn: string; path: string }> }))

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>()
  const wrap = <K extends keyof typeof actual>(name: K) =>
    ((...args: unknown[]) => {
      if (io.recording) io.calls.push({ fn: String(name), path: String(args[0]) })
      return (actual[name] as (...a: unknown[]) => unknown)(...args)
    }) as (typeof actual)[K]
  const wrapped = {
    ...actual,
    access: wrap('access'),
    lstat: wrap('lstat'),
    mkdir: wrap('mkdir'),
    open: wrap('open'),
    readdir: wrap('readdir'),
    readFile: wrap('readFile'),
    rename: wrap('rename'),
    rm: wrap('rm'),
    stat: wrap('stat'),
    unlink: wrap('unlink'),
    writeFile: wrap('writeFile'),
  }
  return { ...wrapped, default: wrapped }
})

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>()
  const wrapped = {
    ...actual,
    createWriteStream: ((...args: Parameters<typeof actual.createWriteStream>) => {
      if (io.recording) io.calls.push({ fn: 'createWriteStream', path: String(args[0]) })
      return actual.createWriteStream(...args)
    }) as typeof actual.createWriteStream,
    watch: ((...args: Parameters<typeof actual.watch>) => {
      if (io.recording) io.calls.push({ fn: 'watch', path: String(args[0]) })
      return actual.watch(...args)
    }) as typeof actual.watch,
  }
  return { ...wrapped, default: wrapped }
})

vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:child_process')>()
  const wrapped = {
    ...actual,
    // git's pathspec (the argument after `--`) is the path the command acts on.
    spawn: ((command: string, args: readonly string[], options: unknown) => {
      const dash = args.indexOf('--')
      if (io.recording && dash !== -1 && args[dash + 1] !== undefined) io.calls.push({ fn: command, path: args[dash + 1]! })
      return (actual.spawn as (...a: unknown[]) => unknown)(command, args, options)
    }) as typeof actual.spawn,
  }
  return { ...wrapped, default: wrapped }
})

/** Directory links: a junction on Windows (no symlink privilege needed; the
 *  type argument is ignored elsewhere). Skipped only if even that fails. */
const canCreateSymlink = (() => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-sidebar-canon-probe-'))
  try {
    mkdirSync(join(dir, 'target'))
    symlinkSync(join(dir, 'target'), join(dir, 'link'), 'junction')
    return true
  } catch {
    return false
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})()

const SESSION = 's-canonical'
let base: string
let real: string
let linked: string
let api: SidebarWebRoute
let routes: SidebarWebRoute[]
let server: Server
let origin: string
const effects: Array<() => void> = []

/** Run `operation` while recording I/O; returns its result and the recorded calls. */
async function recorded<T>(operation: () => Promise<T>): Promise<{ result: T; calls: Array<{ fn: string; path: string }> }> {
  io.calls.length = 0
  io.recording = true
  try {
    const result = await operation()
    return { result, calls: [...io.calls] }
  } finally {
    io.recording = false
  }
}

/** Path comparison with the platform's case rule (case-insensitive on Windows). */
const fold = (path: string): string => (process.platform === 'win32' ? path.toLowerCase() : path)
const samePath = (left: string, right: string): boolean => fold(left) === fold(right)
const isUnder = (root: string, path: string): boolean => samePath(root, path) || fold(path).startsWith(`${fold(root)}${sep}`)

/** Every recorded I/O path is canonical (under the real workspace), and there was some I/O. */
function expectCanonical(calls: Array<{ fn: string; path: string }>, fns: readonly string[]): void {
  const relevant = calls.filter(call => fns.some(fn => call.fn.startsWith(fn)))
  expect(relevant.length, `no ${fns.join('/')} call recorded`).toBeGreaterThan(0)
  for (const call of relevant) {
    expect(isUnder(real, call.path), `${call.fn}(${call.path}) is not under ${real}`).toBe(true)
  }
  for (const call of calls) expect(isUnder(linked, call.path), `${call.fn}(${call.path}) used the caller's spelling`).toBe(false)
}

async function post(method: string, payload: unknown): Promise<{ status: number; body: { ok: boolean; value?: unknown; error?: { code?: string } } }> {
  return send(api, `/sidebar/api/${method}`, 'POST', JSON.stringify(payload))
}

async function send(route: SidebarWebRoute, url: string, method: string, text = ''): Promise<{ status: number; body: { ok: boolean; value?: unknown; error?: { code?: string } }; raw: string }> {
  const body = Buffer.from(text)
  const req = {
    method,
    url,
    headers: { host: '127.0.0.1:3080' },
    [Symbol.asyncIterator]: async function* () { yield body },
  } as never
  const out = { status: 200, chunks: [] as Buffer[] }
  const res = {
    writeHead: (status: number) => { out.status = status },
    end: (chunk?: unknown) => { if (chunk !== undefined) out.chunks.push(Buffer.from(chunk as string)) },
  } as never
  await route.handler(req, res)
  const raw = Buffer.concat(out.chunks).toString('utf8')
  let parsed: { ok: boolean } = { ok: out.status === 200 }
  try {
    parsed = JSON.parse(raw) as { ok: boolean }
  } catch {
    // Non-JSON bodies (media/html bytes).
  }
  return { status: out.status, body: parsed, raw }
}

beforeAll(async () => {
  if (!canCreateSymlink) return
  // The NATIVE realpath, exactly what the code canonicalizes with: on Windows
  // it expands 8.3 short names (`RUNNER~1` → `runneradmin`) that the JS
  // `realpathSync` and `os.tmpdir()` keep.
  base = realpathSync.native(mkdtempSync(join(tmpdir(), 'dsh-sidebar-canon-')))
  real = join(base, 'real-workspace')
  linked = join(base, 'linked-workspace')
  mkdirSync(join(real, 'src'), { recursive: true })
  writeFileSync(join(real, 'src', 'a.txt'), 'alpha')
  writeFileSync(join(real, 'page.html'), '<p>page</p>')
  symlinkSync(real, linked, 'junction')
  const git = (...args: string[]): void => {
    const result = spawnSync('git', ['-C', real, ...args], { encoding: 'utf8' })
    if (result.status !== 0) throw new Error(`git ${args.join(' ')}: ${result.stderr}`)
  }
  git('init', '-q')
  git('config', 'user.email', 'test@example.invalid')
  git('config', 'user.name', 'test')
  git('config', 'commit.gpgsign', 'false')
  git('config', 'core.autocrlf', 'false')
  git('add', '-A')
  git('commit', '-q', '-m', 'init')

  routes = []
  const upgrades: SidebarWebUpgradeRoute[] = []
  apply({
    webRuntime: { trustedHosts: [] },
    connection: { requestRejection: () => undefined },
    webServer: {
      register: (route: SidebarWebRoute) => { routes.push(route); return () => {} },
      registerUpgrade: (route: SidebarWebUpgradeRoute) => { upgrades.push(route); return () => {} },
    },
    sessions: { get: (id: string) => (id === SESSION ? { header: { cwd: linked } } : undefined) },
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
  server = createServer((req: IncomingMessage, res: ServerResponse) => {
    res.writeHead(404)
    res.end()
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
  origin = `ws://127.0.0.1:${address.port}`
})

afterAll(async () => {
  for (const cleanup of effects) cleanup()
  if (server !== undefined) {
    server.closeAllConnections()
    await new Promise<void>(resolve => server.close(() => resolve()))
  }
  if (base !== undefined) rmSync(base, { recursive: true, force: true })
})

describe.skipIf(!canCreateSymlink)('/sidebar routes act on the canonical path (workspace reached through a symlink)', () => {
  it('listing: fs.tree / fs.trees read the canonical directory, answer in the caller\'s spelling', async () => {
    invalidateDirectoryCache()
    const { result, calls } = await recorded(() => post('fs.tree', { sessionId: SESSION, path: join(linked, 'src') }))
    expectCanonical(calls, ['readdir'])
    const listing = result.body.value as { path: string; entries: Array<{ path: string }> }
    expect(listing.path).toBe(join(linked, 'src'))
    expect(listing.entries.map(entry => entry.path)).toEqual([join(linked, 'src', 'a.txt')])

    invalidateDirectoryCache()
    const batch = await recorded(() => post('fs.trees', { sessionId: SESSION, paths: [linked] }))
    expectCanonical(batch.calls, ['readdir'])
    expect((batch.result.body.value as { levels: Array<{ path: string }> }).levels[0]!.path).toBe(linked)
  })

  it('read: fs.read, /sidebar/file and /sidebar/html read the canonical file', async () => {
    const read = await recorded(() => post('fs.read', { sessionId: SESSION, path: join(linked, 'src', 'a.txt') }))
    expectCanonical(read.calls, ['stat', 'open'])
    expect(read.result.body.value).toMatchObject({ kind: 'text', content: 'alpha' })

    const media = routes.find(route => route.path === '/sidebar/file')!
    const file = await recorded(() => send(media, `/sidebar/file?sessionId=${SESSION}&path=${encodeURIComponent(join(linked, 'src', 'a.txt'))}`, 'GET'))
    expectCanonical(file.calls, ['stat', 'readFile'])
    expect(file.result.raw).toBe('alpha')

    const { encodeHtmlUrl } = await import('../src/html-route.ts')
    const html = routes.find(route => route.path === '/sidebar/html')!
    const page = await recorded(() => send(html, encodeHtmlUrl(SESSION, join(linked, 'page.html')), 'GET'))
    expectCanonical(page.calls, ['stat', 'readFile'])
    expect(page.result.raw).toBe('<p>page</p>')
  })

  it('write: fs.write writes (temp + rename) at the canonical destination', async () => {
    const { result, calls } = await recorded(() => post('fs.write', { sessionId: SESSION, path: join(linked, 'new', 'w.txt'), content: 'written' }))
    expect(result.status).toBe(200)
    expectCanonical(calls, ['mkdir', 'writeFile', 'rename'])
    expect(readFileSync(join(real, 'new', 'w.txt'), 'utf8')).toBe('written')
  })

  it('mkdir: creates in the real directory and answers in the caller\'s spelling', async () => {
    const { result, calls } = await recorded(() => post('fs.mkdir', { sessionId: SESSION, path: join(linked, 'src'), name: 'made' }))
    expect((result.body.value as { path: string }).path).toBe(join(linked, 'src', 'made'))
    expectCanonical(calls, ['mkdir', 'access'])
    expect(existsSync(join(real, 'src', 'made'))).toBe(true)
  })

  it('rename: source and destination are canonical; the response keeps the caller\'s spelling', async () => {
    writeFileSync(join(real, 'src', 'old.txt'), 'old')
    const { result, calls } = await recorded(() => post('fs.rename', { sessionId: SESSION, path: join(linked, 'src', 'old.txt'), name: 'renamed.txt' }))
    expect((result.body.value as { path: string }).path).toBe(join(linked, 'src', 'renamed.txt'))
    expectCanonical(calls, ['rename', 'access'])
    expect(samePath(calls.find(call => call.fn === 'rename')?.path ?? '', join(real, 'src', 'old.txt'))).toBe(true)
    expect(readFileSync(join(real, 'src', 'renamed.txt'), 'utf8')).toBe('old')
  })

  it('remove: lstat/unlink the canonical row; the response keeps the caller\'s spelling', async () => {
    writeFileSync(join(real, 'src', 'gone.txt'), 'x')
    const { result, calls } = await recorded(() => post('fs.remove', { sessionId: SESSION, path: join(linked, 'src', 'gone.txt') }))
    expect((result.body.value as { path: string }).path).toBe(join(linked, 'src', 'gone.txt'))
    expectCanonical(calls, ['lstat', 'unlink'])
    expect(existsSync(join(real, 'src', 'gone.txt'))).toBe(false)
  })

  it('upload: streams to a canonical temp file renamed onto the canonical target', async () => {
    const upload = routes.find(route => route.path === '/sidebar/upload')!
    const params = new URLSearchParams({ sessionId: SESSION, dir: join(linked, 'src'), relativePath: 'deep/up.txt' })
    const { result, calls } = await recorded(() => send(upload, `/sidebar/upload?${params.toString()}`, 'POST', 'uploaded'))
    expect((result.body.value as { path: string }).path).toBe(join(linked, 'src', 'deep', 'up.txt'))
    expectCanonical(calls, ['mkdir', 'createWriteStream', 'rename', 'stat'])
    expect(readFileSync(join(real, 'src', 'deep', 'up.txt'), 'utf8')).toBe('uploaded')
  })

  it('archive: the zip walk and reads use canonical paths', async () => {
    const { calls } = await recorded(async () => {
      const build = await post('archive.build', { sessionId: SESSION, paths: [join(linked, 'src')] })
      expect(build.status).toBe(200)
      const id = (build.body.value as { id: string }).id
      for (let attempt = 0; attempt < 400; attempt += 1) {
        const status = await post('archive.status', { sessionId: SESSION, id })
        if ((status.body.value as { state: string }).state !== 'building') return status
        await new Promise(resolve => setTimeout(resolve, 5))
      }
      throw new Error('archive never settled')
    })
    expectCanonical(calls, ['lstat', 'readdir', 'readFile'])
  })

  it('git: the discard pathspec is canonical', async () => {
    writeFileSync(join(real, 'src', 'a.txt'), 'changed')
    const { result, calls } = await recorded(() => post('git.discard', { sessionId: SESSION, path: join(linked, 'src', 'a.txt') }))
    expect(result.status).toBe(200)
    expectCanonical(calls, ['git'])
    expect(readFileSync(join(real, 'src', 'a.txt'), 'utf8')).toBe('alpha')
  })

  it('watch: the OS watcher is opened on the canonical directory; events report the caller\'s spelling', async () => {
    const ws = new WebSocket(`${origin}/sidebar/ws/fs-watch?sessionId=${SESSION}`)
    const frames: Array<{ dir: string; ok?: boolean }> = []
    ws.on('message', data => frames.push(JSON.parse(String(data)) as { dir: string; ok?: boolean }))
    await new Promise<void>((resolve, reject) => { ws.once('open', () => resolve()); ws.once('error', reject) })
    try {
      const display = join(linked, 'src')
      const { calls } = await recorded(async () => {
        ws.send(JSON.stringify({ op: 'watch', path: display }))
        await vi.waitFor(() => { expect(frames).toContainEqual({ dir: display, ok: true }) })
      })
      expectCanonical(calls, ['watch'])
      writeFileSync(join(real, 'src', 'touch.txt'), 'x')
      await vi.waitFor(() => { expect(frames).toContainEqual({ dir: display }) }, { timeout: 3_000 })
    } finally {
      ws.close()
    }
  })
})
