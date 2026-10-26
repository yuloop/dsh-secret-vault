import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm, readFile, readdir, stat, symlink, unlink, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { openStore, MAX_AGE_MS } from '../store.js'
import { createTools } from '../tools.js'
import { createGuard, createScopedFallbackGuard, registerGuard } from '../guard.js'
import { cleanupBoundary } from '../daily-cleanup.js'
import { MAX_BYTES } from '../local-files.js'

async function fixture(t) {
  const root = await mkdtemp('/var/tmp/private-local-test-')
  t.after(() => rm(root, { recursive: true, force: true }))
  let now = Date.UTC(2026, 9, 25, 8)
  const store = await openStore(join(root, 'data'), () => now)
  return { root, store, advance: ms => { now += ms }, now: () => now }
}
const exec = owner => ({ agent: { id: owner } })
const randomText = () => `private fixture ${randomBytes(24).toString('hex')}`

test('plaintext random local files: no master key, names, content or hashes in model metadata', async t => {
  const { store } = await fixture(t)
  const value = randomText()
  const entry = await store.save('owner', value)
  assert.match(entry.id, /^tmp-[a-f0-9]{32}$/)
  assert.equal(await readFile(entry.path, 'utf8'), value)
  assert.equal((await stat(entry.path)).mode & 0o777, 0o600)
  assert.equal((await stat(store.dir)).mode & 0o777, 0o700)
  assert(!JSON.stringify(store.list('owner')).includes(value))
  assert(!JSON.stringify(await readdir(store.dir)).includes('master'))
  // v4.3.0: saving never locks the session — a lock froze every tool exactly when the
  // user wanted the file used.
  assert.equal(store.isLocked('owner'), false)
})

test('local transformation writes a new protected file; every model-facing representation is content-free', async t => {
  const { store } = await fixture(t)
  const value = randomText()
  const source = await store.save('owner', `  ${value}  `)
  const tool = createTools(store).find(x => x.name === 'private_local_process')
  const result = await tool.execute({ reference: source.path, operation: 'trim_edges' }, exec('owner'))
  assert.equal(result.ok, true)
  assert.notEqual(result.result.path, source.path)
  assert.equal(await readFile(result.result.path, 'utf8'), value)
  assert.equal(await readFile(source.path, 'utf8'), `  ${value}  `)
  assert.equal(store.list('owner').find(x => x.id === source.id).used, true)
  for (const data of [result, tool.output.render({}, result)]) {
    assert(!JSON.stringify(data).includes(value))
    assert(!JSON.stringify(data).includes('fingerprint'))
  }
})

test('malformed JSON and unsupported operations never echo private parser exceptions', async t => {
  const { store } = await fixture(t)
  const value = randomText()
  const source = await store.save('owner', `{invalid:${value}}`)
  const tool = createTools(store)[1]
  for (const operation of ['json_pretty', 'eval', 'shell', 'http', 'read', 'base64']) {
    const result = await tool.execute({ reference: source.id, operation }, exec('owner'))
    assert.deepEqual(result, { ok: false, status: 'operation_failed' })
    assert(!JSON.stringify(result).includes(value))
  }
  assert.equal(store.list('owner').length, 1)
})

test('closed schema rejects hidden code, arbitrary output paths and cross-session access', async t => {
  const { store } = await fixture(t)
  const entry = await store.save('one', randomText())
  const tool = createTools(store)[1]
  for (const args of [
    { reference: entry.id, operation: 'copy', command: 'cat something' },
    { reference: entry.id, operation: 'copy', output: '/var/tmp/leak' },
    { reference: '../../etc/passwd', operation: 'copy' },
  ]) assert.equal((await tool.execute(args, exec('one'))).ok, false)
  assert.equal((await tool.execute({ reference: entry.id, operation: 'copy' }, exec('two'))).ok, false)
  assert.deepEqual(store.list('two'), [])
  assert.equal((await tool.execute({ reference: entry.id, operation: 'copy' }, {})).ok, false)
})

test('holding a private file keeps every generic tool, but naming the store is refused', async t => {
  const { store } = await fixture(t)
  const entry = await store.save('owner', randomText())
  const guard = createGuard(store)
  for (const name of ['read', 'read_image', 'grep', 'glob', 'bash', 'terminal_send', 'web_search',
    'web_fetch', 'subagent', 'run_code', 'workflow', 'plugin_manager', 'session_search', 'qq_notify',
    'present', 'cordis_inspect_query', 'future_unknown_tool']) {
    assert.equal(guard({ name, arguments: {}, ...exec('owner') }), undefined, name)
  }
  for (const name of ['private_local_process', 'private_local_status']) {
    assert.equal(guard({ name, arguments: {}, ...exec('owner') }), undefined)
  }
  // The bytes stay out of reach: owning the file does not license reading it back,
  // and another session naming the path is refused too.
  assert.equal(typeof guard({ name: 'read', arguments: { file_path: entry.path }, ...exec('owner') }), 'string')
  assert.equal(typeof guard({ name: 'bash', arguments: { command: `cat ${entry.path}` }, ...exec('owner') }), 'string')
  assert.equal(typeof guard({ name: 'bash', arguments: { command: `cat ${entry.path}` }, ...exec('other') }), 'string')
  assert.equal(typeof guard({ name: 'tmp_run', arguments: {}, ...exec('owner') }), 'string')
})

test('user-initiated removal deletes bytes and entry, then the session can be released', async t => {
  const { store } = await fixture(t)
  const keep = await store.save('owner', randomText())
  const drop = await store.save('owner', randomText())
  const removed = await store.remove('owner', drop.id)
  assert.equal(removed.ok, true)
  assert.equal(removed.locked, false)
  assert.deepEqual(removed.entries.map(e => e.id), [keep.id])
  await assert.rejects(() => readFile(drop.path, 'utf8'), /ENOENT/)
  assert.equal((await stat(keep.path)).mode & 0o777, 0o600)
  await assert.rejects(() => store.remove('other', keep.id))
  await assert.rejects(() => store.remove('owner', `tmp-${'0'.repeat(32)}`))
  assert.equal(store.list('owner').length, 1)
  await store.remove('owner', keep.id)
  assert.equal(store.hasFiles(), false)
  assert.equal(store.isLocked('owner'), false)
})

test('a legacy lock from a pre-4.3.0 state file still protects and still releases', async t => {
  const { store } = await fixture(t)
  const entry = await store.save('owner', randomText())
  const statePath = join(store.dir, 'state.json')
  const state = JSON.parse(await readFile(statePath, 'utf8'))
  state.locked = ['owner'] // forge the old shape: file tracked and session locked
  await writeFile(statePath, JSON.stringify(state))
  const legacy = await openStore(store.dir)
  assert.equal(legacy.isLocked('owner'), true)
  const guard = createGuard(legacy)
  assert.equal(typeof guard({ name: 'bash', arguments: { command: 'true' }, ...exec('owner') }), 'string')
  assert.equal(guard({ name: 'ask_user_question', arguments: {}, ...exec('owner') }), undefined)
  await legacy.remove('owner', entry.id)
  assert.equal(legacy.isLocked('owner'), false)
})

test('an unreadable store refuses only store-touching calls instead of every session tool', async t => {
  const { store } = await fixture(t)
  const entry = await store.save('owner', randomText())
  await rm(store.dir, { recursive: true, force: true })
  await assert.rejects(() => store.save('owner', randomText()))
  assert.equal(store.healthy(), false)
  const guard = createGuard(store)
  assert.equal(guard({ name: 'bash', arguments: { command: 'true' }, ...exec('other') }), undefined)
  assert.equal(guard({ name: 'web_search', arguments: { queries: ['x'] }, ...exec('other') }), undefined)
  assert.equal(typeof guard({ name: 'read', arguments: { file_path: entry.path }, ...exec('other') }), 'string')
  assert.equal(typeof guard({ name: 'private_local_status', arguments: {}, ...exec('owner') }), 'string')
})

test('the fallback guard only refuses store paths, not unrelated tooling', async t => {
  const { store } = await fixture(t)
  const guard = createScopedFallbackGuard(store.dir)
  assert.equal(guard({ name: 'bash', arguments: { command: 'ls' }, ...exec('x') }), undefined)
  assert.equal(typeof guard({ name: 'read', arguments: { file_path: `${store.dir}/state.json` }, ...exec('x') }), 'string')
  assert.equal(typeof guard({ name: 'private_local_status', arguments: {}, ...exec('x') }), 'string')
})

test('registration uses monotonic tools.guard, not order-dependent pre-execute policy', async t => {
  const { store } = await fixture(t)
  let registered
  registerGuard({ effect: f => f(), tools: { guard: f => { registered = f; return () => {} } } }, store)
  assert.equal(typeof registered, 'function')
  const names = createTools(store).map(x => x.name)
  assert.deepEqual(names, ['private_local_status', 'private_local_process'])
})

test('no external fetch during local operations, including hostile URL content', async t => {
  const { store } = await fixture(t)
  const previous = globalThis.fetch
  let requests = 0
  globalThis.fetch = () => { requests++; throw new Error('NETWORK_FORBIDDEN') }
  try {
    const entry = await store.save('owner', '{"url":"https://invalid.example/private"}')
    const result = await createTools(store)[1].execute({ reference: entry.id, operation: 'json_pretty' }, exec('owner'))
    assert.equal(result.ok, true)
    assert.equal(requests, 0)
  } finally { globalThis.fetch = previous }
})

test('symlink, FIFO-like/non-file and oversized reads fail closed', async t => {
  const { root, store } = await fixture(t)
  const entry = await store.save('owner', randomText())
  await unlink(entry.path)
  const outside = join(root, 'outside.txt')
  await writeFile(outside, randomText())
  await symlink(outside, entry.path)
  const tool = createTools(store)[1]
  assert.equal((await tool.execute({ reference: entry.id, operation: 'copy' }, exec('owner'))).ok, false)
  await unlink(entry.path)
  await writeFile(entry.path, 'a'.repeat(MAX_BYTES + 1))
  assert.equal((await tool.execute({ reference: entry.id, operation: 'copy' }, exec('owner'))).ok, false)
})

test('daily cleanup uses used markers, retains fresh unused files, and expires unused data', async t => {
  const f = await fixture(t), { store } = f
  const used = await store.save('owner', randomText())
  const unused = await store.save('owner', randomText())
  await store.markUsed('owner', used.id)
  f.advance(86400000)
  const boundary = cleanupBoundary(f.now())
  assert.equal(new Date(boundary).getUTCHours(), 20)
  assert.equal((await store.cleanup(boundary)).removed, 1)
  assert.equal(store.list('owner')[0].id, unused.id)
  assert.equal(store.isLocked('owner'), false)
  await assert.rejects(() => store.release('owner'))
  f.advance(MAX_AGE_MS)
  assert.equal((await store.cleanup(cleanupBoundary(f.now()))).removed, 1)
  // The last file is gone, so the lock must drop on its own instead of stranding the session.
  assert.equal(store.isLocked('owner'), false)
})

test('removing the last private file releases a legacy lock on the way out', async t => {
  const { store } = await fixture(t)
  const first = await store.save('owner', randomText())
  const second = await store.save('owner', randomText())
  const statePath = join(store.dir, 'state.json')
  const state = JSON.parse(await readFile(statePath, 'utf8'))
  state.locked = ['owner']
  await writeFile(statePath, JSON.stringify(state))
  const legacy = await openStore(store.dir)
  assert.equal((await legacy.remove('owner', first.id)).released, false)
  assert.equal(legacy.isLocked('owner'), true)
  const last = await legacy.remove('owner', second.id)
  assert.equal(last.released, true)
  assert.equal(last.locked, false)
})

test('daily cleanup self-heals a lock that was already stranded with zero files', async t => {
  const f = await fixture(t), { store } = f
  const gone = await store.save('owner', randomText())
  await store.markUsed('owner', gone.id)
  f.advance(86400000)
  assert.equal((await store.cleanup(cleanupBoundary(f.now()))).removed, 1)
  assert.equal(store.hasFiles(), false)
  assert.equal(store.isLocked('owner'), false)
})

test('restart preserves binding and locking; malformed state cannot silently reset protection', async t => {
  const { store } = await fixture(t)
  await store.save('owner', randomText())
  const restarted = await openStore(store.dir)
  assert.equal(restarted.isLocked('owner'), false)
  assert.equal(restarted.list('owner').length, 1)
  await writeFile(join(store.dir, 'state.json'), '{broken')
  await assert.rejects(() => openStore(store.dir), /PRIVATE_OPERATION_FAILED/)
})

test('saving never locks the session (v4.3.0 contract)', async t => {
  const { store } = await fixture(t)
  await store.save('owner', randomText())
  assert.equal(store.isLocked('owner'), false)
  assert.equal(store.hasFiles(), true)
  assert.deepEqual(store.list('owner').length, 1)
})

test('saving auto-decomposes: shape persisted, value-free, visible without asking', async t => {
  const { store } = await fixture(t)
  const key = randomBytes(24).toString('hex')
  const entry = await store.save('owner', `密钥: ${key} 电话 13800138000`)
  assert.equal(entry.shape.secrets.length, 1)
  assert.equal(entry.shape.secrets[0].length, key.length)
  assert(entry.shape.pii.some(item => item.type === '手机号'))
  const onDisk = await readFile(join(store.dir, 'state.json'), 'utf8')
  assert.equal(onDisk.includes(key), false, 'state.json must never carry the value')
  assert.equal(onDisk.includes('13800138000'), false, 'nor any PII value')
  const listed = store.list('owner')[0]
  assert.match(listed.summary, /密钥1/)
  assert.match(listed.summary, /手机号1/)
})

test('entries saved before auto-decomposition get their shape backfilled', async t => {
  const { store } = await fixture(t)
  const key = randomBytes(24).toString('hex')
  const entry = await store.save('owner', `密钥: ${key}`)
  // Simulate a legacy entry: strip the shape, persist, reopen.
  const statePath = join(store.dir, 'state.json')
  const state = JSON.parse(await readFile(statePath, 'utf8'))
  delete state.entries[0].shape
  await writeFile(statePath, JSON.stringify(state))
  const legacy = await openStore(store.dir)
  assert.equal(legacy.list('owner')[0].shape, null)
  assert.equal(await legacy.backfillShapes(), 1)
  const listed = legacy.list('owner')[0]
  assert.equal(listed.shape.secrets.length, 1)
  assert.equal(listed.shape.secrets[0].length, key.length)
  assert.equal((await readFile(statePath, 'utf8')).includes(key), false)
  assert.equal(entry.shape.secrets.length, 1)
})
