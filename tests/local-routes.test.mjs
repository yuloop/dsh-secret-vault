import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { registerRoutes } from '../routes.js'
import { openStore } from '../store.js'

async function fixture(t) {
  const root = await mkdtemp('/var/tmp/private-route-test-')
  t.after(() => rm(root, { recursive: true, force: true }))
  const store = await openStore(join(root, 'data'))
  const routes = new Map()
  const ctx = { effect: f => f(), connection: { fetch: { register: route => {
    assert.equal(route.requestBody, 'streaming')
    assert.deepEqual(route.methods, ['POST'])
    assert.equal(typeof route.fetch, 'function')
    routes.set(route.path.split('/').at(-1), route.fetch)
    return () => {}
  } } } }
  registerRoutes(ctx, { store, isIdleSession: id => ['idle', 'other'].includes(id) })
  async function call(action, body, options = {}) {
    const origin = options.origin || 'http://127.0.0.1:3080'
    // Match the actual DSH Node carrier, including its synthetic URL base.
    const req = new Request(`http://dsh.internal/api/secret-vault/${action}`, {
      method: 'POST', headers: { origin: options.crossOrigin || origin,
        ...(options.noHost ? {} : { host: options.host || new URL(origin).host }),
        'content-type': 'application/json' },
      body: typeof body === 'string' ? body : JSON.stringify(body),
    })
    const res = await routes.get(action)(req)
    return { status: res.status, value: await res.json() }
  }
  return { store, routes, call }
}

test('private admission returns only a random path and locks owner session before returning', async t => {
  const { store, routes, call } = await fixture(t)
  assert.deepEqual([...routes.keys()], ['save', 'list', 'used', 'delete', 'release'])
  const value = randomBytes(24).toString('hex')
  const saved = await call('save', { sessionId: 'idle', value })
  assert.equal(saved.status, 200)
  assert.equal(store.isLocked('idle'), false)
  assert.equal(saved.value.reference, `@${saved.value.entry.path}`)
  // A bare hex blob carries no labels, so the summary is honestly empty-but-present.
  assert.equal(typeof saved.value.shapeLine, 'string')
  assert.equal(typeof saved.value.entry.shape, 'object')
  assert(!JSON.stringify(saved).includes(value))
  assert.equal((await call('list', { sessionId: 'other' })).value.entries.length, 0)
  assert.equal((await call('used', { sessionId: 'other', reference: saved.value.entry.id })).status, 400)
})

test('reject LAN HTTP, cross-origin, active sessions, arbitrary fields and malformed JSON', async t => {
  const { call } = await fixture(t)
  const normal = { sessionId: 'idle', value: 'synthetic example' }
  assert.equal((await call('save', normal, { origin: 'http://192.0.2.1:3080' })).status, 403)
  assert.equal((await call('save', normal, { crossOrigin: 'http://other.example' })).status, 403)
  assert.equal((await call('save', { ...normal, sessionId: 'running' })).status, 409)
  assert.equal((await call('save', { ...normal, command: 'sh' })).status, 400)
  const bad = await call('save', '{"sessionId":"idle","value":"private malformed')
  assert.equal(bad.status, 400)
  assert(!JSON.stringify(bad).includes('malformed'))
})

test('HTTPS proxy entry is admitted via Host/Origin, never the DSH synthetic URL', async t => {
  const { call } = await fixture(t)
  const body = { sessionId: 'idle', value: 'synthetic proxy example' }
  assert.equal((await call('save', body, { origin: 'https://private.example:4433' })).status, 200)
  assert.equal((await call('save', body, { origin: 'https://private.example:4433', noHost: true })).status, 403)
  assert.equal((await call('save', body, { origin: 'https://private.example:4433', host: 'other.example:4433' })).status, 403)
  assert.equal((await call('save', body, { origin: 'ftp://private.example:4433' })).status, 403)
})

test('user-only completion marks records used, cannot unlock while private files remain', async t => {
  const { store, call } = await fixture(t)
  const saved = await call('save', { sessionId: 'idle', value: 'synthetic example' })
  const reference = saved.value.entry.id
  assert.equal((await call('release', { sessionId: 'idle' })).status, 400)
  assert.equal((await call('used', { sessionId: 'idle', reference })).status, 200)
  assert.equal(store.list('idle')[0].used, true)
})

test('delete and list still work while the session is running (only save needs an idle session)', async t => {
  const { store, call } = await fixture(t)
  const entry = await store.save('running', 'synthetic running example')
  assert.equal(store.isLocked('running'), false)
  assert.equal((await call('list', { sessionId: 'running' })).status, 200)
  assert.equal((await call('save', { sessionId: 'running', value: 'blocked' })).status, 409)
  const removed = await call('delete', { sessionId: 'running', reference: entry.id })
  assert.equal(removed.status, 200)
  assert.equal(removed.value.released, false)
  assert.equal(store.isLocked('running'), false)
})

test('user-initiated delete removes only own entries and releases the lock when the store empties', async t => {
  const { store, call } = await fixture(t)
  const saved = await call('save', { sessionId: 'idle', value: 'synthetic delete example' })
  const reference = saved.value.entry.id
  assert.equal((await call('delete', { sessionId: 'other', reference })).status, 400)
  assert.equal((await call('delete', { sessionId: 'idle', reference, extra: 1 })).status, 400)
  assert.equal(store.list('idle').length, 1)
  const removed = await call('delete', { sessionId: 'idle', reference })
  assert.equal(removed.status, 200)
  assert.equal(removed.value.released, false)
  assert.equal(removed.value.locked, false)
  assert.deepEqual(removed.value.entries, [])
  assert.equal(store.list('idle').length, 0)
  assert.equal(store.isLocked('idle'), false)
  assert.equal((await call('release', { sessionId: 'idle' })).status, 200)
})
