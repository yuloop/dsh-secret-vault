/** Browser-only admission of private bytes; no message/attachment/tool-call pipeline. */
import { MAX_BYTES, OWNER } from './local-files.js'
import { shapeLine } from './field-shape.js'

const BASE = '/api/secret-vault'
const response = (status, value) => Response.json(value, {
  status, headers: { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' },
})
const failed = () => response(400, { ok: false, status: 'operation_failed' })
// Only saving injects new private content that a running turn could race with. Listing,
// marking used, deleting and releasing are metadata/cleanup work: requiring an idle session
// for them stranded sessions whenever the user acted mid-turn (observed 2026-10-25).
const IDLE_ONLY = new Set(['save'])

function trustedTransport(request) {
  try {
    const origin = new URL(request.headers.get('origin'))
    // DSH's authenticated carrier builds request.url on http://dsh.internal.
    // Its real, already-admitted authority remains in Host; never compare to that placeholder.
    const authority = request.headers.get('host')
    if (!authority || origin.host !== authority || origin.username || origin.password) return false
    const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(origin.hostname)
    return origin.protocol === 'https:' || (origin.protocol === 'http:' && loopback)
  } catch { return false }
}

async function bodyOf(request) {
  const reader = request.body?.getReader()
  if (!reader) throw new Error('invalid')
  let size = 0
  const chunks = []
  try {
    for (;;) {
      const { value, done } = await reader.read()
      if (done) break
      size += value.byteLength
      if (size > MAX_BYTES * 6 + 1024) throw new Error('limit')
      chunks.push(value)
    }
  } finally { await reader.cancel().catch(() => {}) }
  const value = JSON.parse(Buffer.concat(chunks).toString('utf8'))
  if (!value || Array.isArray(value) || typeof value !== 'object') throw new Error('invalid')
  if (typeof value.sessionId !== 'string' || !OWNER.test(value.sessionId)) throw new Error('invalid')
  return value
}

function requestHandler(action, deps) {
  return async request => {
    if (!trustedTransport(request)) return response(403, { ok: false, status: 'local_or_https_required' })
    try {
      const data = await bodyOf(request)
      const allowed = action === 'save' ? ['sessionId', 'value'] : ['sessionId', 'reference']
      if (Object.keys(data).some(k => !allowed.includes(k))) return failed()
      if (IDLE_ONLY.has(action) && !deps.isIdleSession(data.sessionId)) {
        return response(409, { ok: false, status: 'session_must_be_idle' })
      }
      return await dispatch(action, data, deps.store)
    } catch { return failed() } // Never return parser errors, stack traces or input snippets.
  }
}

async function dispatch(action, data, store) {
  const owner = data.sessionId
  if (action === 'save') {
    const entry = await store.save(owner, data.value)
    return response(200, { ok: true, entry, reference: `@${entry.path}`,
      shapeLine: entry.shape ? shapeLine(entry.shape) : '' })
  }
  if (action === 'list') return response(200, { ok: true, locked: store.isLocked(owner), entries: store.list(owner) })
  if (action === 'used') return response(200, await store.markUsed(owner, data.reference))
  if (action === 'delete') return response(200, await store.remove(owner, data.reference))
  if (action === 'release') return response(200, await store.release(owner))
  return failed()
}

export function registerRoutes(ctx, deps) {
  // All requests are additionally authenticated by connection's owner-peer carrier.
  for (const action of ['save', 'list', 'used', 'delete', 'release']) {
    ctx.effect(() => ctx.connection.fetch.register({
      path: `${BASE}/${action}`, methods: ['POST'], requestBody: 'streaming',
      fetch: requestHandler(action, deps),
    }))
  }
}
