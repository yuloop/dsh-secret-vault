/** The host rescue CLI must work without the browser and never echo file contents. */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { randomBytes } from 'node:crypto'
import { openStore } from '../store.js'

const run = promisify(execFile)
const CLI = new URL('../bin/secret-vault.mjs', import.meta.url).pathname

async function fixture(t) {
  const root = await mkdtemp('/var/tmp/private-cli-test-')
  t.after(() => rm(root, { recursive: true, force: true }))
  const home = join(root, 'home')
  const store = await openStore(join(home, 'secret-vault', 'local-v4'))
  const call = async (...args) => {
    try {
      const { stdout } = await run(process.execPath, [CLI, ...args], { env: { ...process.env, DSH_HOME: home } })
      return { code: 0, out: stdout }
    } catch (error) { return { code: error.code, out: `${error.stdout ?? ''}${error.stderr ?? ''}` } }
  }
  return { store, call }
}

test('status is read-only and reports entries without their contents', async t => {
  const { store, call } = await fixture(t)
  const empty = await call('status')
  assert.equal(empty.code, 0)
  assert.match(empty.out, /没有任何条目/)
  const secret = randomBytes(16).toString('hex')
  const entry = await store.save('session-a', secret)
  const listed = await call('status')
  assert.equal(listed.code, 0)
  assert(listed.out.includes(entry.id))
  assert(!listed.out.includes(secret))
  assert.match(listed.out, /条目=1/)
})

test('release refuses while files remain and succeeds once they are gone', async t => {
  const { store, call } = await fixture(t)
  const entry = await store.save('session-a', randomBytes(8).toString('hex'))
  const refused = await call('release', 'session-a')
  assert.equal(refused.code, 2)
  assert.match(refused.out, /还有 1 个文件/)
  await store.remove('session-a', entry.id)
  const released = await call('release', 'session-a')
  assert.equal(released.code, 0)
  // The last removal already released the lock, so release is a harmless no-op now.
  assert.match(released.out, /没有锁|仍锁定=false/)
})

test('purge needs --yes, then deletes and unlocks even from a stranded lock', async t => {
  const { store, call } = await fixture(t)
  const entry = await store.save('session-a', randomBytes(8).toString('hex'))
  const guarded = await call('purge', 'session-a')
  assert.equal(guarded.code, 2)
  assert.match(guarded.out, /加 --yes/)
  assert.equal(store.list('session-a').length, 1)
  const purged = await call('purge', 'session-a', '--yes')
  assert.equal(purged.code, 0)
  assert.match(purged.out, /剩余条目=0 仍锁定=false/)
  // The CLI ran in its own process, so verify against a freshly opened store.
  const reopened = await openStore(store.dir)
  assert.equal(reopened.hasFiles(), false)
  assert.equal(reopened.isLocked('session-a'), false)
})

test('an unknown subcommand prints usage and exits 2', async t => {
  const { call } = await fixture(t)
  const result = await call('frobnicate')
  assert.equal(result.code, 2)
  assert.match(result.out, /私密存储救援命令/)
})

test('a truncated session id resolves by prefix instead of looking like an empty session', async t => {
  const { store, call } = await fixture(t)
  const entry = await store.save('session-abcdefgh-1234', randomBytes(8).toString('hex'))
  const purged = await call('purge', 'session-abcdefgh', '--yes')
  assert.equal(purged.code, 0)
  assert.match(purged.out, /按前缀匹配到会话 session-abcdefgh-1234/)
  assert.match(purged.out, /剩余条目=0/)
  const reopened = await openStore(store.dir)
  assert.equal(reopened.list('session-abcdefgh-1234').length, 0)
  assert.equal(reopened.isLocked('session-abcdefgh-1234'), false)
  void entry
})

test('an unknown session id is refused and lists the sessions that do have content', async t => {
  const { store, call } = await fixture(t)
  await store.save('session-zzzz-9999', randomBytes(8).toString('hex'))
  const result = await call('purge', 'session-nope', '--yes')
  assert.equal(result.code, 0) // nothing to do is not an error...
  assert.match(result.out, /无需操作/)
  assert.match(result.out, /session-zzzz-9999/) // ...but it names what does have content
})

test('a no-op says nothing changed and never hints at a restart', async t => {
  const { call } = await fixture(t)
  const result = await call('purge', 'session-none-0000', '--yes')
  assert.equal(result.code, 0)
  assert.match(result.out, /无需操作/)
  assert.equal(result.out.includes('旧状态'), false, 'no restart hint without a change')
  const release = await call('release', 'session-none-0000')
  assert.equal(release.code, 0)
  assert.equal(release.out.includes('旧状态'), false)
})

test('fields decomposes a messy blob and never prints the value', async t => {
  const { store, call } = await fixture(t)
  // Deliberately synthetic: random enough to be detected, no real provider shape.
  const secret = `fixture-${randomBytes(18).toString('hex')}`
  const blob = `为 http://192.0.2.10:8080 增加一个供应商 https://tokenrhythm.studio 模型 deepseek-v4.1-flash-1017 密钥 ${secret}`
  await store.save('session-fields-0001', blob)
  const out = await call('fields')
  assert.equal(out.code, 0)
  assert.match(out.out, /192\.0\.2\.10:8080/)
  assert.match(out.out, /tokenrhythm\.studio/)
  assert.match(out.out, /deepseek-v4\.1-flash-1017/)
  assert.match(out.out, new RegExp(`长度=${secret.length}`))
  assert.equal(out.out.includes(secret), false, 'the secret value must never reach stdout')
  assert.equal(out.out.includes('fixture-not-a-key'), false)
})
