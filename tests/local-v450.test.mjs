/** v4.5.0 contracts: narrow guard, honest status, write_secret, exit redaction. */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm, readFile, writeFile, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { openStore } from '../store.js'
import { createTools } from '../tools.js'
import { createGuard } from '../guard.js'
import { selectSecret } from '../secret-write.js'
import { redact } from '../redact.js'
import { registerExitRedaction } from '../exit-redact.js'
import { Context } from '/opt/dsh-web/node_modules/@deepseek-ai/cordis/lib/index.js'
import { ToolRuntime } from '/opt/dsh-web/node_modules/@deepseek-ai/dsh-tools/lib/index.js'

async function fixture(t) {
  const root = await mkdtemp('/var/tmp/private-v450-test-')
  t.after(() => rm(root, { recursive: true, force: true }))
  const store = await openStore(join(root, 'data'))
  return { root, store }
}
const exec = owner => ({ agent: { id: owner } })

test('guard: prose that merely names the vault is allowed, a path argument is refused', async t => {
  const { store } = await fixture(t)
  const entry = await store.save('owner', `key ${randomBytes(16).toString('hex')}`)
  const guard = createGuard(store)
  // The five refusals a real session hit: a report, a compression summary, a message to
  // another agent, a script whose body mentions the directory, a normal command.
  assert.equal(guard({ name: 'bash', arguments: { command: 'date' }, ...exec('owner') }), undefined)
  assert.equal(guard({ name: 'compress', arguments: { content: `见 ${store.dir} 里的文件` }, ...exec('owner') }), undefined)
  assert.equal(guard({ name: 'bus_send', arguments: { text: `请读 ${store.dir}` }, ...exec('owner') }), undefined)
  assert.equal(guard({ name: 'write', arguments: { file_path: '/var/tmp/apply.py',
    content: `VAULT = "${store.dir}"\nprint("hi")` }, ...exec('owner') }), undefined)
  assert.equal(guard({ name: 'bash', arguments: { command: 'ls /var/tmp' }, ...exec('owner') }), undefined)
  // ...while a call that would actually read the bytes is still refused.
  for (const args of [
    { file_path: entry.path },
    { command: `cat ${entry.path}` },
    { cwd: store.dir },
    { paths: [`${store.dir}/state.json`] },
    { command: `ls ${store.dir}` },
  ]) assert.equal(typeof guard({ name: 'bash', arguments: args, ...exec('owner') }), 'string', JSON.stringify(args))
  assert.equal(typeof guard({ name: 'read', arguments: { file_path: entry.path }, ...exec('other') }), 'string')
})

test('guard: a call with no session id keeps its tools unless it touches the vault', async t => {
  const { store } = await fixture(t)
  const entry = await store.save('owner', randomBytes(16).toString('hex'))
  const guard = createGuard(store)
  // This was the machine-wide outage: `!owner && store.hasFiles()` denied every tool.
  assert.equal(guard({ name: 'bash', arguments: { command: 'date' } }), undefined)
  assert.equal(guard({ name: 'read', arguments: { file_path: '/var/tmp/notes.md' } }), undefined)
  assert.equal(typeof guard({ name: 'read', arguments: { file_path: entry.path } }), 'string')
})

test('status answers in one call: mode, what is restricted, and how it ends', async t => {
  const { store } = await fixture(t)
  const status = createTools(store)[0]
  const empty = await status.execute({}, exec('owner'))
  assert.equal(empty.mode, 'normal')
  assert.deepEqual(empty.restricts, [])
  const entry = await store.save('owner', randomBytes(16).toString('hex'))
  const full = await status.execute({}, exec('owner'))
  assert.equal(full.mode, 'local_only')
  assert.deepEqual(full.restricts, ['args naming the private directory'])
  assert.match(full.releaseWhen, /删除|清理/)
  assert.equal(full.entries[0].id, entry.id)
  // The status payload is metadata only: the saved value never appears in it.
  assert(!JSON.stringify(full).includes(await readFile(entry.path, 'utf8')))
})

test('write_secret puts the value in the target file and returns only a fingerprint', async t => {
  const { root, store } = await fixture(t)
  const key = `sk-${randomBytes(18).toString('hex')}`
  const entry = await store.save('owner', `密钥：${key}`)
  const target = join(root, 'app.env')
  await writeFile(target, '# app\nAPI_KEY=old\nOTHER=1\n')
  const tool = createTools(store)[1]
  const result = await tool.execute({ reference: entry.id, operation: 'write_secret',
    target, key_path: 'API_KEY' }, exec('owner'))
  assert.equal(result.ok, true)
  assert.equal(result.status, 'written')
  const written = await readFile(target, 'utf8')
  assert(written.includes(key), 'the value must reach the file')
  assert(written.includes('OTHER=1'), 'neighbouring keys stay untouched')
  // The model-facing payload carries no value, and the rendered block carries none either.
  assert(!JSON.stringify(result).includes(key))
  assert(!JSON.stringify(tool.output.render({}, result)).includes(key))
  assert.match(result.fingerprint, /^[a-f0-9]{8}$/)
  // An existing file keeps the mode the user gave it: tightening it here would break a
  // reader (php-fpm, a service user) that was working before we touched the file.
  assert.equal((await stat(target)).mode & 0o777, 0o644)
})

test('write_secret seeds a missing file, refuses a target inside the vault, and re-checks mode', async t => {
  const { root, store } = await fixture(t)
  const entry = await store.save('owner', `key：${randomBytes(16).toString('hex')}`)
  const tool = createTools(store)[1]
  const fresh = join(root, 'nested.json')
  assert.equal((await tool.execute({ reference: entry.id, operation: 'write_secret',
    target: fresh, key_path: 'ai.key' }, exec('owner'))).ok, true)
  const created = JSON.parse(await readFile(fresh, 'utf8'))
  assert.equal(typeof created.ai.key, 'string')
  // A target inside the vault would let a write loop back into private storage.
  assert.equal((await tool.execute({ reference: entry.id, operation: 'write_secret',
    target: join(store.dir, 'planted.env'), key_path: 'A' }, exec('owner'))).ok, false)
  // Another session cannot spend this entry.
  assert.equal((await tool.execute({ reference: entry.id, operation: 'write_secret',
    target: join(root, 'x.env'), key_path: 'A' }, exec('other'))).ok, false)
  assert.equal((await tool.execute({ reference: entry.id, operation: 'write_secret',
    target: join(root, 'x.env'), key_path: 'A', mode: 'guess' }, exec('owner'))).ok, false)
})

test('selectSecret takes the tightest secret span, not one that swallowed the prose', () => {
  const key = `sk-${randomBytes(18).toString('hex')}`
  const value = selectSecret(`密钥 ${key} 后面还有一句说明`, 'first-secret')
  assert.equal(value, key)
  assert.equal(selectSecret(`密钥：${key}`, 'first-secret'), key)
  assert.throws(() => selectSecret('这里没有密钥', 'first-secret'), /PRIVATE_OPERATION_FAILED/)
  assert.throws(() => selectSecret('', 'whole'), /PRIVATE_OPERATION_FAILED/)
})

test('installed runtime: a key printed by an unrelated tool is masked on the way out', async t => {
  const { root, store } = await fixture(t)
  const ctx = new Context()
  const releasePrompt = ctx.provide('systemPrompt', { tools: () => () => {} })
  const tools = new ToolRuntime(ctx)
  const key = `sk-${randomBytes(18).toString('hex')}`
  const releases = [
    tools.register({ name: 'leaky_command', description: 'test only', parameters: {},
      output: { schema: { type: 'string' }, render: (_, v) => [{ type: 'text', text: v }] },
      // Simulates the reported incident: a bad `sed` echoes a key into tool output.
      execute: async () => `API_KEY=${key}\ndone` }),
    tools.register({ name: 'clean_command', description: 'test only', parameters: {},
      output: { schema: { type: 'string' }, render: (_, v) => [{ type: 'text', text: v }] },
      execute: async () => 'nothing secret here' }),
    registerExitRedaction(ctx),
  ]
  const signal = new AbortController().signal
  const invoke = (name, args) => tools.execute({ name, arguments: args, agent: { id: 'owner' },
    callId: `synthetic-${name}`, signal })
  try {
    const leaked = await invoke('leaky_command', {})
    assert.equal(leaked.isError, false)
    const text = leaked.content.map(b => b.text ?? '').join('\n')
    assert(!text.includes(key), 'the key must not reach the transcript')
    assert.match(text, /已打码/)
    const clean = await invoke('clean_command', {})
    assert.equal(clean.content.map(b => b.text ?? '').join(''), 'nothing secret here')
  } finally {
    for (const release of releases.reverse()) await release()
    await releasePrompt()
  }
})

test('redact leaves ordinary output and file paths alone', () => {
  for (const text of [
    '/root/xiangmudata_sync/paihang2/config/secrets.local.php 已更新',
    'commit 868058d1a2b3c4d5e6f7890abcdef0123456789a',
    'uuid 550e8400-e29b-41d4-a716-446655440000',
    `tmp-${'0'.repeat(32)}`,
  ]) assert.equal(redact(text), text)
})
