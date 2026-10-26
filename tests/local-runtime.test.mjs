/** Exercise the actual installed DSH dispatch pipeline, not a homemade hook simulation. */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { Context } from '/opt/dsh-web/node_modules/@deepseek-ai/cordis/lib/index.js'
import { ToolRuntime } from '/opt/dsh-web/node_modules/@deepseek-ai/dsh-tools/lib/index.js'
import { openStore } from '../store.js'
import { createTools } from '../tools.js'
import { createGuard } from '../guard.js'
import { transformLocally } from '../local-operations.js'

test('installed DSH runtime: blocked body never runs; allowed result stays content-free', async t => {
  const root = await mkdtemp('/var/tmp/private-runtime-test-')
  t.after(() => rm(root, { recursive: true, force: true }))
  const store = await openStore(join(root, 'data'))
  const value = randomBytes(20).toString('hex')
  const entry = await store.save('owner', `  ${value}  `)
  const ctx = new Context()
  const releasePrompt = ctx.provide('systemPrompt', { tools: () => () => {} })
  const tools = new ToolRuntime(ctx)
  const releases = createTools(store).map(tool => tools.register(tool))
  const schema = tools.schemas().find(s => s.name === 'private_local_process').parameters
  assert.equal(schema.type, 'object')
  assert.equal(schema.additionalProperties, false)
  assert.deepEqual(schema.required, ['reference', 'operation'])
  assert(schema.properties.operation.enum.includes('json_pretty'))
  let executed = false
  releases.push(tools.register({ name: 'arbitrary_command', description: 'test only', parameters: {},
    output: { schema: { type: 'string' }, render: (_, v) => [{ type: 'text', text: v }] },
    execute: async () => { executed = true; return 'not private' } }))
  let named = 0
  releases.push(tools.register({ name: 'name_the_store', description: 'test only', parameters: {},
    output: { schema: { type: 'string' }, render: (_, v) => [{ type: 'text', text: v }] },
    execute: async args => { named++; return String(args?.path ?? '') } }))
  releases.push(tools.guard(createGuard(store)))
  const signal = new AbortController().signal
  const invoke = (name, args) => tools.execute({ name, arguments: args, agent: { id: 'owner' },
    callId: 'synthetic-call', signal })
  try {
    // v4.3.0: holding a private file no longer freezes the session's other tools.
    const allowed = await invoke('arbitrary_command', {})
    assert.equal(allowed.isError, false)
    assert.equal(executed, true)
    // ...but a call that names the private directory is refused before its body runs.
    const denied = await invoke('name_the_store', { path: `${store.dir}/state.json` })
    assert.equal(denied.isError, true)
    assert.equal(named, 0)
    const processed = await invoke('private_local_process', { reference: entry.path, operation: 'trim_edges' })
    assert.equal(processed.isError, false)
    assert.equal(processed.value.ok, true)
    assert(!JSON.stringify(processed).includes(value), 'canonical value/content/meta must not contain plaintext')
    assert.equal(await readFile(processed.value.result.path, 'utf8'), value)
  } finally {
    for (const release of releases.reverse()) await release()
    await releasePrompt()
  }
})

test('JSON formatting preserves large numeric tokens and duplicate keys', () => {
  const raw = '{"n":9999999999999999999999999,"n":-0,"s":"a\\nb"}'
  const pretty = transformLocally(raw, 'json_pretty')
  assert.equal(transformLocally(pretty, 'json_compact'), raw)
})
