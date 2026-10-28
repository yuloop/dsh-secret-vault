/** Outbound redaction: credentials must be masked, look-alikes must survive, and masking is stable. */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { redact, redactBlocks } from '../redact.js'

const sha8 = text => createHash('sha256').update(text).digest('hex').slice(0, 8)
/** Fixtures are assembled at runtime so no repository file contains a token-shaped literal;
 *  the repo's own secret scanner would otherwise block the commit (and rightly so). */
const synth = (...parts) => parts.join('')
const masked = token => `${token.slice(0, 4)}…【已打码 ${sha8(token)}】`

const OPENAI = synth('sk-', 'abcdefghijklmnopqrstuvwx')
const OPENAI_US = synth('sk_', '9aBcDeFgHiJkLmNoPqRs')
const AWS_KEY = synth('AKIA', 'IOSFODNN7EXAMPLE')
const AWS_STS = synth('ASIA', 'ABCDEFGHIJKLMNOP')
const GH_PAT = synth('ghp_', 'aB3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zA6b7')
const GH_OAUTH = synth('gho_', 'abcdefghijklmnopqrstuvwxyz0123456789')
const GH_FINE = synth('github_pat_', '11ABCDEFG0123456789_abcdefghijklmnop')
const SLACK = synth('xoxb-', '1234567890-abcdefghijkl')
const GOOGLE = synth('AIza', 'SyA1234567890abcdefghijklmnopqrstu')
const JWT = synth('eyJhbGciOiJIUzI1NiJ9', '.', 'eyJzdWIiOiIxMjM0NTY3ODkwIn0', '.',
  'dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U')
const BEARER = synth('abcdefghijklmnopqrstuvwxyz', '123456')
const GENERIC = synth('Qw3rT5yU7iO9', 'pAs2Df4gH6jK8lZ1xC3v')

/** One sample per credential family: vendor prefixes, JWT, Bearer, generic high-entropy run. */
function credentials() {
  return [
    { name: 'openai', text: `export OPENAI_KEY=${OPENAI}`, token: OPENAI },
    { name: 'openai-underscore', text: `key ${OPENAI_US} end`, token: OPENAI_US },
    { name: 'aws-akia', text: `aws ${AWS_KEY} here`, token: AWS_KEY },
    { name: 'aws-asia', text: `sts ${AWS_STS} done`, token: AWS_STS },
    { name: 'github-ghp', text: `token ${GH_PAT}`, token: GH_PAT },
    { name: 'github-gho', text: `oauth ${GH_OAUTH}`, token: GH_OAUTH },
    {
      name: 'github-pat',
      text: `pat ${GH_FINE}`,
      token: GH_FINE,
    },
    { name: 'slack', text: `slack ${SLACK}`, token: SLACK },
    { name: 'google', text: `maps ${GOOGLE}`, token: GOOGLE },
    {
      name: 'jwt',
      text: `auth ${JWT}`,
      token: JWT,
    },
    { name: 'bearer', text: `Authorization: Bearer ${BEARER}`, token: BEARER },
    { name: 'generic', text: `value ${GENERIC} end`, token: GENERIC },
  ]
}

/** Six-plus look-alikes that must come back byte-identical. */
function lookalikes() {
  return [
    { name: '中文段落', text: '这是一段普通的中文说明，没有任何凭据，只是把结果解释清楚。' },
    { name: '英文段落', text: 'The quick brown fox jumps over the lazy dog while the build finishes.' },
    { name: 'UUID', text: '550e8400-e29b-41d4-a716-446655440000' },
    { name: '路径', text: '/root/x/y/z.php' },
    { name: '长路径', text: '/root/xiangmudata_sync/dsh-secret-vault/redact.js' },
    { name: '40位小写hex', text: 'da39a3ee5e6b4b0d3255bfef95601890afd80709' },
    { name: 'tmp引用id', text: 'tmp-0123456789abcdef0123456789abcdef' },
    { name: 'URL', text: 'see https://example.com/path?a=1&b=2 for details' },
    { name: '带连字符的路径式文本', text: 'documentation/guides/installation-steps' },
  ]
}

test('every credential family is masked and its full text never appears', () => {
  const failures = []
  for (const sample of credentials()) {
    const out = redact(sample.text)
    if (out.includes(sample.token)) failures.push(`${sample.name}: token echoed`)
    if (!out.includes('【已打码 ')) failures.push(`${sample.name}: no marker in ${JSON.stringify(out)}`)
    if (out === sample.text) failures.push(`${sample.name}: untouched`)
  }
  assert.deepEqual(failures, [])
})

test('first four characters and the marker survive; the rest is a fingerprint', () => {
  const failures = []
  for (const sample of credentials()) {
    const out = redact(sample.text)
    if (!out.includes(sample.token.slice(0, 4))) failures.push(`${sample.name}: prefix lost`)
    const expected = sample.name === 'bearer' ? sample.token.slice(0, 4) : masked(sample.token).slice(0, 4)
    if (!out.includes(expected)) failures.push(`${sample.name}: prefix mismatch`)
    if (!/…【已打码 [0-9a-f]{8}】/.test(out)) failures.push(`${sample.name}: marker shape ${JSON.stringify(out)}`)
  }
  assert.deepEqual(failures, [])
})

test('the masked form keeps only the first four characters of the credential', () => {
  const token = OPENAI
  const out = redact(`key ${token} end`)
  assert.equal(out, `key ${masked(token)} end`)
  assert.ok(out.startsWith('key sk-a'), 'first four characters are kept')
  // Nothing past the fourth character may reappear, not even a short run of it.
  for (let i = 4; i + 4 <= token.length; i++) {
    const run = token.slice(i, i + 4)
    assert.ok(!out.includes(run), `run ${run} leaked`)
  }
})

test('Bearer keeps its prefix while the token itself is masked', () => {
  const token = 'abcdefghijklmnopqrstuvwxyz123456'
  const out = redact(`Authorization: Bearer ${token}`)
  assert.equal(out, `Authorization: Bearer ${masked(token)}`)
  assert.ok(!out.includes(token))
})

test('negatives: prose, UUIDs, paths, short hex, plugin ids and URLs are untouched', () => {
  const failures = []
  for (const sample of lookalikes()) {
    const out = redact(sample.text)
    if (out !== sample.text) failures.push(`${sample.name}: ${JSON.stringify(out)}`)
  }
  assert.deepEqual(failures, [])
})

test('short hex and lowercase git shas stay readable', () => {
  for (const text of ['deadbeef', '0123456789abcdef0123456789abcdef0', 'abc123', 'commit 4f9c2ab1']) {
    assert.equal(redact(text), text, text)
  }
})

test('idempotent: masking twice equals masking once', () => {
  const samples = [...credentials().map(s => s.text), 'no secrets at all in this line']
  for (const text of samples) {
    const once = redact(text)
    assert.equal(redact(once), once, text)
  }
})

test('a mixed log line masks only the key and the JWT', () => {
  const key = OPENAI
  const jwt = JWT
  const lines = [
    '2026-10-28T10:00:00Z INFO  start worker pid=4242',
    `2026-10-28T10:00:01Z DEBUG config key=${key} loaded`,
    `2026-10-28T10:00:02Z DEBUG auth header=x ${jwt} sent`,
    '2026-10-28T10:00:03Z INFO  done in 1200ms path=/root/x/y/z.php',
  ]
  const out = redact(lines.join('\n')).split('\n')
  assert.equal(out.length, lines.length)
  assert.equal(out[0], lines[0], 'plain line must not change')
  assert.equal(out[3], lines[3], 'path line must not change')
  assert.ok(!out.join('\n').includes(key))
  assert.ok(!out.join('\n').includes(jwt))
  assert.ok(out[1].includes('key=sk-a…【已打码 '))
  assert.ok(out[2].includes('eyJh…【已打码 '))
  // Exactly two lines changed, so nothing else was caught by accident.
  assert.equal(out.filter((line, i) => line !== lines[i]).length, 2)
})

test('a key inside a URL query is masked, a slug that merely starts with sk- is not', () => {
  const key = OPENAI
  const url = `https://api.example.com/v1/items?key=${key}&page=2`
  const out = redact(url)
  assert.ok(!out.includes(key))
  assert.ok(out.includes('?key=sk-a…【已打码 '))
  assert.ok(out.endsWith('&page=2'), 'the rest of the URL survives')
  const slug = `see https://example.com/${synth('sk-', 'documentation-of-something-long-page')} now`
  assert.equal(redact(slug), slug, 'a documentation slug is not a credential')
})

test('redactBlocks touches only text blocks', () => {
  const image = { type: 'image', source: { type: 'base64', data: OPENAI } }
  const json = { type: 'json', json: { key: OPENAI } }
  const blocks = [
    { type: 'text', text: `key ${OPENAI} end` },
    image,
    json,
    { type: 'text', text: 'nothing to hide here' },
  ]
  const out = redactBlocks(blocks)
  assert.equal(out.length, 4)
  assert.ok(!out[0].text.includes(OPENAI))
  assert.ok(out[0].text.includes('【已打码 '))
  assert.equal(out[1], image, 'image block is passed through by reference')
  assert.equal(out[2], json, 'json block is passed through by reference')
  assert.equal(out[3].text, 'nothing to hide here')
  assert.deepEqual(blocks[0].text, `key ${OPENAI} end`, 'input is not mutated')
})

test('redactBlocks tolerates junk input instead of throwing', () => {
  assert.equal(redactBlocks(null), null)
  assert.equal(redactBlocks('not an array'), 'not an array')
  assert.deepEqual(redactBlocks([]), [])
  const weird = [null, undefined, 42, { type: 'text' }, { type: 'text', text: 7 }, { noType: true }]
  assert.deepEqual(redactBlocks(weird), weird)
})

test('redact never throws on odd input', () => {
  for (const value of [undefined, null, 0, false, {}, [], 'x']) {
    assert.doesNotThrow(() => redact(value))
    assert.equal(redact(value), value)
  }
  assert.equal(redact(''), '')
})
