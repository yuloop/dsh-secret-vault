/** 40-sample corpus: does the shape parser find every planted secret, and only those? */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { describe, shannon, hostOf, parseLabelLine, roleOfLabel } from '../field-shape.js'

const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
const rand = n => { const bytes = randomBytes(n); let out = ''; for (let i = 0; i < n; i++) out += ALPHA[bytes[i] % ALPHA.length]; return out }
const hex = n => randomBytes(Math.ceil(n / 2)).toString('hex').slice(0, n)
const upper = n => rand(n).toUpperCase()

/** Positive samples: text + the values that must be detected and must never be echoed. */
function positives() {
  const v = {
    label49: rand(48), hex32: hex(32), token24: rand(24), pass18: rand(18), cjk16: rand(16),
    gh: `ghp_${rand(36)}`, aws: `AKIA${upper(16)}`, slack: `xoxb-${rand(20)}`, sk: `sk-${rand(32)}`,
    bearer: rand(32), jwt: `eyJ${rand(20)}.${rand(20)}.${rand(20)}`, json40: hex(40),
    nested: rand(30), sentence49: rand(49), yaml28: rand(28), cjkToken: rand(24),
    passwd20: rand(20), secretKey32: rand(32), curl24: rand(24), spaced20: rand(20),
  }
  return [
    { name: 'label-密钥', text: `密钥: ${v.label49}`, values: [v.label49] },
    { name: 'label-api_key-hex', text: `api_key: ${v.hex32}`, values: [v.hex32] },
    { name: 'label-token', text: `token=${v.token24}`, values: [v.token24] },
    { name: 'label-password', text: `password: ${v.pass18}`, values: [v.pass18] },
    { name: 'label-密码', text: `密码：${v.cjk16}`, values: [v.cjk16] },
    { name: 'rule-github', text: `GITHUB_TOKEN=${v.gh}`, values: [v.gh] },
    { name: 'rule-aws', text: `aws_access_key_id = ${v.aws}`, values: [v.aws] },
    { name: 'rule-slack', text: `slack: ${v.slack}`, values: [v.slack] },
    { name: 'rule-openai-style', text: `key ${v.sk}`, values: [v.sk] },
    { name: 'rule-bearer', text: `Authorization: Bearer ${v.bearer}`, values: [v.bearer] },
    { name: 'rule-jwt', text: `cookie=${v.jwt}`, values: [v.jwt] },
    { name: 'json-api_key', text: JSON.stringify({ api_key: v.json40 }), values: [v.json40] },
    { name: 'json-nested-secret', text: JSON.stringify({ provider: { secret: v.nested } }), values: [v.nested] },
    { name: 'sentence-密钥', text: `为 http://192.0.2.10:8080 加供应商，密钥 ${v.sentence49}`, values: [v.sentence49] },
    { name: 'yaml-secret', text: `secret: ${v.yaml28}`, values: [v.yaml28] },
    { name: 'cjk-访问令牌', text: `访问令牌：${v.cjkToken}`, values: [v.cjkToken] },
    { name: 'cjk-口令', text: `口令=${v.passwd20}`, values: [v.passwd20] },
    { name: 'label-secret_key', text: `secret_key: ${v.secretKey32}`, values: [v.secretKey32] },
    { name: 'curl-bearer', text: `curl -H 'Authorization: Bearer ${v.curl24}' http://x`, values: [v.curl24] },
    { name: 'spaced-equals', text: `password = ${v.spaced20}`, values: [v.spaced20] },
  ]
}

/** Negative samples: identifiers and noise that must NOT be reported as secrets. */
function negatives() {
  return [
    { name: 'model-id', text: 'model: deepseek-v4.1-flash-1017' },
    { name: 'url', text: 'https://tokenrhythm.studio/v1/models' },
    { name: 'path', text: '/opt/dsh-secret-vault/bin/secret-vault.mjs' },
    { name: 'git-sha', text: `commit ${hex(40)}` },
    { name: 'uuid', text: 'id 3f2504e0-4f89-11d3-9a0c-0305e82c3301' },
    { name: 'iso-time', text: 'created 2026-10-25T15:13:05.232Z' },
    { name: 'english-word', text: 'the internationalization of counterrevolutionaries' },
    { name: 'chinese-sentence', text: '把网关的通道加好以后用新模型测一次就好' },
    { name: 'version', text: 'version v4.3.0' },
    { name: 'port', text: 'PORT=3080' },
    { name: 'max-tokens', text: 'max_tokens=3000' },
    { name: 'mixed-case-token', text: `note ${rand(12)}${upper(6)}${rand(6)}` },
    { name: 'base64-image-fragment', text: `data:image/png;base64,${randomBytes(48).toString('base64')}` },
    { name: 'sha256-digest', text: `sha256:${hex(64)}` },
    { name: 'docker-image', text: 'registry.example.com/team/service:v2.1.0' },
    { name: 'email', text: 'admin@example.com' },
    { name: 'url-only-label', text: 'url: https://example.com/v1' },
    { name: 'timeout', text: 'timeout=30000' },
    { name: 'host-line', text: 'host: 192.0.2.10:8080' },
    { name: 'json-config', text: JSON.stringify({ base_url: 'https://x.example/v1', model: 'deepseek-v4.1-flash-1017', timeout: 30000 }) },
  ]
}

test('corpus: every planted secret is detected', () => {
  const missed = []
  for (const sample of positives()) {
    const report = describe(sample.text)
    const lengths = new Set(report.secrets.map(item => item.length))
    for (const value of sample.values) if (!lengths.has(value.length)) missed.push(`${sample.name}(len ${value.length})`)
  }
  assert.deepEqual(missed, [])
})

test('corpus: no planted secret value is ever echoed back', () => {
  const leaked = []
  for (const sample of positives()) {
    const blob = JSON.stringify(describe(sample.text))
    for (const value of sample.values) if (blob.includes(value)) leaked.push(sample.name)
  }
  assert.deepEqual(leaked, [])
})

test('corpus: negative samples produce no secret findings', () => {
  const falsePositives = []
  for (const sample of negatives()) {
    const report = describe(sample.text)
    if (report.secrets.length) falsePositives.push(`${sample.name}: ${report.secrets.map(s => `${s.rule}/${s.length}`).join(',')}`)
  }
  assert.deepEqual(falsePositives, [])
})

test('helpers: entropy separates random material from words', () => {
  assert(shannon(rand(32)) > shannon('internationalization'))
  assert(shannon('aaaaaaaaaaaaaaaaaaaaaaaa') < 1)
  assert.equal(hostOf('https://tokenrhythm.studio/v1/models?token=x'), 'https://tokenrhythm.studio')
  assert.equal(hostOf('not a url'), null)
})

test('helpers: labels map to roles, and a sentence with a URL is not a label', () => {
  assert.equal(roleOfLabel('密钥'), 'secret')
  assert.equal(roleOfLabel('api_key'), 'secret')
  assert.equal(roleOfLabel('地址'), 'address')
  assert.equal(roleOfLabel('model'), 'model')
  assert.equal(parseLabelLine('为 http://x 增加供应商')?.role, undefined)
  assert.equal(parseLabelLine('api_key: value123')?.role, 'secret')
})
