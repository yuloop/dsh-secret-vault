/** Classification cascade: right kinds, safe abstention, masked inputs, no value leakage. */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { analyze, classify, COST } from '../classify.js'
import { describe, mask } from '../field-shape.js'

const SAMPLES = {
  'provider-config': '为 http://192.0.2.10:8080 增加一个模型供应商 https://tokenrhythm.studio 模型 deepseek-v4.1-flash-1017 密钥 Ab3xk2m9QzW1pL5vT8nR4cK7d',
  'server-login': 'ssh root@198.51.100.9 -p 22022 密码 Qwe12345!',
  'db-credential': 'mysql://app:Pa55w0rd@198.51.100.5:3306/prod 数据库连接串',
  'bank-sms': '【某银行】您尾号1234的卡转出 5000 元。验证码：483920，5分钟内有效。',
  identity: '姓名：张三 身份证 110101198803151234 住址：北京市海淀区',
  'api-keys': 'API 清单：token abcd1234efgh5678ijkl9012mnop3456',
}

test('each representative sample lands in its own kind', () => {
  for (const [kind, text] of Object.entries(SAMPLES)) {
    assert.equal(analyze(text).shape.kind, kind, text)
  }
})

test('ordinary prose abstains instead of guessing', () => {
  const shape = analyze('明天下午三点开会，记得带材料').shape
  assert.equal(shape.kind, 'unknown')
  assert.equal(shape.confidence, 'high')
  assert.equal(shape.sensitivity, 'low')
})

test('masking hides every value and keeps placeholder length constant', () => {
  const text = SAMPLES['provider-config']
  const report = describe(text)
  const { masked, replaced } = mask(text, report)
  assert(replaced >= 3)
  for (const secret of ['Ab3xk2m9QzW1pL5vT8nR4cK7d', '192.0.2.10', 'tokenrhythm.studio']) {
    assert.equal(masked.includes(secret), false, `leaked ${secret}`)
  }
  // Placeholders carry no size hint.
  assert.equal(/\[\[[A-Z]+_\d+\]\]/.test(masked), false)
  assert.match(masked, /\[\[SECRET\]\]/)
})

test('the persisted digest never contains a value', () => {
  const text = SAMPLES['identity']
  const shape = analyze(text).shape
  const blob = JSON.stringify(shape)
  for (const value of ['张三', '110101198803151234', '北京市海淀区']) assert.equal(blob.includes(value), false, value)
  assert.equal(shape.sensitivity, 'pii')
  assert.equal(typeof shape.advice, 'string')
})

test('a semantic fallback only fills gaps the rules left unknown', () => {
  const masked = '[[SECRET]] 和 [[URL]] 都在这里'
  const rulesOnly = classify(masked, analyze('普通一句话').shape)
  assert.equal(rulesOnly.kind, 'unknown')
  const withModel = classify(masked, analyze('普通一句话').shape, () => ({ kind: 'provider-config', confidence: 0.8 }))
  assert.equal(withModel.kind, 'provider-config')
  assert.equal(withModel.tier, 'model')
  const unsure = classify(masked, analyze('普通一句话').shape, () => ({ kind: 'provider-config', confidence: 0.3 }))
  assert.equal(unsure.kind, 'unknown', 'low-confidence model output must not decide')
})

test('cost matrix ranks the dangerous confusions highest', () => {
  assert.equal(COST['bank-sms>provider-config'], 10)
  assert.equal(COST['identity>provider-config'], 10)
  assert.equal(COST['>unknown'], 0.5)
})

test('cascade is fast enough for the save path', () => {
  const started = process.hrtime.bigint()
  for (let i = 0; i < 50; i++) analyze(SAMPLES['server-login'])
  const perCall = Number(process.hrtime.bigint() - started) / 1e6 / 50
  assert(perCall < 20, `per-call ${perCall.toFixed(2)} ms`)
})
