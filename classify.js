/**
 * Content-level classification from the masked skeleton plus the deterministic shape.
 * The result is a SUGGESTION only: nothing here may trigger an automatic action, because a
 * wrong label (bank SMS read as a provider config) would be irreversible.
 * Values never reach this module — callers pass `mask()`ed text.
 */

import { describe, mask, summarize } from './field-shape.js'
import { loadModel, makeFallback } from './tfidf.js'

export const KINDS = ['provider-config', 'server-login', 'db-credential', 'bank-sms', 'identity', 'api-keys', 'mixed', 'unknown']

export const KIND_LABELS = {
  'provider-config': '模型供应商配置',
  'server-login': '服务器登录信息',
  'db-credential': '数据库凭据',
  'bank-sms': '银行/支付短信',
  identity: '身份资料',
  'api-keys': 'API 密钥清单',
  mixed: '混合内容',
  unknown: '未能判定',
}

/** How bad is confusing one kind with another; used by the evaluator, not at runtime. */
export const COST = {
  default: 1,
  'bank-sms>provider-config': 10,
  'identity>provider-config': 10,
  'bank-sms>server-login': 8,
  'identity>server-login': 8,
  'db-credential>provider-config': 5,
  'provider-config>bank-sms': 6,
  '>unknown': 0.5,
}

const ADVICE = {
  'provider-config': '可用于配置供应商；值只在宿主进程内取用，别贴进对话',
  'server-login': '可按登录流程使用；勿写入仓库或日志',
  'db-credential': '仅用于连接数据库；注意别让连接串进日志',
  'bank-sms': '无需动作，建议归档或删除',
  identity: '仅本地查看；不要外发或写进任何配置',
  'api-keys': '可用于配置或调用；按密钥生命周期管理',
  mixed: '含多类内容，逐条确认后再动',
  unknown: '未能判定类型，请人工确认后再使用',
}

const PATTERN = {
  provider: /供应商|渠道|provider|base[\s_-]?url|endpoint|模型名|model[\s_-]?id|apikey|api[\s_-]?key|兼容模式/i,
  login: /ssh|root@|登录|密码|私钥|id_rsa|passwd|passphrase|端口|port\s*\d|跳板/i,
  db: /mysql|postgres|redis|mongo|数据库|jdbc|连接串|dbname|db[\s_-]?host/i,
  bank: /银行|尾号|转入|转出|余额|信用卡|储蓄卡|账单|支付|到账|扣款/i,
  otp: /验证码|校验码|动态码|one[\s-]?time|otp/i,
  identity: /身份证|护照|通行证|姓名|住址|户口|证件|出生日期/i,
  token: /token|密钥|secret|key|ak|sk|bearer/i,
}

function readSignals(masked, shape) {
  const text = String(masked)
  return {
    url: shape.addresses.length > 0,
    multiUrl: shape.addresses.length > 1,
    model: shape.models.length > 0,
    secret: shape.secrets.length > 0,
    pii: shape.pii.length > 0,
    provider: PATTERN.provider.test(text),
    login: PATTERN.login.test(text),
    db: PATTERN.db.test(text),
    bank: PATTERN.bank.test(text),
    otp: PATTERN.otp.test(text),
    identity: PATTERN.identity.test(text),
    tokenWord: PATTERN.token.test(text),
  }
}

/**
 * Which domains a blob touches. db / provider / login are mutually exclusive buckets (a DB
 * line mentions 密码 and 端口 too, so treating them as three domains produced false "mixed"),
 * while bank and identity can each coexist with one of them — that is what mixed means.
 */
export function domainsOf(signals) {
  const domains = []
  if (signals.bank) domains.push('bank')
  if (signals.identity) domains.push('identity')
  if (signals.db) domains.push('db')
  else if (signals.provider) domains.push('provider')
  else if (signals.login) domains.push('login')
  return domains
}

/** Ordered, conservative rules: strong combinations decide, everything else refuses. */
function decide(signals) {
  const s = signals
  const domains = domainsOf(s)
  // A blob spanning two domains must not be auto-treated as either one.
  if (domains.length >= 2) return { kind: 'mixed', confidence: 'medium', evidence: [`multi-domain:${domains.join('+')}`] }
  if (s.bank && (s.otp || s.pii)) return { kind: 'bank-sms', confidence: 'high', evidence: ['bank+otp/pii'] }
  if (s.identity && s.pii) return { kind: 'identity', confidence: 'high', evidence: ['identity+pii'] }
  if (s.db && (s.secret || s.login)) return { kind: 'db-credential', confidence: 'high', evidence: ['db+secret/login'] }
  if (s.provider && s.url && s.model && s.secret) return { kind: 'provider-config', confidence: 'high', evidence: ['provider+url+model+secret'] }
  if (s.login && (s.secret || s.url) && !s.bank) return { kind: 'server-login', confidence: 'medium', evidence: ['login+secret/url'] }
  if (s.secret && s.pii) return { kind: 'mixed', confidence: 'medium', evidence: ['secret+pii'] }
  if (s.tokenWord && s.secret && !s.url) return { kind: 'api-keys', confidence: 'medium', evidence: ['tokenword+secret'] }
  return { kind: 'unknown', confidence: 'high', evidence: ['no-strong-signal'] }
}

function gradeSensitivity(shape) {
  if (shape.secrets.length && shape.pii.length) return 'secret+pii'
  if (shape.secrets.length) return 'secret'
  if (shape.pii.length) return 'pii'
  return 'low'
}

/**
 * @param masked text with values replaced by fixed placeholders
 * @param shape  deterministic digest from summarize(describe(text))
 * @param fallback optional { classify(masked, shape): { kind, confidence } } for the semantic tier
 */
export function classify(masked, shape, fallback = null) {
  const signals = readSignals(masked, shape)
  let decision = decide(signals)
  let tier = decision.kind === 'unknown' ? 'rules' : 'rules'
  if (decision.kind === 'unknown' && fallback) {
    try {
      const guess = fallback(masked, shape)
      if (guess && guess.kind && guess.kind !== 'unknown' && guess.confidence >= 0.6) {
        decision = { kind: guess.kind, confidence: 'model', evidence: [`tfidf:${guess.confidence.toFixed(2)}`] }
        tier = 'model'
      }
    } catch { /* a broken fallback must never break classification */ }
  }
  return {
    kind: decision.kind,
    label: KIND_LABELS[decision.kind],
    sensitivity: gradeSensitivity(shape),
    confidence: decision.confidence,
    evidence: decision.evidence,
    advice: ADVICE[decision.kind],
    tier,
  }
}

/** One-line summary for the panel/status: "模型供应商配置 · 敏感:密钥 · 网址1 模型1 密钥1". */
export function kindLine(shape) {
  const parts = []
  if (shape.kind) parts.push(KIND_LABELS[shape.kind] ?? shape.kind)
  if (shape.sensitivity) parts.push(`敏感:${shape.sensitivity}`)
  return parts.join(' · ')
}

/** The semantic tier is optional: without the model file the cascade is rules-only. */
let semanticCache = null
function semanticFallback() {
  if (semanticCache === null) {
    try { semanticCache = makeFallback(loadModel(new URL('./model/tfidf-model.json', import.meta.url)), 0.6) ?? false }
    catch { semanticCache = false }
  }
  return semanticCache || null
}

/**
 * One call from raw text to persisted digest: field shape + masked classification.
 * The masked skeleton is returned for callers that want to log/debug, but must NOT be
 * persisted (see store.js) — keep the "skeleton is destroyed immediately" rule.
 */
export function analyze(text, options = {}) {
  const report = describe(text)
  const shape = summarize(report)
  const { masked, replaced } = mask(text, report)
  const decision = classify(masked, shape, options.fallback ?? semanticFallback())
  return { shape: { ...shape, ...decision, kindLabel: decision.label, replaced }, masked }
}
