/**
 * Shape extraction for messy private input.
 * Order of evidence: user labels first, structure second, token rules last.
 * Contract: a value classified as secret NEVER leaves this module — only its length and a
 * short fingerprint. Hosts and model ids are returned because they are identifiers, not secrets.
 */
import { createHash } from 'node:crypto'
import { recognizePii } from './pii-recognizers.js'

export const fingerprint = text => createHash('sha256').update(text).digest('hex').slice(0, 10)

/** Shannon entropy over characters, used to tell random tokens from words/paths. */
export function shannon(text) {
  if (!text) return 0
  const counts = new Map()
  for (const ch of text) counts.set(ch, (counts.get(ch) ?? 0) + 1)
  let entropy = 0
  for (const n of counts.values()) {
    const p = n / text.length
    entropy -= p * Math.log2(p)
  }
  return entropy
}

const HEX = /^[0-9a-fA-F]+$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/
const PATHISH = /^(?:~|\.{1,2})?\/[^\s]*$/
// Any scheme, not just http(s): "mysql://user:pass@host" carries a credential too.
const URL_TEXT = /[a-z][a-z0-9+.-]*:\/\/[^\s"'`,;)\]）】]+/gi
const TOKEN_TEXT = /[A-Za-z0-9][A-Za-z0-9_.=+/-]{7,}/g

/** Provider-shaped rules (a small gitleaks-style subset). Prefixes beat entropy as evidence. */
const RULES = [
  { id: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/ },
  { id: 'slack-token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { id: 'aws-access-key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: 'openai-style', re: /\bsk-[A-Za-z0-9_-]{16,}\b/ },
  { id: 'bearer-header', re: /\bBearer\s+([A-Za-z0-9._-]{16,})\b/, group: 1 },
  { id: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
]

const SECRET_LABEL = /^(?:密钥|秘钥|密码|口令|令牌|访问令牌|api[\s_-]?key|apikey|key|token|secret|password|passwd|pw|access[\s_-]?key)$/i
const ADDRESS_LABEL = /^(?:地址|服务地址|接口|接口地址|api\s*地址|base[\s_-]?url|endpoint|url|host|api)$/i
const MODEL_LABEL = /^(?:模型|模型名|model|model[\s_-]?id)$/i
// Word boundaries matter: "tokenrhythm" or "secret-vault" are product names, not hint words.
const SECRET_HINT = /(?:密钥|秘钥|密码|口令|令牌|(?<![A-Za-z])(?:token|secret|password|api[_-]?key|access[_-]?key|bearer)(?![A-Za-z]))/i
const PATHLIKE = /^[\w.@+-]+(?:\/[\w.@+-]+)+$/

export function roleOfLabel(label) {
  const clean = String(label).trim()
  if (SECRET_LABEL.test(clean)) return 'secret'
  if (ADDRESS_LABEL.test(clean)) return 'address'
  if (MODEL_LABEL.test(clean)) return 'model'
  return 'other'
}

export function hostOf(text) {
  try { const url = new URL(String(text).trim()); return `${url.protocol}//${url.host}` } catch { return null }
}

const randomish = token => token.length >= 20 &&
  (HEX.test(token) ? shannon(token) >= 3 : shannon(token) >= 3.5)

/** A base64 body of binary data (image, archive) is not a credential. */
function isBinaryBlob(token) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(token) || token.length < 32) return false
  const buf = Buffer.from(token, 'base64')
  if (!buf.length) return false
  const printable = [...buf].filter(byte => byte >= 32 && byte < 127).length
  return printable / buf.length < 0.7
}

/**
 * Random API keys (as opposed to hashes or blobs) are mixed case, contain digits and are
 * long. Measured on real material: the gateway key is 49 chars, entropy 4.91, upper+digit;
 * the false positive that started this work was 25 lowercase chars, entropy 3.86.
 */
const strongRandom = token => token.length >= 32 && /[A-Z]/.test(token) && /[a-z]/.test(token) &&
  /\d/.test(token) && !/[+/=]/.test(token) && shannon(token) >= 4.5 && !isBinaryBlob(token)

/** One token's verdict: provider rule > label role > keyword+entropy > unknown-long > plain. */
export function classifyToken(token, context = {}) {
  const text = String(token)
  for (const rule of RULES) {
    const hit = text.match(rule.re)
    if (hit) return { kind: 'secret', rule: rule.id }
  }
  if (context.role === 'secret') return { kind: 'secret', rule: 'label' }
  if (randomish(text) && SECRET_HINT.test(context.line ?? '')) return { kind: 'secret', rule: 'keyword+entropy' }
  if (strongRandom(text)) return { kind: 'secret', rule: 'entropy+charset' }
  if (randomish(text)) return { kind: 'unknown-long' }
  return { kind: 'plain' }
}

/** Safe-to-print description of a token's character set (never the characters themselves). */
export function charsetOf(text) {
  const value = String(text)
  if (HEX.test(value)) return '十六进制'
  if (/^[a-z0-9]+$/.test(value)) return '小写+数字'
  if (/^[a-z]+$/.test(value)) return '纯小写字母'
  if (isBinaryBlob(value)) return 'base64(二进制数据)'
  if (/[A-Z]/.test(value) && /[a-z]/.test(value) && /\d/.test(value)) return '大小写+数字'
  return '混合'
}

export function isIdentifier(text) {
  const value = String(text).trim()
  return UUID.test(value) || ISO_TIME.test(value) || PATHISH.test(value)
}

// Two anchor shapes: "label:" (any known label) and, for the words Chinese SMS/pastes use
// without a colon, "label " followed by whitespace ("电话 138…"). Without the second form the
// preceding label's value swallows the next field.
const LABEL_WORD = '密钥|秘钥|密码|口令|令牌|访问令牌|api[\\s_-]?key|apikey|access[\\s_-]?key|token|secret|password|passwd|pw|key|地址|服务地址|接口地址|接口|base[\\s_-]?url|endpoint|url|host|api|模型名|模型|model[\\s_-]?id|姓名|名字|收件人|联系人|开户人|持卡人|name|电话|手机|手机号|联系方式|验证码|校验码|动态码|护照|通行证|车牌|社保|医保|工号|学号|卡号|账号|账户|邮箱|email|e-mail'
const SPACE_LABEL = '电话|手机|手机号|联系方式|验证码|校验码|动态码|姓名|地址|邮箱|密钥|密码'
const LABEL_ALL = new RegExp(`(?:${LABEL_WORD})\\s*[:=：]\\s*|(?:${SPACE_LABEL})\\s+`, 'gi')

/**
 * All `label: value` pairs in one line. A pasted blob often crams several onto one line
 * ("地址: X 模型: Y 密钥: Z"), and taking only the first pair would mis-role the rest.
 */
export function parseLabels(line) {
  const text = String(line)
  const anchors = [...text.matchAll(LABEL_ALL)].map(m => ({
    label: m[0].replace(/[\s:=：]+$/, '').trim(), start: m.index, valueStart: m.index + m[0].length,
  }))
  return anchors.map((anchor, i) => {
    const end = i + 1 < anchors.length ? anchors[i + 1].start : text.length
    const value = text.slice(anchor.valueStart, end).trim().replace(/[，,;；。]+$/, '').trim()
    return { label: anchor.label, role: roleOfLabel(anchor.label), value, start: anchor.valueStart, end }
  }).filter(item => item.value)
}

/** First `label: value` pair of a line (kept for callers that only need one). */
export function parseLabelLine(line) {
  const match = String(line).match(/^\s*([^:=：]{1,24}?)\s*[:=：]\s*(.+?)\s*$/)
  if (!match) return null
  const label = match[1].trim()
  if (!label) return null
  const role = roleOfLabel(label)
  // A sentence that merely contains a URL also has a colon in it ("为 http://…"):
  // only accept a label when it is a known role, or a single plain word with no spaces.
  const plainWord = /^[A-Za-z0-9_.-]{1,24}$/.test(label) && !/^https?$/i.test(label)
  if (role === 'other' && !plainWord) return null
  return { label, role, value: match[2].trim() }
}

/** Is this token a bare or number-bearing identifier (model id), not random material? */
function looksModel(token) {
  return /^[a-z][a-z0-9.-]*$/.test(token) && /[.-]/.test(token) &&
    !/[0-9a-f]{16,}/i.test(token) && shannon(token) <= 4.2 && /[a-z]{2}/.test(token)
}

function collectLeafValues(value, prefix, out, depth = 0) {
  if (depth > 3 || out.length > 200) return
  if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) collectLeafValues(child, prefix ? `${prefix}.${key}` : key, out, depth + 1)
    return
  }
  out.push({ path: prefix, value: String(value ?? '') })
}

const view = item => ({ length: item.length, fingerprint: fingerprint(item.text), rule: item.rule })
const dedupe = items => [...new Map(items.map(item => [item.fingerprint, item])).values()]

function classifyJson(report, raw) {
  let parsed
  try { parsed = JSON.parse(raw) } catch { return }
  report.json = true
  const leaves = []
  collectLeafValues(parsed, '', leaves)
  report.jsonPaths = leaves.map(leaf => leaf.path)
  for (const leaf of leaves) {
    const key = leaf.path.split('.').pop() ?? ''
    if (roleOfLabel(key) !== 'secret' || !leaf.value) continue
    report.secrets.push({ text: leaf.value, length: leaf.value.length, rule: `json:${key}` })
  }
}

export function describe(text) {
  const raw = String(text)
  const lines = raw.split('\n')
  const lineStarts = [0]
  for (let i = 0; i < raw.length; i++) if (raw[i] === '\n') lineStarts.push(i + 1)
  const report = {
    bytes: Buffer.byteLength(raw), lines: lines.length, blank: lines.filter(line => !line.trim()).length,
    addresses: [], models: [], secrets: [], unknownLong: [], pii: [], labels: [], jsonPaths: [], json: false,
    spans: [],
  }
  const contexts = new Map()
  for (let li = 0; li < lines.length; li++) {
    const line = lines[li]
    const base = lineStarts[li] ?? 0
    const labelled = parseLabels(line)
    for (const item of labelled) {
      report.labels.push({ label: item.label, role: item.role, length: item.value.length })
      // The label names the value's role directly, so use the value as the evidence.
      if (item.role === 'secret') {
        report.secrets.push({ text: item.value, length: item.value.length, rule: `label:${item.label}` })
        report.spans.push({ start: base + item.start, end: base + item.start + item.value.length, type: 'secret' })
      }
      if (item.role === 'address') { const host = hostOf(item.value); if (host) report.addresses.push(host) }
      if (item.role === 'model') report.models.push(item.value.trim())
    }
    for (const m of line.matchAll(URL_TEXT)) {
      const host = hostOf(m[0])
      if (host) report.addresses.push(host)
      report.spans.push({ start: base + m.index, end: base + m.index + m[0].length, type: 'url' })
      // "mysql://user:pass@host" carries a credential in the URL itself.
      try {
        const parsed = new URL(m[0])
        if (parsed.username || parsed.password) {
          const credential = `${parsed.username}${parsed.password ? `:${parsed.password}` : ''}`
          report.secrets.push({ text: credential, length: credential.length, rule: 'url-userinfo' })
        }
      } catch { /* not a parseable URL */ }
    }
    // Provider rules scan the whole line: "Bearer <token>" and "token=<value>" shapes only
    // make sense in context, so a bare-token classifier would miss them.
    for (const rule of RULES) {
      const hit = line.match(rule.re)
      if (!hit) continue
      const value = hit[rule.group ?? 0]
      report.secrets.push({ text: value, length: value.length, rule: rule.id })
      const rel = hit[0].indexOf(value)
      if (rel >= 0) report.spans.push({ start: base + hit.index + rel, end: base + hit.index + rel + value.length, type: 'secret' })
    }
    for (const m of line.matchAll(TOKEN_TEXT)) {
      const owner = labelled.find(seg => m.index >= seg.start && m.index < seg.end)
      if (!contexts.has(m[0])) contexts.set(m[0], { role: owner?.role, line, at: base + m.index })
    }
  }
  for (const [token, context] of contexts) {
    if (hostOf(token) || token.includes('://') || PATHLIKE.test(token)) continue
    if (report.addresses.some(host => host.includes(token))) continue
    if (isIdentifier(token)) continue
    if (looksModel(token)) { report.models.push(token); continue }
    const verdict = classifyToken(token, context)
    if (verdict.kind === 'secret') {
      report.secrets.push({ text: token, length: token.length, rule: verdict.rule })
      const at = contexts.get(token)?.at
      if (Number.isFinite(at)) report.spans.push({ start: at, end: at + token.length, type: 'secret' })
    }
    else if (verdict.kind === 'unknown-long') report.unknownLong.push({ text: token, length: token.length, rule: `entropy-only:${charsetOf(token)}` })
  }
  report.pii = recognizePii(raw)
  for (const item of report.pii) {
    if (Number.isFinite(item.start) && Number.isFinite(item.end)) {
      report.spans.push({ start: item.start, end: item.end, type: 'pii' })
    }
  }
  classifyJson(report, raw)
  report.addresses = [...new Set(report.addresses)]
  report.models = [...new Set(report.models)]
  report.secrets = dedupe(report.secrets.map(item => ({ ...item, fingerprint: fingerprint(item.text) }))).map(view)
  report.unknownLong = dedupe(report.unknownLong.map(item => ({ ...item, fingerprint: fingerprint(item.text) }))).map(view)
  return report
}

/** Compact, value-free digest of a report — this is what gets persisted and shown. */
export function summarize(report) {
  return {
    addresses: report.addresses,
    models: report.models,
    secrets: report.secrets,
    pii: report.pii,
    labels: report.labels.map(item => `${item.label}:${item.role}`),
    json: report.json,
  }
}

/** One human/agent-readable line: "地址2 · 模型1 · 密钥1 · 手机号1 · 身份证1". */
export function shapeLine(shape) {
  const parts = []
  if (shape.kindLabel) parts.push(shape.kindLabel)
  if (shape.sensitivity) parts.push(`敏感:${shape.sensitivity}`)
  if (shape.addresses.length) parts.push(`网址${shape.addresses.length}`)
  if (shape.models.length) parts.push(`模型${shape.models.length}`)
  if (shape.secrets.length) parts.push(`密钥${shape.secrets.length}`)
  const counts = new Map()
  for (const item of shape.pii) counts.set(item.type, (counts.get(item.type) ?? 0) + 1)
  for (const [type, n] of counts) parts.push(`${type}${n}`)
  return parts.join(' · ') || '未识别到结构化字段'
}

/** Fixed-length placeholders: a length-coded token like [[SECRET_49]] would leak the size. */
const PLACEHOLDER = { secret: '[[SECRET]]', pii: '[[PII]]', url: '[[URL]]' }

/** Replace every detected value with a fixed placeholder, so a classifier sees only skeleton. */
export function mask(text, report) {
  const spans = [...(report?.spans ?? [])].sort((a, b) => a.start - b.start || b.end - a.end)
  let out = ''
  let cursor = 0
  let replaced = 0
  for (const span of spans) {
    if (span.start < cursor || span.end <= span.start) continue // overlapping span already covered
    out += String(text).slice(cursor, span.start)
    out += PLACEHOLDER[span.type] ?? '[[MASKED]]'
    cursor = span.end
    replaced++
  }
  out += String(text).slice(cursor)
  return { masked: out, replaced }
}
