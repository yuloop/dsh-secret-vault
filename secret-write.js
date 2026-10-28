/**
 * Pure functions that write one vault secret into a target configuration file.
 * The secret appears only inside the returned file text; every thrown error carries the fixed
 * PRIVATE_OPERATION_FAILED message, so a caller may log a failure without leaking the value.
 * Only the matched value bytes are touched — the rest of the file stays byte-identical.
 */
import { describe } from './field-shape.js'
import { fail } from './local-files.js'

const MAX_KEY_PATH = 128
const CONTROL = /[\n\r\0]/
const PROTO_SEGMENTS = new Set(['__proto__', 'constructor', 'prototype'])
const ENV_EXTENSIONS = new Set(['', '.env', '.ini', '.cfg', '.conf', '.properties'])
const CODE_EXTENSIONS = new Set(['.php', '.js', '.mjs', '.cjs', '.ts'])
const QUOTES = new Set(['"', "'"])

const escapeRegex = text => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
/** Whole-word key match: KEY must not hit MY_KEY, KEY_OLD or KEY2. */
const boundary = key => `(?<![A-Za-z0-9_])${escapeRegex(key)}(?![A-Za-z0-9_])`

/** Vault raw text in, the exact value to write out. An ambiguous mode fails instead of guessing. */
export function selectSecret(rawText, mode = 'whole') {
  if (typeof rawText !== 'string') fail()
  if (mode === 'whole') {
    const value = rawText.trim()
    if (!value) fail()
    return value
  }
  if (mode !== 'first-secret') fail()
  // describe() emits overlapping candidates for one value: a label rule can swallow the prose
  // after the key ("密钥 xxx 后面还有字"). The tightest span is the value; the wider ones are
  // supersets that would paste prose into the target file.
  const spans = describe(rawText).spans.filter(item => item.type === 'secret')
  if (!spans.length) fail()
  const tightest = spans.reduce((best, item) => item.end - item.start < best.end - best.start ? item : best)
  const value = rawText.slice(tightest.start, tightest.end)
  if (!value.trim()) fail()
  return value
}

/** ".env" style dotfiles are their own extension; no dot at all means the env family. */
function extensionOf(target) {
  const base = String(target).split(/[\\/]/).pop() ?? ''
  const dot = base.lastIndexOf('.')
  if (dot === -1) return ''
  if (dot === 0) return base.toLowerCase()
  return base.slice(dot).toLowerCase()
}

function keyPathSegments(keyPath, json) {
  if (typeof keyPath !== 'string' || !keyPath) fail()
  if (keyPath.length > MAX_KEY_PATH) fail()
  if (CONTROL.test(keyPath)) fail()
  if (keyPath !== keyPath.trim()) fail()
  if (keyPath.startsWith('.') || keyPath.endsWith('.')) fail()
  if (!json) return [keyPath]
  const segments = keyPath.split('.')
  if (segments.some(segment => !segment || PROTO_SEGMENTS.has(segment))) fail()
  return segments
}

const quoteDouble = value => `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
const quoteSingle = value => `'${value.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`

/**
 * Line-oriented formats hold one value per line, and neither env nor a JS single-quoted string
 * can carry a raw line break: writing one would produce a file that no parser accepts. Refuse
 * instead of corrupting the target. JSON handles breaks itself, so it skips this check.
 */
const lineSafe = secret => { if (CONTROL.test(secret)) fail(); return secret }

/** Decode a quoted literal back to its raw value so "already this value" is byte-independent. */
function decodeLiteral(raw) {
  const text = String(raw).trim()
  if (text.length >= 2 && QUOTES.has(text[0]) && text[text.length - 1] === text[0]) {
    return text.slice(1, -1).replace(/\\(.)/gs, '$1')
  }
  return text
}

/** Index just past the quoted literal starting at `at`, or -1 when it is not a quoted literal. */
function literalEnd(text, at) {
  const quote = text[at]
  if (!QUOTES.has(quote)) return -1
  for (let i = at + 1; i < text.length; i++) {
    if (text[i] === '\\') { i++; continue }
    if (text[i] === quote) return i + 1
  }
  return -1
}

/** Rewrite one value literal in place; returns null when the byte at `at` is not a literal. */
function replaceLiteral(text, at, literal) {
  const end = literalEnd(text, at)
  if (end === -1) return null
  if (decodeLiteral(text.slice(at, end)) === decodeLiteral(literal)) return { text, changed: false }
  return { text: text.slice(0, at) + literal + text.slice(end), changed: true }
}

/** Split on LF only and keep every EOL verbatim so untouched lines round-trip exactly. */
function splitLines(text) {
  const lines = []
  let at = 0
  while (at < text.length) {
    const nl = text.indexOf('\n', at)
    const stop = nl === -1 ? text.length : nl
    let content = text.slice(at, stop)
    let eol = nl === -1 ? '' : '\n'
    if (eol && content.endsWith('\r')) { content = content.slice(0, -1); eol = '\r\n' }
    lines.push({ content, eol })
    at = stop + 1
  }
  return lines
}

/** A '#' starts a trailing comment only when unquoted and at a word start, so URLs survive. */
function splitComment(rest) {
  let quote = null
  for (let i = 0; i < rest.length; i++) {
    const ch = rest[i]
    if (quote) {
      if (ch === '\\' && quote === '"') { i++; continue }
      if (ch === quote) quote = null
      continue
    }
    if (QUOTES.has(ch)) { quote = ch; continue }
    if (ch === '#' && (i === 0 || /\s/.test(rest[i - 1]))) {
      return { value: rest.slice(0, i), comment: rest.slice(i) }
    }
  }
  return { value: rest, comment: '' }
}

const LINE_PATTERNS = {
  env: key => new RegExp(`^(\\s*(?:export\\s+)?)(${boundary(key)})(\\s*=\\s*)`),
  yaml: key => new RegExp(`^(\\s*(?:-\\s+)?)(${boundary(key)})(\\s*:\\s*)`),
  toml: key => new RegExp(`^(\\s*)(${boundary(key)})(\\s*=\\s*)`),
}

/** KEY=VALUE style files (env/ini/yaml/toml): replace the matched line, or append a new one. */
function applyLine(text, keyPath, secret, kind) {
  const key = keyPathSegments(keyPath, false)[0]
  lineSafe(secret)
  const pattern = LINE_PATTERNS[kind](key)
  const line = kind === 'env' ? `${key}=${quoteDouble(secret)}` : kind === 'yaml'
    ? `${key}: ${quoteDouble(secret)}` : `${key} = ${quoteDouble(secret)}`
  const lines = splitLines(text)
  const at = lines.findIndex(item => pattern.test(item.content))
  if (at === -1) return appendLine(text, line)
  const match = pattern.exec(lines[at].content)
  const rest = lines[at].content.slice(match[0].length)
  const { value, comment } = splitComment(rest)
  if (decodeLiteral(value) === secret) return { text, changed: false }
  const gap = value.slice(value.trimEnd().length) || (comment ? ' ' : '')
  const rebuilt = match[0] + quoteDouble(secret) + gap + comment
  if (rebuilt === lines[at].content) return { text, changed: false }
  const next = lines.map((item, i) => (i === at ? rebuilt + item.eol : item.content + item.eol)).join('')
  return { text: next, changed: true }
}

/** Append a missing key on its own line, reusing the file's EOL style and its trailing-newline habit. */
function appendLine(text, line) {
  const eol = text.includes('\r\n') ? '\r\n' : '\n'
  if (!text) return { text: line + eol, changed: true }
  const closed = text.endsWith('\n')
  const head = closed ? text : text + eol
  return { text: head + line + (closed ? eol : ''), changed: true }
}

/** Walk to the parent object of the last segment, creating missing intermediate objects. */
function jsonParent(root, segments) {
  let cursor = root
  for (const segment of segments.slice(0, -1)) {
    if (cursor[segment] === undefined) cursor[segment] = {}
    const next = cursor[segment]
    if (!next || typeof next !== 'object' || Array.isArray(next)) fail()
    cursor = next
  }
  return cursor
}

function applyJson(text, keyPath, secret) {
  const segments = keyPathSegments(keyPath, true)
  let root
  try { root = JSON.parse(text) } catch { fail() }
  if (!root || typeof root !== 'object' || Array.isArray(root)) fail()
  const parent = jsonParent(root, segments)
  const leaf = segments[segments.length - 1]
  if (parent[leaf] === secret) return { text, changed: false }
  if (parent[leaf] && typeof parent[leaf] === 'object') fail()
  parent[leaf] = secret
  const tail = text.match(/(\r?\n)$/)?.[1] ?? ''
  return { text: JSON.stringify(root, null, 2) + tail, changed: true }
}

function replaceDefine(text, key, literal) {
  const pattern = new RegExp(`(define\\(\\s*(['"])${boundary(key)}\\2\\s*,\\s*)`)
  const match = pattern.exec(text)
  if (!match) return null
  return replaceLiteral(text, match.index + match[1].length, literal)
}

function replacePair(text, key, literal) {
  for (const glue of ['=>', ':']) {
    const pattern = new RegExp(`((['"]?)${boundary(key)}\\2\\s*${glue}\\s*)`)
    const match = pattern.exec(text)
    if (!match) continue
    // 'KEY' => getValue() has no literal to replace; keep looking rather than guess.
    const outcome = replaceLiteral(text, match.index + match[1].length, literal)
    if (outcome) return outcome
  }
  return null
}

/** PHP/JS sources: define('KEY', …) first, then 'KEY' => … / KEY: … assignments. */
function applyCode(text, keyPath, secret) {
  const key = keyPathSegments(keyPath, false)[0]
  lineSafe(secret)
  const literal = quoteSingle(secret)
  const outcome = replaceDefine(text, key, literal) ?? replacePair(text, key, literal)
  if (!outcome) fail()
  return outcome
}

/**
 * Pure: write `secret` at `keyPath` inside `text`. Returns { text, changed }; changed=false means
 * the file already holds this value and `text` is returned untouched.
 */
export function applySecret(input = {}) {
  const { text, target, keyPath, secret } = input
  if (typeof text !== 'string' || typeof target !== 'string' || !target) fail()
  if (typeof secret !== 'string' || !secret) fail()
  const extension = extensionOf(target)
  if (extension === '.json') return applyJson(text, keyPath, secret)
  if (ENV_EXTENSIONS.has(extension)) return applyLine(text, keyPath, secret, 'env')
  if (extension === '.yml' || extension === '.yaml') return applyLine(text, keyPath, secret, 'yaml')
  if (extension === '.toml') return applyLine(text, keyPath, secret, 'toml')
  if (CODE_EXTENSIONS.has(extension)) return applyCode(text, keyPath, secret)
  fail()
}

/** Initial content for a file that does not exist yet: only this one key. */
export function seedText(input = {}) {
  const { target, keyPath, secret } = input
  if (typeof target !== 'string' || !target) fail()
  if (typeof secret !== 'string' || !secret) fail()
  const extension = extensionOf(target)
  if (extension === '.json') {
    const segments = keyPathSegments(keyPath, true)
    const root = {}
    let cursor = root
    for (const segment of segments.slice(0, -1)) { cursor[segment] = {}; cursor = cursor[segment] }
    cursor[segments[segments.length - 1]] = secret
    return `${JSON.stringify(root, null, 2)}\n`
  }
  const key = keyPathSegments(keyPath, false)[0]
  lineSafe(secret)
  if (CODE_EXTENSIONS.has(extension)) return `define('${key}', ${quoteSingle(secret)});\n`
  if (ENV_EXTENSIONS.has(extension)) return `${key}=${quoteDouble(secret)}\n`
  if (extension === '.yml' || extension === '.yaml') return `${key}: ${quoteDouble(secret)}\n`
  if (extension === '.toml') return `${key} = ${quoteDouble(secret)}\n`
  fail()
}
