/**
 * Outbound credential redaction for the tool egress path.
 * Contract: a detected credential never leaves this module — only its first four characters and a
 * short sha256 fingerprint survive, so a masked log stays correlatable but not usable.
 * Any internal failure returns the input untouched: this runs on the tool exit, where a throw
 * would destroy the session. Work is one linear pass over whitespace-delimited tokens, so a
 * pathological 1 MB line cannot stall the egress path.
 */
import { createHash } from 'node:crypto'
import { shannon } from './field-shape.js'

const MARK = '【已打码 '
const MARKER = '【已打码'
const ELLIPSIS = '…'
const WORD = /\S+/g
const sha8 = text => createHash('sha256').update(text).digest('hex').slice(0, 8)

/** Longest prefix first: github_pat_ must win before anything shorter can claim the position. */
const VENDOR_PREFIXES = ['github_pat_', 'sk-', 'sk_', 'AKIA', 'ASIA', 'ghp_', 'gho_', 'ghs_',
  'xoxa-', 'xoxb-', 'xoxp-', 'xoxr-', 'xoxs-', 'AIza']
const KEY_CHAR = /[A-Za-z0-9_-]/
const RUN = /[A-Za-z0-9_-]{32,}/g
const BEARER_TOKEN = /[A-Za-z0-9._~+/=-]{16,}/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const TMP_REF = /^tmp-[a-f0-9]{32}$/

const overlaps = (a, b) => a.start < b.end && b.start < a.end
const runEnd = (text, from) => {
  let end = from
  while (end < text.length && KEY_CHAR.test(text[end])) end++
  return end
}

/** High entropy means random, not prose: mixed case plus a digit plus >= 4.0 bits per character. */
const randomish = token => /[A-Z]/.test(token) && /[a-z]/.test(token) && /\d/.test(token) &&
  shannon(token) >= 4.0

/** URLs, paths, our own tmp refs, UUIDs and already-masked text are shape, not secrets: no generic
 * pass and no weak-evidence prefix hit inside them, which also keeps masking idempotent. */
const isProtected = token => token.includes('://') || /[/\\]/.test(token) ||
  TMP_REF.test(token) || UUID.test(token) || token.includes(MARKER)

function vendorSpans(token) {
  const spans = []
  for (let at = 0; at < token.length;) {
    const prefix = VENDOR_PREFIXES.find(item => token.startsWith(item, at))
    // A leading word character means the prefix is the tail of a longer word ("task-", "risk-").
    if (!prefix || (at > 0 && KEY_CHAR.test(token[at - 1]))) { at++; continue }
    const end = runEnd(token, at + prefix.length)
    if (end - at - prefix.length >= 16) { spans.push({ start: at, end }); at = end; continue }
    at++
  }
  return spans
}

/** eyJ<seg>.eyJ<seg>.<seg>, scanned by hand so no regex can backtrack over a long token. */
function jwtSpans(token) {
  const spans = []
  for (let at = token.indexOf('eyJ'); at !== -1; at = token.indexOf('eyJ', at + 3)) {
    if (at > 0 && KEY_CHAR.test(token[at - 1])) continue
    const first = runEnd(token, at + 3)
    if (token[first] !== '.' || !token.startsWith('eyJ', first + 1)) continue
    const second = runEnd(token, first + 4)
    const third = token[second] === '.' ? runEnd(token, second + 1) : second
    if (third > second + 1) spans.push({ start: at, end: third })
  }
  return spans
}

/** A provider prefix inside a URL or path is usually a slug ("/sk-documentation"), so there the
 * evidence must be stronger: a digit inside the value, or an assignment position ("?key="). */
const strong = (token, span) => token[span.start - 1] === '=' ||
  /\d/.test(token.slice(span.start, span.end))

function specificSpans(token) {
  const spans = [...vendorSpans(token), ...jwtSpans(token)]
  return isProtected(token) ? spans.filter(span => strong(token, span)) : spans
}

function genericSpans(token, taken) {
  return [...token.matchAll(RUN)]
    .map(match => ({ text: match[0], start: match.index, end: match.index + match[0].length }))
    .filter(span => randomish(span.text) && !taken.some(other => overlaps(span, other)))
}

function tokenSpans(token, base) {
  const own = specificSpans(token)
  const generic = isProtected(token) ? [] : genericSpans(token, own)
  return [...own, ...generic].map(span => ({ start: span.start + base, end: span.end + base }))
}

/** Only the token after the word "Bearer" is masked; the word itself stays. */
function bearerSpan(token, base) {
  const match = BEARER_TOKEN.exec(token)
  return match ? { start: match.index + base, end: match.index + match[0].length + base } : null
}

/** Every byte of the token except the first four characters becomes the fingerprint placeholder. */
function render(text, spans) {
  let out = '', cursor = 0
  for (const span of spans) {
    const token = text.slice(span.start, span.end)
    out += text.slice(cursor, span.start) + token.slice(0, 4) + ELLIPSIS + MARK + sha8(token) + '】'
    cursor = span.end
  }
  return out + text.slice(cursor)
}

/** Tokens are the unit of work: a credential never spans whitespace, and markers are skipped. */
function plan(text) {
  const spans = []
  let bearerNext = false
  for (const match of text.matchAll(WORD)) {
    const [token] = match
    if (bearerNext) {
      bearerNext = false
      const span = bearerSpan(token, match.index)
      if (span) spans.push(span)
      continue
    }
    if (token === 'Bearer') bearerNext = true
    else spans.push(...tokenSpans(token, match.index))
  }
  return spans
}

export function redact(text) {
  try {
    if (typeof text !== 'string' || !text) return text
    const spans = plan(text)
    return spans.length ? render(text, spans) : text
  } catch {
    return text
  }
}

/** Only text blocks are touched; images, json and unknown blocks pass through unchanged. */
export function redactBlocks(content) {
  try {
    if (!Array.isArray(content)) return content
    return content.map(block => {
      if (!block || block.type !== 'text' || typeof block.text !== 'string') return block
      const text = redact(block.text)
      return text === block.text ? block : { ...block, text }
    })
  } catch {
    return content
  }
}
