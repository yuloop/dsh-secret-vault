/**
 * PII recognizers: pattern + structural validation + context words, Presidio-style.
 * A bare regex would flag every 18-digit order number, so each recognizer validates what it can:
 * mainland ID card by GB 11643 checksum and birth date, bank card by Luhn, mobile by prefix set.
 * Values never leave this module — callers get type, length, fingerprint and the evidence used.
 */
import { createHash } from 'node:crypto'

const fingerprint = text => createHash('sha256').update(text).digest('hex').slice(0, 10)

const PROVINCES = new Set(['11', '12', '13', '14', '15', '21', '22', '23', '31', '32', '33', '34', '35', '36', '37',
  '41', '42', '43', '44', '45', '46', '50', '51', '52', '53', '54', '61', '62', '63', '64', '65', '71', '81', '82', '91'])
const ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
const ID_CHECK = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2']
const MOBILE_PREFIX = /^1(?:3\d|4[5-9]|5[0-35-9]|6[2567]|7[0-8]|8\d|9[0-35-9])\d{8}$/

export function idCardValid(value) {
  if (!/^\d{17}[\dXx]$/.test(value)) return false
  if (!PROVINCES.has(value.slice(0, 2))) return false
  const year = Number(value.slice(6, 10)), month = Number(value.slice(10, 12)), day = Number(value.slice(12, 14))
  if (year < 1900 || year > new Date().getFullYear()) return false
  if (month < 1 || month > 12 || day < 1 || day > 31) return false
  const sum = [...value.slice(0, 17)].reduce((acc, ch, i) => acc + Number(ch) * ID_WEIGHTS[i], 0)
  return ID_CHECK[sum % 11] === value[17].toUpperCase()
}

export function luhnValid(value) {
  const digits = String(value).replace(/\D/g, '')
  if (digits.length < 12 || digits.length > 19) return false
  let sum = 0
  for (let i = 0; i < digits.length; i++) {
    let digit = Number(digits[digits.length - 1 - i])
    if (i % 2 === 1) { digit *= 2; if (digit > 9) digit -= 9 }
    sum += digit
  }
  return sum % 10 === 0
}

/** Card numbers also need a known issuer prefix: Luhn alone accepts one in ten numbers. */
export function cardBinValid(value) {
  const digits = String(value).replace(/\D/g, '')
  if (/^4/.test(digits)) return [13, 16, 19].includes(digits.length)
  if (/^5[1-5]/.test(digits) || /^2[2-7]/.test(digits)) return digits.length === 16
  if (/^3[47]/.test(digits)) return digits.length === 15
  if (/^35/.test(digits)) return digits.length === 16
  if (/^62/.test(digits)) return digits.length === 16 || digits.length === 19
  if (/^60|^65/.test(digits)) return digits.length >= 16
  return false
}

export function mobileValid(value) {
  const digits = String(value).replace(/[\s-]/g, '').replace(/^\+?86/, '')
  return MOBILE_PREFIX.test(digits)
}

const OTP_HINT = /(?:验证码|校验码|动态码|短信码|一次性密码|verification\s*code|one[\s-]?time\s*(?:code|password)|otp|2fa|code)/i
const NAME_LABEL = /(?:姓名|名字|收件人|联系人|开户人|持卡人|name)\s*[:：=]\s*([\u4e00-\u9fa5]{2,4}|[A-Za-z][A-Za-z.'-]*(?:\s+[A-Za-z][A-Za-z.'-]*){0,3})/g
const ADDRESS_LABEL = /(?:地址|住址|收货地址|address)\s*[:：=]\s*(.{4,80})/g
const OTHER_LABEL = /(?:护照|通行证|车牌|社保|医保|工号|学号|卡号|账号|账户|邮箱|email|e-mail)\s*[:：=]\s*([^\s,，;；]{3,40})/gi

const hits = (text, re, build) => {
  const out = []
  for (const m of text.matchAll(re)) out.push({ start: m.index, end: m.index + m[0].length, ...build(m) })
  return out
}

/** Ordered recognizers: each consumes its span so a later one cannot re-report digits inside it. */
export function recognizePii(text) {
  const raw = String(text)
  let work = raw
  const found = []
  const consume = (start, end) => {
    const width = end - start
    work = `${work.slice(0, start)}${' '.repeat(width)}${work.slice(end)}`
  }
  const add = (type, value, evidence, start, end) => {
    if (!value) return
    found.push({ type, length: value.length, fingerprint: fingerprint(value), evidence, start, end })
  }

  for (const m of hits(work, /(?<!\d)(\d{17}[\dXx])(?!\d)/g, m => ({ value: m[1] }))) {
    if (!idCardValid(m.value)) continue
    add('身份证号', m.value, 'GB11643 校验位通过', m.start, m.end); consume(m.start, m.end)
  }
  for (const m of hits(work, /(?<!\d)(\d[\d -]{10,21}\d)(?!\d)/g, m => ({ value: m[0] }))) {
    const digits = m.value.replace(/\D/g, '')
    if (!luhnValid(digits) || !cardBinValid(digits)) continue
    add('银行卡号', digits, 'Luhn+发卡行前缀通过', m.start, m.end); consume(m.start, m.end)
  }
  for (const m of hits(work, /(?<!\d)(?:\+?86[\s-]?)?(1[3-9]\d{9})(?!\d)/g, m => ({ value: m[1] }))) {
    if (!mobileValid(m.value)) continue
    add('手机号', m.value, '号段+长度通过', m.start, m.end); consume(m.start, m.end)
  }
  for (const m of hits(work, /(?<!\d)(\d{4,8})(?!\d)/g, m => ({ value: m[1] }))) {
    // Same clause only: "转出 5000 元。验证码：483920" must report 483920, not 5000.
    const before = (raw.slice(Math.max(0, m.start - 40), m.start).split(/[。；;\n]/).pop() ?? '')
    const after = (raw.slice(m.end, Math.min(raw.length, m.end + 16)).split(/[。；;\n]/)[0] ?? '')
    if (!OTP_HINT.test(before) && !OTP_HINT.test(after)) continue
    add('验证码', m.value, '同句邻近验证码类关键词', m.start, m.end); consume(m.start, m.end)
  }
  // A domain needs a letter-based TLD; "root@198.51.100.9" is a host, not an address.
  for (const m of hits(work, /[\w.+-]+@(?:[\w-]+\.)+[A-Za-z]{2,}/g, m => ({ value: m[0] }))) {
    add('邮箱', m.value, '邮箱格式', m.start, m.end); consume(m.start, m.end)
  }
  const labelled = [[NAME_LABEL, '姓名', '标签:姓名'], [ADDRESS_LABEL, '地址', '标签:地址'], [OTHER_LABEL, '证件/账号类', '标签:证件/账号']]
  for (const [re, type, evidence] of labelled) {
    for (const m of hits(work, re, m => ({ value: m[1] }))) {
      add(type, m.value.trim(), evidence, m.start, m.end); consume(m.start, m.end)
    }
  }
  return found
}
