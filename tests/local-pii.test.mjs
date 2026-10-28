/** PII recognizers: positives must be found, look-alikes must not, and nothing may be echoed. */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes, randomInt } from 'node:crypto'
import { recognizePii, idCardValid, luhnValid, cardBinValid, mobileValid } from '../pii-recognizers.js'

const PROVINCES = ['110101', '310104', '440305', '510107', '370202']
const ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
const ID_CHECK = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2']

/** Synthetic, checksum-valid ID card: random region, random birth date, random sequence. */
function fakeIdCard() {
  const region = PROVINCES[randomInt(PROVINCES.length)]
  const year = 1950 + randomInt(70)
  const month = String(1 + randomInt(12)).padStart(2, '0')
  const day = String(1 + randomInt(28)).padStart(2, '0')
  const body = `${region}${year}${month}${day}${String(randomInt(1000)).padStart(3, '0')}`.slice(0, 17)
  const sum = [...body].reduce((acc, ch, i) => acc + Number(ch) * ID_WEIGHTS[i], 0)
  return `${body}${ID_CHECK[sum % 11]}`
}

/** Synthetic, Luhn-valid 16-digit bank card. */
function fakeBankCard() {
  const body = `6222${Array.from({ length: 11 }, () => randomInt(10)).join('')}`
  for (let check = 0; check < 10; check++) { const candidate = body + check; if (luhnValid(candidate)) return candidate }
  throw new Error('unreachable')
}

/** Valid mainland prefixes only: picking a random second digit made the test flaky. */
const MOBILE_PREFIX = ['138', '131', '155', '186', '199', '147', '166', '170']
const fakeMobile = () => `${MOBILE_PREFIX[randomInt(MOBILE_PREFIX.length)]}${String(randomInt(1e8)).padStart(8, '0')}`

/** An ID whose check digit is provably wrong. */
function invalidIdCard() {
  for (;;) {
    const id = fakeIdCard()
    const bad = id.slice(0, 17) + (id[17] === '1' ? '2' : '1')
    if (!idCardValid(bad)) return bad
  }
}

/** 18 digits that deliberately fail Luhn, so the negative case is deterministic. */
function luhnInvalid18() {
  const base = `1234${Array.from({ length: 13 }, () => randomInt(10)).join('')}`
  for (let check = 0; check < 10; check++) if (!luhnValid(base + check)) return `${base}${check}`
  throw new Error('unreachable')
}

function positives() {
  const card = fakeBankCard(), id = fakeIdCard(), mobile = fakeMobile()
  const otp = String(100000 + randomInt(900000))
  return [
    { name: '身份证', text: `客户身份证 ${id} 请核对`, values: [id], type: '身份证号' },
    { name: '手机号', text: `联系电话：${mobile}`, values: [mobile], type: '手机号' },
    { name: '手机号+86', text: `+86 ${mobile} 来电`, values: [mobile], type: '手机号' },
    { name: '银行卡', text: `卡号 ${card} 转账`, values: [card], type: '银行卡号' },
    { name: '验证码', text: `【某银行】您的验证码是 ${otp}，5分钟内有效`, values: [otp], type: '验证码' },
    { name: '邮箱', text: '邮箱: someone@example.com', values: ['someone@example.com'], type: '邮箱' },
    { name: '姓名', text: '姓名：张三', values: ['张三'], type: '姓名' },
    { name: '地址', text: '收货地址：北京市海淀区中关村大街1号', values: ['北京市海淀区中关村大街1号'], type: '地址' },
    // 地址后紧跟另一个标签时，取值必须在下个标签前收手，不能把「手机：…」并进地址
    { name: '地址后跟手机号', text: '地址：北京市海淀区中关村大街1号 手机：13800138000', values: ['北京市海淀区中关村大街1号'], type: '地址' },
    { name: '护照', text: '护照：E12345678', values: ['E12345678'], type: '证件/账号类' },
  ]
}

function negatives() {
  // Mutating one digit can land on the correct check digit by chance (~1/11); retry until
  // the sample is genuinely invalid so the negative case is deterministic.
  const invalidId = invalidIdCard()
  return [
    { name: '18位订单号(Luhn 不通过)', text: `订单 ${luhnInvalid18()} 已发货` },
    { name: '无效身份证', text: `编号 ${invalidId}` },
    // 13 digits topped with "123": no issuer prefix, so the card recognizer must skip it even
    // when Luhn happens to accept the digits.
    { name: '13位非卡号', text: `流水号 123${Array.from({ length: 10 }, () => randomInt(10)).join('')}` },
    { name: '11位非手机(10开头)', text: '工单 10987654321 已受理' },
    { name: '日期时间', text: 'created 2026-10-25T15:13:05Z' },
    { name: '金额', text: '合计 12345 元' },
    { name: '无关键词的6位数字', text: '端口 808080 已占用' },
    { name: '手机号附近无关键词的短数字', text: '编号 1234 备注数量 5678' },
    // 拉丁关键词必须带词边界，否则 postcode/decode/hostname 里的 code、name 会被当成标签
    { name: 'postcode 里的 code', text: 'postcode: 100080' },
    { name: 'decode 里的 code', text: 'decode 4096 bytes' },
    { name: 'username 里的 name', text: 'username: 张三' },
    { name: 'hostname 里的 name', text: 'hostname: server01' },
  ]
}

test('positives: every synthetic PII value is recognized with the right type', () => {
  const missed = []
  for (const sample of positives()) {
    const found = recognizePii(sample.text)
    const ok = found.some(item => item.type === sample.type && item.length === sample.values[0].length)
    if (!ok) missed.push(`${sample.name}: ${JSON.stringify(found)}`)
  }
  assert.deepEqual(missed, [])
})

test('negatives: look-alike numbers are not reported', () => {
  const falsePositives = []
  for (const sample of negatives()) {
    const found = recognizePii(sample.text)
    if (found.length) falsePositives.push(`${sample.name}: ${found.map(i => i.type).join(',')}`)
  }
  assert.deepEqual(falsePositives, [])
})

test('no PII value is ever returned, only type/length/fingerprint/evidence', () => {
  const leaked = []
  for (const sample of positives()) {
    const blob = JSON.stringify(recognizePii(sample.text))
    for (const value of sample.values) if (blob.includes(value)) leaked.push(sample.name)
  }
  assert.deepEqual(leaked, [])
})

test('同一句里只报验证码，金额不能被连带报成验证码', () => {
  // 逗号/顿号也是子句边界：银行短信全靠它们分句。
  const found = recognizePii('验证码：123456，您正在支付 5000 元')
  assert.deepEqual(found.map(item => `${item.type}/${item.length}`), ['验证码/6'])
})

test('validators', () => {
  const id = fakeIdCard()
  assert.equal(idCardValid(id), true)
  assert.equal(idCardValid(`${id.slice(0, 17)}${id[17] === '1' ? '2' : '1'}`), false, 'bad checksum')
  assert.equal(idCardValid(`99${id.slice(2)}`), false, 'unknown province')
  assert.equal(luhnValid('4111111111111111'), true)
  assert.equal(luhnValid('4111111111111112'), false)
  assert.equal(cardBinValid('6222021234567890'), true)
  assert.equal(cardBinValid('110101201709221591'), false, 'an ID-shaped number is not a card')
  assert.equal(cardBinValid('4111111111111111'), true)
  assert.equal(mobileValid('13800138000'), true)
  assert.equal(mobileValid('+86 138 0013 8000'), true)
  assert.equal(mobileValid('12800138000'), false)
})
