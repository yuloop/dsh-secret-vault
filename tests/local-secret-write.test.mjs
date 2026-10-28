/** Secret writing: in-place edits keep the file intact, and no failure may ever echo the value. */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { describe } from '../field-shape.js'
import { selectSecret, applySecret, seedText } from '../secret-write.js'

/** Shaped like a real gateway key, so field-shape classifies it as a secret span. */
const SECRET = `sk-proj${'AbCdEf0123456789ghIJKLMN'}`
const OLD = 'old-value-from-previous-rotation'
const FAILED = /PRIVATE_OPERATION_FAILED/

/** Every failure mode funnels through this helper: it asserts the throw AND that it stays quiet. */
function expectFail(run, secret = SECRET) {
  assert.throws(run, FAILED)
  let message = ''
  try { run() } catch (error) { message = String(error.message) }
  assert.equal(message.includes(secret), false, 'the error message must never carry the secret')
}

test('selectSecret: whole trims surrounding whitespace', () => {
  assert.equal(selectSecret(`  ${SECRET}\n\t`), SECRET)
  assert.equal(selectSecret(`\n ${SECRET} \n`, 'whole'), SECRET)
  expectFail(() => selectSecret('   \n\t ', 'whole'))
})

test('selectSecret: first-secret pulls the key out of mixed prose', () => {
  const prose = `这是一份旧备份，别外传。\n密钥：${SECRET}\n其余内容先不动。`
  assert.equal(selectSecret(prose, 'first-secret'), SECRET)
  // The span really is inside the prose, not the whole line: the wrapper words are gone.
  assert.equal(selectSecret(prose, 'first-secret').includes('其余'), false)
  assert.ok(describe(prose).spans.some(span => span.type === 'secret'))
})

test('selectSecret: no secret span fails instead of degrading to whole', () => {
  expectFail(() => selectSecret('just some ordinary words here', 'first-secret'))
  expectFail(() => selectSecret('', 'first-secret'))
})

test('selectSecret: an unknown mode fails', () => {
  expectFail(() => selectSecret(SECRET, 'first'))
  expectFail(() => selectSecret(SECRET, 'spans'))
  expectFail(() => selectSecret(SECRET, ''))
})

test('.env: replaces an existing line and keeps the trailing comment', () => {
  const text = '# gateway\nAPI_KEY=old  # rotate quarterly\nOTHER=1\n'
  const { text: out, changed } = applySecret({ text, target: '.env', keyPath: 'API_KEY', secret: SECRET })
  assert.equal(changed, true)
  assert.equal(out, `# gateway\nAPI_KEY="${SECRET}"  # rotate quarterly\nOTHER=1\n`)
  assert.ok(out.includes('OTHER=1'), 'unrelated lines untouched')
})

test('.env: appends a missing key at the end', () => {
  const { text, changed } = applySecret({ text: 'A=1\n', target: '.env', keyPath: 'API_KEY', secret: SECRET })
  assert.equal(changed, true)
  assert.equal(text, `A=1\nAPI_KEY="${SECRET}"\n`)
  // A file without a trailing newline gets one added, but no extra blank line.
  const bare = applySecret({ text: 'A=1', target: 'config', keyPath: 'API_KEY', secret: SECRET })
  assert.equal(bare.text, `A=1\nAPI_KEY="${SECRET}"`)
})

test('.env: KEY never matches MY_KEY, KEY_OLD or KEY2', () => {
  const text = 'MY_KEY=keep\nKEY_OLD=keep\nKEY2=keep\n'
  const { text: out } = applySecret({ text, target: '.env', keyPath: 'KEY', secret: SECRET })
  assert.ok(out.startsWith('MY_KEY=keep\nKEY_OLD=keep\nKEY2=keep\n'), 'look-alike keys stay as they were')
  assert.ok(out.includes(`\nKEY="${SECRET}"`), 'the append targets the real KEY')
  assert.equal(out.includes('MY_KEY="'), false)
})

test('.env: keeps export prefix, quoting and CRLF line endings', () => {
  const text = 'export API_KEY=old\r\nOTHER=1\r\n'
  const { text: out } = applySecret({ text, target: '.env', keyPath: 'API_KEY', secret: SECRET })
  assert.equal(out, `export API_KEY="${SECRET}"\r\nOTHER=1\r\n`)
})

test('.json: writes a nested keyPath and keeps every other key', () => {
  const text = '{\n  "a": {\n    "b": {\n      "keep": 1\n    }\n  },\n  "z": true\n}\n'
  const { text: out, changed } = applySecret({ text, target: 'conf.json', keyPath: 'a.b.c', secret: SECRET })
  assert.equal(changed, true)
  const parsed = JSON.parse(out)
  assert.equal(parsed.a.b.c, SECRET)
  assert.equal(parsed.a.b.keep, 1)
  assert.equal(parsed.z, true)
  assert.equal(out, `${JSON.stringify(parsed, null, 2)}\n`, 'two-space indent, trailing newline kept')
})

test('.json: the trailing newline survives only if the original had one', () => {
  const withNewline = applySecret({ text: '{\n  "a": 1\n}\n', target: 'c.json', keyPath: 'a', secret: SECRET })
  assert.ok(withNewline.text.endsWith('}\n'))
  const without = applySecret({ text: '{"a":1}', target: 'c.json', keyPath: 'a', secret: SECRET })
  assert.equal(without.text.endsWith('\n'), false)
  assert.equal(without.text, `{\n  "a": "${SECRET}"\n}`)
})

test('.php: define() replacement makes the old value disappear', () => {
  const text = "<?php\ndefine('API_KEY', 'old');\n"
  const { text: out, changed } = applySecret({ text, target: 'config.php', keyPath: 'API_KEY', secret: SECRET })
  assert.equal(changed, true)
  assert.equal(out.includes('old'), false, 'the previous value is gone')
  assert.ok(out.includes(SECRET))
  assert.equal(out, `<?php\ndefine('API_KEY', '${SECRET}');\n`)
})

test('.php: array arrow form is replaced too, and look-alike keys are skipped', () => {
  const text = "<?php\n$c = [\n  'OTHER' => 'x',\n  'API_KEY' => 'old',\n];\n"
  const { text: out } = applySecret({ text, target: 'config.php', keyPath: 'API_KEY', secret: SECRET })
  assert.equal(out.includes("'old'"), false)
  assert.ok(out.includes(`'API_KEY' => '${SECRET}'`))
  assert.ok(out.includes(`'OTHER' => 'x'`))
})

test('.php: a secret with a quote and a backslash is escaped, not dropped', () => {
  const secret = `it's a \\ backslash and "quote"`
  const { text: out } = applySecret({ text: "<?php\ndefine('API_KEY', 'old');\n", target: 'c.php', keyPath: 'API_KEY', secret })
  assert.ok(out.includes("'it\\'s a \\\\ backslash and \"quote\"'"), 'single quotes and backslashes escaped')
  assert.equal(out.includes("define('API_KEY', 'old')"), false)
})

test('.js: object property form is replaced with a single-quoted literal', () => {
  const { text: out } = applySecret({ text: 'const c = {\n  API_KEY: "old",\n}\n', target: 'conf.mjs', keyPath: 'API_KEY', secret: SECRET })
  assert.equal(out, `const c = {\n  API_KEY: '${SECRET}',\n}\n`)
})

test('.js: a property without a literal fails instead of guessing', () => {
  expectFail(() => applySecret({ text: 'const c = { API_KEY: process.env.X }', target: 'c.ts', keyPath: 'API_KEY', secret: SECRET }))
  expectFail(() => applySecret({ text: 'const c = { OTHER: 1 }', target: 'c.js', keyPath: 'API_KEY', secret: SECRET }))
})

test('.yml and .toml: the matching line is rewritten and neighbours are kept', () => {
  const yml = applySecret({ text: '# note\nAPI_KEY: old\nother: 1\n', target: 'c.yml', keyPath: 'API_KEY', secret: SECRET })
  assert.equal(yml.text, `# note\nAPI_KEY: "${SECRET}"\nother: 1\n`)
  const yaml = applySecret({ text: 'API_KEY: old\n', target: 'c.yaml', keyPath: 'API_KEY', secret: SECRET })
  assert.ok(yaml.text.includes(`API_KEY: "${SECRET}"`))
  const toml = applySecret({ text: '[svc]\nAPI_KEY = "old"\nother = 1\n', target: 'c.toml', keyPath: 'API_KEY', secret: SECRET })
  assert.equal(toml.text, `[svc]\nAPI_KEY = "${SECRET}"\nother = 1\n`)
})

test('seedText: .json nests the keyPath and ends with a newline', () => {
  const text = seedText({ target: 'conf.json', keyPath: 'a.b.c', secret: SECRET })
  assert.equal(text, `${JSON.stringify({ a: { b: { c: SECRET } } }, null, 2)}\n`)
  assert.deepEqual(JSON.parse(text), { a: { b: { c: SECRET } } })
})

test('seedText: .env emits a single quoted KEY=VALUE line', () => {
  assert.equal(seedText({ target: '.env', keyPath: 'API_KEY', secret: SECRET }), `API_KEY="${SECRET}"\n`)
  assert.equal(seedText({ target: 'app.ini', keyPath: 'API_KEY', secret: SECRET }), `API_KEY="${SECRET}"\n`)
})

test('seedText: php and yaml/toml shapes, and unknown extensions fail', () => {
  assert.equal(seedText({ target: 'c.php', keyPath: 'API_KEY', secret: SECRET }), `define('API_KEY', '${SECRET}');\n`)
  assert.equal(seedText({ target: 'c.yml', keyPath: 'API_KEY', secret: SECRET }), `API_KEY: "${SECRET}"\n`)
  assert.equal(seedText({ target: 'c.toml', keyPath: 'API_KEY', secret: SECRET }), `API_KEY = "${SECRET}"\n`)
  expectFail(() => seedText({ target: 'c.ini.bak', keyPath: 'API_KEY', secret: SECRET }))
  expectFail(() => seedText({ target: 'c.xml', keyPath: 'API_KEY', secret: SECRET }))
})

test('keyPath validation: newline, __proto__ and over-long paths are rejected', () => {
  const json = '{"a":1}'
  expectFail(() => applySecret({ text: json, target: 'c.json', keyPath: 'a\nb', secret: SECRET }))
  expectFail(() => applySecret({ text: json, target: 'c.json', keyPath: 'a\rb', secret: SECRET }))
  expectFail(() => applySecret({ text: json, target: 'c.json', keyPath: 'a\0b', secret: SECRET }))
  expectFail(() => applySecret({ text: json, target: 'c.json', keyPath: '__proto__.a', secret: SECRET }))
  expectFail(() => applySecret({ text: json, target: 'c.json', keyPath: 'a.constructor.b', secret: SECRET }))
  expectFail(() => applySecret({ text: json, target: 'c.json', keyPath: 'prototype', secret: SECRET }))
  expectFail(() => applySecret({ text: json, target: 'c.json', keyPath: 'a'.repeat(129), secret: SECRET }))
  expectFail(() => applySecret({ text: json, target: 'c.json', keyPath: '', secret: SECRET }))
  expectFail(() => applySecret({ text: json, target: 'c.json', keyPath: '.a', secret: SECRET }))
  expectFail(() => applySecret({ text: json, target: 'c.json', keyPath: 'a.', secret: SECRET }))
})

test('keyPath validation applies to non-JSON formats as one literal key name', () => {
  expectFail(() => applySecret({ text: 'A=1\n', target: '.env', keyPath: 'A\nB', secret: SECRET }))
  expectFail(() => applySecret({ text: 'A=1\n', target: '.env', keyPath: 'A'.repeat(129), secret: SECRET }))
  // A dot is part of the name here, not a path separator.
  const dotted = applySecret({ text: 'a.b=1\n', target: '.env', keyPath: 'a.b', secret: SECRET })
  assert.equal(dotted.text, `a.b="${SECRET}"\n`)
})

test('unsupported extensions fail', () => {
  expectFail(() => applySecret({ text: 'x', target: 'c.xml', keyPath: 'K', secret: SECRET }))
  expectFail(() => applySecret({ text: 'x', target: 'c.yaml.bak', keyPath: 'K', secret: SECRET }))
  expectFail(() => applySecret({ text: 'x', target: '', keyPath: 'K', secret: SECRET }))
})

test('a secret carrying a line break is refused for line-based formats', () => {
  expectFail(() => applySecret({ text: 'A=1\n', target: '.env', keyPath: 'K', secret: 'line1\nline2' }), 'line1\nline2')
  expectFail(() => applySecret({ text: 'K: old\n', target: 'c.yml', keyPath: 'K', secret: 'a\rb' }), 'a\rb')
})

test('applySecret twice is idempotent: the second call reports changed=false', () => {
  const cases = [
    ['.env', 'A=1\n', 'API_KEY'],
    ['c.json', '{\n  "a": {\n    "b": 1\n  }\n}\n', 'a.b'],
    ['c.yml', 'API_KEY: old\n', 'API_KEY'],
    ['c.toml', 'API_KEY = "old"\n', 'API_KEY'],
    ['c.php', "<?php\ndefine('API_KEY', 'old');\n", 'API_KEY'],
    ['c.js', 'const c = { API_KEY: "old" }\n', 'API_KEY'],
  ]
  for (const [target, text, keyPath] of cases) {
    const first = applySecret({ text, target, keyPath, secret: SECRET })
    const second = applySecret({ text: first.text, target, keyPath, secret: SECRET })
    assert.equal(first.changed, true, `${target}: first write must change the file`)
    assert.equal(second.changed, false, `${target}: second write must be a no-op`)
    assert.equal(second.text, first.text, `${target}: idempotent text`)
  }
})
