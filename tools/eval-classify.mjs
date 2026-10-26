/**
 * Evaluate the classification cascade on a corpus the trainer never saw.
 * Gates (from the MoA review): high-cost mistakes must be 0, abstain rate <= 25%, P99 < 100 ms.
 */
import { buildCorpus } from './corpus.mjs'
import { analyze, COST } from '../classify.js'

const EVAL_SEED = 9876
const HIGH_COST = 5
const corpus = buildCorpus(EVAL_SEED, 60, 0.35)

const cost = (truth, guess) => {
  if (guess === truth) return 0
  if (guess === 'unknown') return COST['>unknown']
  return COST[`${truth}>${guess}`] ?? COST.default
}

const timings = []
const confusion = new Map()
const perKind = new Map()
let highCost = 0
const mistakes = []

for (const sample of corpus) {
  const started = process.hrtime.bigint()
  const shape = analyze(sample.text).shape
  timings.push(Number(process.hrtime.bigint() - started) / 1e6)
  const guess = shape.kind
  const c = cost(sample.kind, guess)
  if (c >= HIGH_COST) { highCost++; mistakes.push(`${sample.kind} -> ${guess}  「${sample.text.slice(0, 40)}」`) }
  confusion.set(`${sample.kind}>${guess}`, (confusion.get(`${sample.kind}>${guess}`) ?? 0) + 1)
  const row = perKind.get(sample.kind) ?? { total: 0, right: 0, abstain: 0 }
  row.total++
  if (guess === sample.kind) row.right++
  if (guess === 'unknown') row.abstain++
  perKind.set(sample.kind, row)
}

const f1 = (() => {
  const labels = [...new Set([...perKind.keys(), ...[...confusion.keys()].map(k => k.split('>')[1])])].filter(l => l !== 'unknown')
  const scores = labels.map(label => {
    const tp = confusion.get(`${label}>${label}`) ?? 0
    const fp = [...confusion].filter(([k]) => k.split('>')[1] === label && k.split('>')[0] !== label).reduce((a, [, v]) => a + v, 0)
    const fn = [...confusion].filter(([k]) => k.split('>')[0] === label && k.split('>')[1] !== label).reduce((a, [, v]) => a + v, 0)
    const precision = tp + fp ? tp / (tp + fp) : 0
    const recall = tp + fn ? tp / (tp + fn) : 0
    return precision + recall ? 2 * precision * recall / (precision + recall) : 0
  })
  return scores.reduce((a, b) => a + b, 0) / (scores.length || 1)
})()

timings.sort((a, b) => a - b)
const pct = p => timings[Math.min(timings.length - 1, Math.floor(p / 100 * timings.length))]
const abstain = [...perKind.values()].reduce((acc, row) => acc + row.abstain, 0) / corpus.length

console.log(`samples=${corpus.length}  high-cost mistakes=${highCost}  abstain=${(abstain * 100).toFixed(1)}%`)
console.log(`macro-F1 (excluding unknown) = ${f1.toFixed(3)}`)
console.log(`latency ms  p50=${pct(50).toFixed(2)} p95=${pct(95).toFixed(2)} p99=${pct(99).toFixed(2)}`)
console.log('\nper class:')
for (const [kind, row] of perKind) {
  console.log(`  ${kind.padEnd(16)} n=${String(row.total).padEnd(3)} correct=${String(row.right).padEnd(3)} abstain=${row.abstain}`)
}
if (mistakes.length) { console.log('\nhigh-cost mistakes:'); for (const m of mistakes.slice(0, 10)) console.log('  ' + m) }
const gates = [
  ['high-cost mistakes = 0', highCost === 0],
  ['abstain <= 25%', abstain <= 0.25],
  ['P99 < 100 ms', pct(99) < 100],
  ['macro-F1 >= 0.85', f1 >= 0.85],
]
console.log('\ngates:')
for (const [name, ok] of gates) console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}`)
process.exitCode = gates.every(([, ok]) => ok) ? 0 : 1
