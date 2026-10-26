/** Train the tiny linear classifier from the synthetic corpus and write model/tfidf-model.json. */
import { writeFileSync, statSync } from 'node:fs'
import { buildCorpus, KINDS } from './corpus.mjs'
import { train, predict } from '../tfidf.js'

const TRAIN_SEED = 1234
const corpus = buildCorpus(TRAIN_SEED, 60, 0.35)
const model = train(corpus, { labels: KINDS, epochs: 14, rate: 0.5, keepPerLabel: 400 })
const out = new URL('../model/tfidf-model.json', import.meta.url)
writeFileSync(out, JSON.stringify(model))

let correct = 0
for (const sample of corpus) if (predict(model, sample.text).kind === sample.kind) correct++
const size = statSync(out).size
console.log(`train samples=${corpus.length} train-accuracy=${(correct / corpus.length * 100).toFixed(1)}%`)
console.log(`model features=${Object.keys(model.idf).length} size=${(size / 1024).toFixed(0)} KB -> model/tfidf-model.json`)
