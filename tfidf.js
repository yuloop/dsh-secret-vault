/**
 * TF-IDF (char 2–4 gram) + linear softmax classifier, pure JS, no dependencies.
 * Purpose: the deterministic rules abstain on unfamiliar wording; this layer covers that
 * residue at <1 ms and stays auditable (weights are a plain JSON file you can read).
 */
import { readFileSync, existsSync } from 'node:fs'

const PLACEHOLDER = /\[\[(secret|pii|url)\]\]/g

/** Bag of char n-grams plus placeholder tokens; digits and case are normalised away. */
export function features(masked) {
  const text = String(masked).toLowerCase()
  const bag = new Map()
  const add = (gram, weight = 1) => bag.set(gram, (bag.get(gram) ?? 0) + weight)
  for (const m of text.matchAll(PLACEHOLDER)) add(`<${m[1]}>`)
  const clean = text.replace(PLACEHOLDER, ' ').replace(/[^\u4e00-\u9fa5a-z]+/g, '')
  for (let n = 2; n <= 4; n++) {
    for (let i = 0; i + n <= clean.length; i++) add(clean.slice(i, i + n))
  }
  for (const word of text.match(/[a-z]{2,}/g) ?? []) add(`w:${word}`)
  return bag
}

function vectorize(bag, idf) {
  const out = []
  for (const [gram, count] of bag) {
    const weight = idf[gram]
    if (weight === undefined) continue
    out.push([gram, (1 + Math.log(count)) * weight])
  }
  return out
}

const softmax = scores => {
  const max = Math.max(...scores)
  const exps = scores.map(s => Math.exp(s - max))
  const sum = exps.reduce((a, b) => a + b, 0)
  return exps.map(e => e / sum)
}

/** Predict from a trained model object. Returns { kind, confidence } (confidence in [0,1]). */
export function predict(model, masked) {
  const vec = vectorize(features(masked), model.idf)
  const scores = model.labels.map(label => {
    const weights = model.weights[label] ?? {}
    let score = model.bias[label] ?? 0
    for (const [gram, value] of vec) if (weights[gram] !== undefined) score += weights[gram] * value
    return score
  })
  const probs = softmax(scores)
  let best = 0
  for (let i = 1; i < probs.length; i++) if (probs[i] > probs[best]) best = i
  return { kind: model.labels[best], confidence: probs[best], scores: probs }
}

/** Train a multinomial linear classifier. Kept deliberately small: a few epochs of SGD. */
export function train(samples, options = {}) {
  const epochs = options.epochs ?? 12
  const rate = options.rate ?? 0.5
  const labels = options.labels
  const df = new Map()
  const bags = samples.map(sample => {
    const bag = features(sample.text)
    for (const gram of bag.keys()) df.set(gram, (df.get(gram) ?? 0) + 1)
    return bag
  })
  const N = samples.length
  const idf = {}
  for (const [gram, count] of df) {
    if (count < 2) continue
    idf[gram] = Math.log((N + 1) / (count + 1)) + 1
  }
  const weights = {}, bias = {}
  for (const label of labels) { weights[label] = {}; bias[label] = 0 }
  const vectors = bags.map(bag => vectorize(bag, idf))
  for (let epoch = 0; epoch < epochs; epoch++) {
    for (let i = 0; i < N; i++) {
      const truth = samples[i].kind
      const vec = vectors[i]
      const scores = labels.map(label => {
        let score = bias[label]
        for (const [gram, value] of vec) if (weights[label][gram] !== undefined) score += weights[label][gram] * value
        return score
      })
      const probs = softmax(scores)
      for (let li = 0; li < labels.length; li++) {
        const label = labels[li]
        const error = probs[li] - (label === truth ? 1 : 0)
        if (!error) continue
        bias[label] -= rate * error
        for (const [gram, value] of vec) {
          weights[label][gram] = (weights[label][gram] ?? 0) - rate * error * value
        }
      }
    }
  }
  return { version: 1, labels, idf, weights: prune(weights, options.keepPerLabel ?? 400), bias }
}

/** Keep only the strongest features per label so the shipped model stays small and readable. */
function prune(weights, keepPerLabel) {
  const out = {}
  for (const [label, map] of Object.entries(weights)) {
    const top = Object.entries(map).sort((a, b) => Math.abs(b[1]) - Math.abs(a[1])).slice(0, keepPerLabel)
    out[label] = Object.fromEntries(top)
  }
  return out
}

export function loadModel(path) {
  if (!existsSync(path)) return null
  try { return JSON.parse(readFileSync(path, 'utf8')) } catch { return null }
}

/** Fallback adapter shaped for classify(): abstains when the model is unsure. */
export function makeFallback(model, threshold = 0.6) {
  if (!model) return null
  return masked => {
    const guess = predict(model, masked)
    return guess.confidence >= threshold ? { kind: guess.kind, confidence: guess.confidence } : { kind: 'unknown', confidence: guess.confidence }
  }
}
