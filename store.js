/** Plaintext local files. Only fixed transformations can consume their bytes. */
import { isAbsolute, join, resolve } from 'node:path'
import { homedir } from 'node:os'
import { unlink } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { ID, OWNER, MAX_BYTES, MAX_STATE_BYTES, MAX_TARGET_BYTES, boundedRead, privateDirectory,
  exclusiveWrite, atomicState, atomicReplace, newId, fail } from './local-files.js'
import { OPERATIONS, transformLocally } from './local-operations.js'
import { shapeLine } from './field-shape.js'
import { selectSecret, applySecret, seedText } from './secret-write.js'
import { analyze } from './classify.js'

export const MAX_AGE_MS = 24 * 60 * 60 * 1000
export const storeDir = () => join(process.env.DSH_HOME || join(homedir(), '.dsh-home'),
  'secret-vault', 'local-v4')

function validateState(state) {
  if (state?.version !== 4 || !Array.isArray(state.entries) || !Array.isArray(state.locked)) fail()
  if (!state.locked.every(id => typeof id === 'string' && OWNER.test(id))) fail()
  if (!Number.isFinite(state.lastSweep)) fail()
  const ids = new Set()
  for (const e of state.entries) {
    // v4.3.0 dropped the session lock, so entries no longer have to imply one. Old state
    // files that still carry a lock keep loading, and that legacy lock still releases.
    if (!ID.test(e.id) || !OWNER.test(e.owner)) fail()
    if (ids.has(e.id) || !Number.isFinite(e.created) || e.created < 0) fail()
    if (e.used !== null && (!Number.isFinite(e.used) || e.used < 0)) fail()
    ids.add(e.id)
  }
  return state
}

class LocalStore {
  #state; #clock; #broken = false; #tail = Promise.resolve()
  constructor(dir, state, clock) { this.dir = dir; this.#state = state; this.#clock = clock }
  healthy() { return !this.#broken }
  isLocked(owner) { return this.#broken || this.#state.locked.includes(owner) }
  hasFiles() { return this.#broken || this.#state.entries.length > 0 }
  #path(id) { return join(this.dir, `${id}.txt`) }
  #view(e) {
    const shape = e.shape ?? null
    return { id: e.id, path: this.#path(e.id), used: e.used !== null, shape, summary: shape ? shapeLine(shape) : null }
  }
  #owner(owner) { if (typeof owner !== 'string' || !OWNER.test(owner)) fail(); return owner }
  #serial(operation) {
    const task = this.#tail.then(() => { if (this.#broken) fail(); return operation() })
    this.#tail = task.catch(() => {})
    return task
  }
  async #persist() {
    try { await atomicState(this.dir, this.#state) }
    catch { this.#broken = true; fail() }
  }
  #lookup(owner, reference) {
    this.#owner(owner)
    if (typeof reference !== 'string') fail()
    const found = this.#state.entries.find(e => e.owner === owner &&
      (e.id === reference || this.#path(e.id) === reference))
    if (!found) fail()
    return found
  }
  async #create(owner, text) {
    if (typeof text !== 'string' || Buffer.byteLength(text) > MAX_BYTES) fail()
    const id = newId()
    // Structure is computed once, at save time: callers get the field digest for free and
    // never need to ask, and the digest carries no values (length/fingerprint only).
    const entry = { id, owner: this.#owner(owner), created: this.#clock(), used: null, shape: analyze(text).shape }
    // v4.3.0: saving no longer locks the session. A lock froze every tool exactly when the
    // user wanted the file used, so the model could not act on what it was given. What still
    // protects the bytes: they never enter chat, and any call naming the store path is refused.
    // Metadata precedes private bytes: even a crash leaves a tracked cleanup target.
    this.#state.entries.push(entry)
    await this.#persist()
    try { await exclusiveWrite(this.#path(id), text) }
    catch {
      // Keep the tracked record for daily cleanup, including partial writes.
      throw new Error('PRIVATE_OPERATION_FAILED')
    }
    return entry
  }
  save(owner, text) {
    return this.#serial(async () => {
      if (typeof text !== 'string' || !text.length || this.#state.entries.length >= 256) fail()
      return this.#view(await this.#create(owner, text))
    })
  }
  list(owner) {
    this.#owner(owner)
    if (this.#broken) fail()
    return this.#state.entries.filter(e => e.owner === owner).map(e => this.#view(e))
  }
  process(owner, reference, operation) {
    return this.#serial(async () => {
      if (!OPERATIONS.includes(operation) || this.#state.entries.length >= 256) fail()
      const source = this.#lookup(owner, reference)
      const raw = await boundedRead(this.#path(source.id))
      const output = await this.#create(owner, transformLocally(raw, operation))
      source.used = this.#clock()
      await this.#persist()
      return { ok: true, status: 'processed', result: this.#view(output) }
    })
  }
  /**
   * v4.5.0: the operation the vault exists for — put one secret into a target config file.
   * The value goes vault -> target and never through the model: the return carries the key
   * path, the changed flag and a fingerprint prefix, never the bytes.
   */
  writeSecret(owner, { reference, target, keyPath, mode }) {
    return this.#serial(async () => {
      const source = this.#lookup(owner, reference)
      const raw = await boundedRead(this.#path(source.id))
      const secret = selectSecret(raw, mode ?? 'whole')
      if (typeof target !== 'string' || !isAbsolute(target) || target.startsWith(this.dir + '/')) fail()
      let current = null
      try { current = await boundedRead(target, MAX_TARGET_BYTES) } catch (error) { if (error.code !== 'ENOENT') fail() }
      const outcome = current === null
        ? { text: seedText({ target, keyPath, secret }), changed: true }
        : applySecret({ text: current, target, keyPath, secret })
      if (outcome.changed) await atomicReplace(target, outcome.text)
      source.used = this.#clock()
      await this.#persist()
      return {
        ok: true, status: outcome.changed ? 'written' : 'unchanged',
        target, keyPath, mode: mode ?? 'whole',
        fingerprint: createHash('sha256').update(secret).digest('hex').slice(0, 8),
      }
    })
  }
  markUsed(owner, reference) {    return this.#serial(async () => {
      this.#lookup(owner, reference).used = this.#clock()
      await this.#persist()
      return { ok: true }
    })
  }
  // User-initiated removal: the only path to an empty store besides daily cleanup.
  async remove(owner, reference) {
    return this.#serial(async () => {
      const source = this.#lookup(owner, reference)
      const target = this.#path(source.id)
      if (!ID.test(source.id) || resolve(target) !== target) fail()
      await unlink(target).catch(error => { if (error.code !== 'ENOENT') throw error })
      this.#state.entries = this.#state.entries.filter(e => e.id !== source.id)
      // Removing the last file must not leave the session stranded behind an extra click.
      const released = this.#autoRelease(owner)
      await this.#persist()
      return { ok: true, released, locked: this.isLocked(owner), entries: this.list(owner) }
    })
  }
  // A lock protects files; with no files left it protects nothing and only strands the session.
  #autoRelease(owner) {
    if (this.#state.entries.some(e => e.owner === owner)) return false
    if (!this.#state.locked.includes(owner)) return false
    this.#state.locked = this.#state.locked.filter(id => id !== owner)
    return true
  }
  /** Entries saved before auto-decomposition existed get their shape on the next start. */
  backfillShapes() {
    return this.#serial(async () => {
      // Also upgrade digests written before classification existed (shape without `kind`).
      const missing = this.#state.entries.filter(entry => !entry.shape || !entry.shape.kind)
      if (!missing.length) return 0
      for (const entry of missing) {
        try { entry.shape = analyze(await boundedRead(this.#path(entry.id))).shape }
        catch { entry.shape = { unavailable: true, addresses: [], models: [], secrets: [], pii: [], labels: [], json: false } }
      }
      await this.#persist()
      return missing.length
    })
  }
  release(owner) {
    return this.#serial(async () => {
      this.#owner(owner)
      if (this.#state.entries.some(e => e.owner === owner)) fail()
      this.#state.locked = this.#state.locked.filter(id => id !== owner)
      await this.#persist()
      return { ok: true }
    })
  }
  cleanup(boundary) {
    return this.#serial(async () => {
      if (!Number.isFinite(boundary) || boundary <= this.#state.lastSweep) return { removed: 0 }
      const expired = this.#state.entries.filter(e =>
        (e.used !== null && e.used < boundary) || e.created < boundary - MAX_AGE_MS)
      for (const entry of expired) {
        const target = this.#path(entry.id)
        if (!ID.test(entry.id) || resolve(target) !== target) fail()
        await unlink(target).catch(error => { if (error.code !== 'ENOENT') throw error })
      }
      const removed = new Set(expired.map(e => e.id))
      this.#state.entries = this.#state.entries.filter(e => !removed.has(e.id))
      // Same reasoning as #autoRelease: also self-heals locks already stranded with zero files.
      this.#state.locked = this.#state.locked.filter(owner =>
        this.#state.entries.some(e => e.owner === owner))
      this.#state.lastSweep = boundary
      await this.#persist()
      return { removed: removed.size }
    })
  }
}

export async function openStore(directory = storeDir(), clock = Date.now) {
  const dir = await privateDirectory(directory)
  let state
  try { state = validateState(JSON.parse(await boundedRead(join(dir, 'state.json'), MAX_STATE_BYTES))) }
  catch (error) {
    if (error.code !== 'ENOENT') fail()
    state = { version: 4, entries: [], locked: [], lastSweep: 0 }
  }
  return new LocalStore(dir, state, clock)
}
