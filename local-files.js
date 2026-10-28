/** Private bytes stay in local filesystem operations; never echo caught errors. */
import { constants } from 'node:fs'
import { open, mkdir, lstat, realpath, rename, unlink } from 'node:fs/promises'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'

export const MAX_BYTES = 128 * 1024
export const MAX_STATE_BYTES = 1024 * 1024
// A target config file we are allowed to rewrite; larger is a mistake, not a config.
export const MAX_TARGET_BYTES = 1024 * 1024
export const newId = () => `tmp-${randomBytes(16).toString('hex')}`
export const ID = /^tmp-[a-f0-9]{32}$/
export const OWNER = /^[a-zA-Z0-9_-]{1,128}$/
export const fail = () => { throw new Error('PRIVATE_OPERATION_FAILED') }

export async function privateDirectory(dir) {
  await mkdir(dir, { recursive: true, mode: 0o700 })
  const info = await lstat(dir)
  if (!info.isDirectory() || info.isSymbolicLink()) fail()
  if ((info.mode & 0o077) !== 0) fail()
  return realpath(dir)
}

export async function boundedRead(path, max = MAX_BYTES) {
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  try {
    const info = await fd.stat()
    if (!info.isFile() || info.nlink !== 1 || info.size > max) fail()
    const buffer = Buffer.alloc(max + 1)
    let count = 0
    while (count < buffer.length) {
      const part = await fd.read(buffer, count, buffer.length - count, null)
      if (!part.bytesRead) break
      count += part.bytesRead
    }
    if (count > max) fail()
    return new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, count))
  } finally { await fd.close() }
}

export async function exclusiveWrite(path, text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > MAX_BYTES) fail()
  const fd = await open(path, 'wx', 0o600)
  try { await fd.writeFile(text, 'utf8'); await fd.sync() }
  finally { await fd.close() }
}

/**
 * Replace a target file's bytes via a sibling temp file. Mode is preserved from the existing
 * file (0o600 for a new one): an API key must not become world-readable because we rewrote it.
 */
export async function atomicReplace(path, text) {
  if (typeof text !== 'string') fail()
  const dir = path.slice(0, path.lastIndexOf('/')) || '.'
  const temp = join(dir, `.private-write-${randomBytes(12).toString('hex')}`)
  let mode = 0o600
  try { mode = (await lstat(path)).mode & 0o777 } catch (error) { if (error.code !== 'ENOENT') fail() }
  const fd = await open(temp, 'wx', mode)
  try { await fd.writeFile(text, 'utf8'); await fd.sync() }
  finally { await fd.close() }
  try { await rename(temp, path) }
  catch (error) { await unlink(temp).catch(() => {}); throw error }
}

export async function atomicState(dir, state) {
  const text = JSON.stringify(state)
  if (Buffer.byteLength(text) > MAX_STATE_BYTES) fail()
  const temp = join(dir, `.state-${randomBytes(12).toString('hex')}`)
  const fd = await open(temp, 'wx', 0o600)
  try { await fd.writeFile(text, 'utf8'); await fd.sync() }
  finally { await fd.close() }
  try { await rename(temp, join(dir, 'state.json')) }
  catch (error) { await unlink(temp).catch(() => {}); throw error }
}
