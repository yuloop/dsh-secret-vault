/**
 * Default-deny for calls that reach the private files — not for whole sessions.
 * This is a DSH tool-dispatch boundary, NOT an OS sandbox for other root processes.
 *
 * v4.5.0 narrowed the trigger from "any argument mentions the store" to "an argument that
 * carries a path or a command mentions the store". The old rule read free prose too, so a
 * compress summary, a bug report to another agent, or a script that merely *named* the vault
 * directory was refused — which silenced the very reports this plugin needs, and never
 * stopped a determined caller anyway (an assembly-time path defeats substring matching).
 * What actually keeps bytes out of the transcript is the exit redaction in index.js plus the
 * fact that no tool returns file contents; this guard only stops the accidental direct hit.
 */
import { homedir } from 'node:os'
import { isAbsolute, normalize } from 'node:path'

const SAFE = new Set(['private_local_status', 'private_local_process'])
// A legacy-locked session must still be able to ask its own user. Private bytes never reach
// the model, so a question cannot carry them; blocking this only produced deadlock.
const INQUIRY = new Set(['ask_user_question'])
const RETIRED = new Set(['tmp_run', 'tmp_http', 'tmp_inspect', 'tmp_normalize', 'tmp_list',
  'vault_run', 'vault_http', 'vault_inspect', 'vault_normalize', 'vault_list'])
// Argument keys that can address a file or run code. Free prose (`text`, `content`,
// `summary`, `prompt`, `message`, `title`) is deliberately absent: naming the vault in a
// message moves no bytes, and refusing it turned reporting into a dead end.
const TOUCH_KEYS = new Set(['file_path', 'path', 'paths', 'cwd', 'dir', 'directory', 'root',
  'command', 'script', 'code', 'target', 'destination', 'source', 'pattern_path'])
const MAX_DEPTH = 4
const REASON = '本会话的私密文件受保护：只拦「参数里用路径或命令指向私密目录」的调用（如 read/cat 那个目录），'
  + '其余工具照常可用。要用私密文件里的值，走 '
  + 'private_local_process({operation:"write_secret", reference, target, key_path}) —— 值只进文件，不进上下文。'
  + '查看状态用 private_local_status。'
const UNAVAILABLE = '私密存储状态异常：会碰到私密存储的调用已暂停，其余工具照常；请在宿主本地修复存储。'

/** Absolute and home-relative spellings of the private directory. */
function storeForms(dir) {
  const forms = new Set()
  if (typeof dir === 'string' && dir) {
    forms.add(dir)
    const normalized = normalize(dir).replace(/[\\/]+$/, '')
    if (normalized) forms.add(normalized)
    const home = homedir()
    if (home && dir.startsWith(home)) forms.add(`~${dir.slice(home.length)}`)
  }
  return [...forms]
}

/** Every string under a path/command-like key, plus values that are themselves absolute paths. */
function touchValues(value, depth = 0, out = []) {
  if (depth > MAX_DEPTH || value === null || typeof value !== 'object') return out
  for (const [key, item] of Object.entries(value)) {
    if (typeof item === 'string') {
      if (TOUCH_KEYS.has(key) || (key !== 'content' && key !== 'text' && isAbsolute(item))) out.push(item)
    } else if (Array.isArray(item)) {
      if (TOUCH_KEYS.has(key)) for (const element of item) if (typeof element === 'string') out.push(element)
      else touchValues(item, depth + 1, out)
    } else if (item && typeof item === 'object') touchValues(item, depth + 1, out)
  }
  return out
}

/** True when the call itself addresses the private directory (accidental direct read/hit). */
function referencesStore(exec, forms) {
  let args
  try { args = exec?.arguments } catch { return true }
  if (args === null || typeof args !== 'object') return true // unrepresentable arguments: fail closed
  const values = touchValues(args)
  return values.some(value => forms.some(form => value.includes(form)))
}

export function createGuard(store) {
  const forms = storeForms(store.dir)
  const touches = exec => referencesStore(exec, forms)
  return exec => {
    if (RETIRED.has(exec.name)) return REASON
    const owner = exec?.agent?.id || exec?.agent?.session?.id
    const touchesStore = touches(exec)
    // Scoped fail-closed (v4.2.0): an unreadable store must not freeze unrelated tooling in
    // every session — that turned one bad file into a machine-wide tool outage.
    if (!store.healthy()) return touchesStore || SAFE.has(exec.name) ? UNAVAILABLE : undefined
    // v4.5.0: an unattributable call cannot be a vault owner's legitimate call, but denying
    // every tool for it turned a missing session id into a machine-wide outage.
    if (!owner) return touchesStore ? REASON : undefined
    if (store.isLocked(owner) && !SAFE.has(exec.name) && !INQUIRY.has(exec.name)) return REASON
    if (SAFE.has(exec.name)) return undefined // implementation rechecks owner + strict operation
    // Defense against accidental direct reads/references from any session.
    // Arbitrary root code in OTHER sessions still needs OS isolation; no false guarantee.
    return touchesStore ? REASON : undefined
  }
}

/**
 * Mounted when openStore() itself failed: there is no per-session state to consult, so only the
 * private bytes are defended. Everything else keeps working (same reasoning as above).
 */
export function createScopedFallbackGuard(dir) {
  const forms = storeForms(dir)
  return exec => {
    if (SAFE.has(exec.name) || RETIRED.has(exec.name)) return UNAVAILABLE
    return referencesStore(exec, forms) ? UNAVAILABLE : undefined
  }
}

export function registerGuard(ctx, store) {
  return ctx.effect(() => ctx.tools.guard(createGuard(store)))
}
