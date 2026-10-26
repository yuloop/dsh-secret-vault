/**
 * Default-deny for sessions that supplied private local data.
 * This is a DSH tool-dispatch boundary, NOT an OS sandbox for other root processes.
 * No content matching: encoding, slicing and alternate commands do not reopen tools.
 */
import { homedir } from 'node:os'

const SAFE = new Set(['private_local_status', 'private_local_process'])
// A locked session must still be able to ask its own user. Private bytes never reach
// the model, so a question cannot carry them; blocking this only produced deadlock.
const INQUIRY = new Set(['ask_user_question'])
const RETIRED = new Set(['tmp_run', 'tmp_http', 'tmp_inspect', 'tmp_normalize', 'tmp_list',
  'vault_run', 'vault_http', 'vault_inspect', 'vault_normalize', 'vault_list'])
const REASON = '本会话处于私密本地处理模式：只能调用 private_local_status / private_local_process；普通读取、命令、网络、子代理和管理工具暂停。正文不得进入模型或日志。'
const UNAVAILABLE = '私密存储状态异常：会碰到私密存储的调用已暂停，其余工具照常；请在宿主本地修复存储。'

/** Absolute and home-relative spellings of the private directory. */
function storeForms(dir) {
  const forms = new Set()
  if (typeof dir === 'string' && dir) {
    forms.add(dir)
    const home = homedir()
    if (home && dir.startsWith(home)) forms.add(`~${dir.slice(home.length)}`)
  }
  return [...forms]
}

function argsOf(exec) {
  try { return JSON.stringify(exec?.arguments ?? {}) }
  catch { return null }
}

/** True when the call itself names the private directory (accidental direct read). */
function referencesStore(args, forms) {
  if (typeof args !== 'string') return true // unrepresentable arguments: fail closed
  return forms.some(form => args.includes(form))
}

export function createGuard(store) {
  const forms = storeForms(store.dir)
  return exec => {
    const owner = exec?.agent?.id || exec?.agent?.session?.id
    if (RETIRED.has(exec.name)) return REASON
    const touchesStore = referencesStore(argsOf(exec), forms)
    // Scoped fail-closed (v4.2.0): an unreadable store must not freeze unrelated tooling in
    // every session — that turned one bad file into a machine-wide tool outage.
    if (!store.healthy()) return touchesStore || SAFE.has(exec.name) ? UNAVAILABLE : undefined
    if (!owner && store.hasFiles()) return REASON
    if (store.isLocked(owner) && !SAFE.has(exec.name) && !INQUIRY.has(exec.name)) return REASON
    if (SAFE.has(exec.name)) return undefined // implementation rechecks owner + strict operation
    // Defense against accidental direct reads/references from another session.
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
    return referencesStore(argsOf(exec), forms) ? UNAVAILABLE : undefined
  }
}

export function registerGuard(ctx, store) {
  return ctx.effect(() => ctx.tools.guard(createGuard(store)))
}
