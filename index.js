/**
 * Private local processing: status/path-only output, no shell or HTTP tools.
 * v4.1.0: the user deletes their own temporary files from the panel (two-step confirm,
 * irreversible); the model has no delete tool. A locked session may still call
 * ask_user_question — private bytes never reach the model, so a question cannot carry them.
 * v4.2.0: the lock drops by itself once the last file is gone, and a broken store only
 * refuses store-touching calls instead of freezing tooling for every session.
 */
import { openStore, storeDir } from './store.js'
import { createTools } from './tools.js'
import { registerRoutes } from './routes.js'
import { registerGuard, createScopedFallbackGuard } from './guard.js'
import { startDailyCleanup } from './daily-cleanup.js'

export const inject = ['tools', 'agents', 'connection']

export async function apply(ctx) {
  let store
  try { store = await openStore() }
  catch {
    // Scoped fail-closed: the vault is unreadable, so store-touching calls are refused, but the
    // rest of the machine keeps working. A deny-everything guard here used to take every
    // session's tools down with a single bad state file.
    ctx.effect(() => ctx.tools.guard(createScopedFallbackGuard(storeDir())))
    ctx.logger?.warn?.('private-local: storage unavailable; store-touching calls refused')
    return
  }
  // Older entries predate save-time decomposition; fill them in once, in the background.
  store.backfillShapes().then(n => { if (n) ctx.logger?.info?.(`private-local: backfilled shape for ${n} entry(ies)`) })
    .catch(() => ctx.logger?.warn?.('private-local: shape backfill failed; contents were not logged'))
  registerGuard(ctx, store)
  for (const tool of createTools(store)) ctx.effect(() => ctx.tools.register(tool))
  registerRoutes(ctx, {
    store,
    isIdleSession: id => {
      const agent = ctx.agents.get(id)
      return agent?.status === 'idle'
    },
  })
  ctx.effect(() => startDailyCleanup(store, () => {
    ctx.logger?.warn?.('private-local: daily cleanup failed; contents were not logged')
  }))
}
