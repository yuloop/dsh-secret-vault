/** Fixed local daily task (no LLM invocation), 04:00 Asia/Shanghai = previous 20:00 UTC. */
const DAY = 86400000
const HOUR = 3600000

export function cleanupBoundary(now) {
  return Math.floor((now + 4 * HOUR) / DAY) * DAY - 4 * HOUR
}

export function startDailyCleanup(store, report = () => {}) {
  let stopped = false
  let timeout
  let running
  async function tick() {
    try { await store.cleanup(cleanupBoundary(Date.now())) }
    catch { report('私密文件清理失败；文件保留，未输出内容。') }
    if (!stopped) timeout = setTimeout(run, cleanupBoundary(Date.now()) + DAY - Date.now() + 20)
    timeout?.unref?.()
  }
  function run() { running = tick() }
  run()
  return async () => { stopped = true; clearTimeout(timeout); await running }
}
