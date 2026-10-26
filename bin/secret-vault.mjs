#!/usr/bin/env node
/**
 * Host-side rescue CLI. It exists so a broken browser UI can never strand a session behind
 * the private-vault lock: run it from the host shell, no browser peer or auth needed.
 * It prints identifiers and flags only — never file contents.
 */
import { spawnSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { describe } from '../field-shape.js'
import { openStore } from '../store.js'
import { cleanupBoundary } from '../daily-cleanup.js'

const USAGE = `私密存储救援命令（宿主本地，不需要浏览器）
  secret-vault status [session]        列出条目与锁定状态（只读）
  secret-vault release <session>       条目已清空时解除锁定
  secret-vault purge <session> --yes   删除该会话的全部私密文件并解锁
  secret-vault fields [id]            分解一份私密内容的字段形状（不打印值）
  secret-vault cleanup                 立即按 04:00 规则清理一次
选项
  --restart   改完后重启 dsh-web，让进程内存里的旧状态失效（改了存储就必须有这一步）
`
const argv = process.argv.slice(2)
const restart = argv.includes('--restart')
const confirmed = argv.includes('--yes') || argv.includes('-y')
const words = argv.filter(a => !a.startsWith('-'))
const command = words[0] || 'status'
const target = words[1]

async function readState(dir) {
  try { return JSON.parse(await readFile(join(dir, 'state.json'), 'utf8')) }
  catch (error) {
    if (error.code === 'ENOENT') return { entries: [], locked: [] }
    throw new Error('STORE_UNREADABLE')
  }
}

function webActive() {
  return spawnSync('systemctl', ['is-active', 'dsh-web'], { encoding: 'utf8' }).stdout?.trim() === 'active'
}

function scheduleRestart() {
  const unit = `sv-cli-restart-${process.pid}`
  const result = spawnSync('systemd-run', ['--unit', unit, '--collect', '--quiet',
    'bash', '-lc', 'sleep 1; systemctl restart dsh-web'], { encoding: 'utf8' })
  if (result.status !== 0) {
    console.log(`重启没触发（${(result.stderr || '').trim() || 'systemd-run 失败'}）。手动跑：systemctl restart dsh-web`)
    return
  }
  console.log(`已排队重启 dsh-web（${unit}）；正在跑的会话会被打断，重启后自动续。`)
}

function reportMutation(store, session) {
  const left = store.list(session).length
  console.log(`session=${session} 剩余条目=${left} 仍锁定=${store.isLocked(session)}`)
  if (!webActive()) { console.log('dsh-web 没在跑：下次启动即生效，无需重启。'); return }
  if (restart) scheduleRestart()
  else console.log('dsh-web 正在跑，内存里还是旧状态：加 --restart，或稍后 systemctl restart dsh-web。')
}

/** Nothing changed: say so plainly and never imply a restart is needed. */
function reportNoop(session, why) {
  console.log(`session=${session}：${why}，没有改动，不需要重启。`)
}

/**
 * A truncated session id used to look like an empty session, so the CLI answered
 * "nothing to delete" while the files were still there (2026-10-25). Resolve prefixes,
 * refuse ambiguity, and name the full id.
 */
function resolveOwner(state, wanted) {
  const owners = [...new Set([...state.locked, ...state.entries.map(e => e.owner)])]
  if (owners.includes(wanted)) return wanted
  const prefixed = owners.filter(o => o.startsWith(wanted))
  if (prefixed.length === 1) { console.log(`按前缀匹配到会话 ${prefixed[0]}`); return prefixed[0] }
  if (prefixed.length > 1) {
    console.log(`前缀 ${wanted} 匹配到多个会话，请给完整 id：`)
    for (const o of prefixed) console.log(`  ${o}`)
    return null
  }
  // Empty string means "nothing to do" (exit 0); null means "ambiguous target" (exit 2).
  console.log(`会话 ${wanted}：没有私密文件，也没有锁，无需操作。`)
  if (owners.length) { console.log('当前有内容的会话（截断 id 时对一下）：'); for (const o of owners) console.log(`  ${o}`) }
  return ''
}

async function status(store, wanted) {
  const state = await readState(store.dir)
  console.log(`store=${store.dir} healthy=${store.healthy()}`)
  if (!state.entries.length && !state.locked.length) { console.log('没有任何条目，也没有锁定的会话。'); return }
  for (const owner of [...new Set([...state.locked, ...state.entries.map(e => e.owner)])]) {
    const rows = state.entries.filter(e => e.owner === owner)
    if (wanted && wanted !== owner) continue
    const lock = state.locked.includes(owner)
    console.log(`会话 ${owner}：锁定=${lock ? (rows.length ? '有文件' : '无文件（可 release）') : '无'} 条目=${rows.length}`)
    for (const e of rows) {
      const used = e.used === null ? '未用' : `已用 ${new Date(e.used).toISOString()}`
      console.log(`  ${e.id} 创建=${new Date(e.created).toISOString()} ${used}`)
    }
  }
}

/**
 * Describe the shape of a private blob without disclosing it: URLs reduced to scheme+host,
 * model ids printed (public), secret-looking tokens reduced to length + fingerprint.
 * Messy input (natural language with values mixed in) is expected here, not an error.
 */
async function fields(store, wanted) {
  const state = await readState(store.dir)
  const entry = wanted ? state.entries.find(e => e.id === wanted) : state.entries.sort((a, b) => b.created - a.created)[0]
  if (!entry) { console.log(wanted ? `没有条目 ${wanted}` : '存储里没有私密内容'); process.exitCode = 2; return }
  const raw = await readFile(join(store.dir, `${entry.id}.txt`), 'utf8')
  const report = describe(raw)
  console.log(`entry=${entry.id} owner=${entry.owner} bytes=${report.bytes} lines=${report.lines}`)
  if (entry.shape?.kind) {
    const shape = entry.shape
    console.log(`内容类型: ${shape.kindLabel ?? shape.kind} (${shape.kind}) · 敏感:${shape.sensitivity} · 置信:${shape.confidence} · 依据:${(shape.evidence ?? []).join(',')}`)
    if (shape.advice) console.log(`建议: ${shape.advice}`)
  }
  console.log('地址字段:', report.addresses.join(' , ') || '(无)')
  console.log('模型/标识:', report.models.join(', ') || '(无)')
  if (!report.pii.length) console.log('个人信息: 未识别到')
  for (const item of report.pii) console.log(`个人信息: ${item.type} 长度=${item.length} 指纹=${item.fingerprint} 依据=${item.evidence} (值不打印)`)
  if (!report.secrets.length) console.log('密钥: 未识别到（可能是纯文本或结构不支持）')
  for (const item of report.secrets) console.log(`密钥: 长度=${item.length} 指纹=${item.fingerprint} 依据=${item.rule} (值不打印)`)
  for (const item of report.unknownLong) console.log(`未分类长串: 长度=${item.length} 指纹=${item.fingerprint} (不判为密钥)`)
  if (report.labels.length) console.log('标签:', report.labels.map(l => `${l.label}(${l.role})`).join(' | '))
  if (report.json) console.log(`JSON: 可解析，路径=${report.jsonPaths.slice(0, 12).join(', ') || '(空)'}`)
  else console.log('JSON: 不可解析（自然语言/多段混排都可以）')
}

async function main() {
  const store = await openStore()
  if (command === 'status') return status(store, target)
  if (command === 'fields') return fields(store, target)
  if (command === 'cleanup') {
    const result = await store.cleanup(cleanupBoundary(Date.now()))
    console.log(`清理完成，删除 ${result.removed} 个文件；无文件残留的锁已自动解除。`)
    return webActive() && console.log('如需让运行中的 dsh-web 立即看到，请重启它。')
  }
  if (command === 'release' || command === 'purge') {
    if (!target) { console.log(USAGE); process.exitCode = 2; return }
    const owner = resolveOwner(await readState(store.dir), target)
    if (owner === null) { process.exitCode = 2; return }
    if (owner === '') return
    if (command === 'purge') {
      const rows = store.list(owner)
      if (!rows.length) {
        if (!store.isLocked(owner)) return reportNoop(owner, '没有条目也没有锁')
        await store.release(owner)
        return reportMutation(store, owner)
      }
      if (!confirmed) {
        console.log(`该会话有 ${rows.length} 个私密文件；删除不可恢复，确认请加 --yes。`)
        process.exitCode = 2
        return
      }
      for (const entry of rows) await store.remove(owner, entry.id)
      return reportMutation(store, owner)
    }
    if (store.list(owner).length) {
      console.log(`该会话还有 ${store.list(owner).length} 个文件，release 会拒绝；先 purge 或让用户删掉。`)
      process.exitCode = 2
      return
    }
    if (!store.isLocked(owner)) return reportNoop(owner, '没有锁')
    await store.release(owner)
    return reportMutation(store, owner)
  }
  console.log(USAGE)
  process.exitCode = 2
}

main().catch(error => {
  console.log(error.message === 'STORE_UNREADABLE'
    ? 'state.json 读不出来（不是不存在）；请勿手改，先备份再排查。'
    : '操作失败：PRIVATE_OPERATION_FAILED（不回显内容）')
  process.exitCode = 1
})
