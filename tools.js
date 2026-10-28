/** Model-facing surface: fixed operations and opaque references only. */
import { OPERATIONS } from './local-operations.js'

const FAILURE = Object.freeze({ ok: false, status: 'operation_failed' })
const RESULT = {
  schema: { type: 'object' },
  render: (_args, result) => [{ type: 'text', text: JSON.stringify(result) }],
}
// v4.5.0: the operation the vault exists for. The value travels vault -> target and never
// enters the transcript; only the fingerprint prefix comes back.
const WRITE = 'write_secret'
const WRITE_KEYS = ['reference', 'operation', 'target', 'key_path', 'mode']
const MODES = ['whole', 'first-secret']

function sessionOf(exec) {
  return exec?.agent?.id || exec?.agent?.session?.id
}

function writeResult(args, exec, store) {
  return store.writeSecret(sessionOf(exec), {
    reference: args.reference,
    target: args.target,
    keyPath: args.key_path,
    mode: args.mode,
  })
}

export function createTools(store) {
  return [
    {
      name: 'private_local_status',
      description: '报本会话私密模式的状态：mode=local_only 表示有私密文件（不阻断任何工具，只有参数指向私密目录的调用会被拦），mode=normal 表示没有。附解除条件与文件引用清单，不读取也不返回正文。',
      parameters: { type: 'object', properties: {}, additionalProperties: false }, output: RESULT,
      async execute(_args, exec) {
        try {
          const owner = sessionOf(exec)
          const entries = store.list(owner)
          const localOnly = entries.length > 0
          return {
            ok: true,
            // Stable, single-call answer: one field tells the model whether it is restricted.
            mode: localOnly ? 'local_only' : 'normal',
            // v4.5.0: no longer a blanket denial — naming what remains open stops the
            // "everything is broken" loop that produced 5 rounds of "I cannot do that".
            restricts: localOnly ? ['args naming the private directory'] : [],
            openTools: 'all except calls whose path/command arguments name the private directory',
            releaseWhen: localOnly
              ? '这些文件被删除（用户在面板里删）、或 24 小时后自动清理；无需解锁命令'
              : 'already normal',
            locked: store.isLocked(owner),
            entries,
          }
        } catch { return FAILURE }
      },
    },
    {
      name: 'private_local_process',
      description: '在宿主本地执行固定格式操作，结果保存在新的私密临时文件；仅返回状态和路径，不返回正文、摘要、指纹或解析错误。不能执行代码、shell、联网或语义分析。'
        + ' operation=write_secret 时改为「把私密文件里的值写进目标配置文件的指定键」，返回只含成功状态与指纹前 8 位，正文永不返回。',
      parameters: {
        type: 'object', additionalProperties: false, required: ['reference', 'operation'],
        properties: {
          reference: { type: 'string', description: '本会话临时文件的随机 ID 或完整路径。禁止使用 read 读取正文。' },
          operation: { type: 'string', enum: [...OPERATIONS, WRITE], description: 'copy 原样复制；trim_edges 去首尾空白；normalize_newlines 统一换行；json_pretty/json_compact 格式化 JSON；dedupe_lines 按整行去重；write_secret 把值写进 target 的 key_path（需同时给 target 与 key_path）。只有明确要求时才选择对应操作；不自动猜测内容格式。' },
          target: { type: 'string', description: 'write_secret 专用：目标配置文件绝对路径，按扩展名决定写法（.env/.ini/.properties/.yml/.toml/.json/.php/.js/.ts）。' },
          key_path: { type: 'string', description: 'write_secret 专用：键名；.json 用点分路径（a.b.c），其余格式为单个键名。' },
          mode: { type: 'string', enum: MODES, description: 'write_secret 专用：whole（默认）取整个文件去首尾空白；first-secret 取文件里识别到的第一个密钥。' },
        },
      },
      output: RESULT,
      async execute(args, exec) {
        try {
          if (!args || typeof args !== 'object') return FAILURE
          if (args.operation === WRITE) {
            if (Object.keys(args).some(key => !WRITE_KEYS.includes(key))) return FAILURE
            if (typeof args.target !== 'string' || !args.target) return FAILURE
            if (args.mode !== undefined && !MODES.includes(args.mode)) return FAILURE
            return await writeResult(args, exec, store)
          }
          if (Object.keys(args).some(key => !['reference', 'operation'].includes(key))) return FAILURE
          return await store.process(sessionOf(exec), args.reference, args.operation)
        } catch { return FAILURE }
      },
    },
  ]
}
