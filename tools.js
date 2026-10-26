/** Model-facing surface: fixed operations and opaque references only. */
import { OPERATIONS } from './local-operations.js'

const FAILURE = Object.freeze({ ok: false, status: 'operation_failed' })
const RESULT = {
  schema: { type: 'object' },
  render: (_args, result) => [{ type: 'text', text: JSON.stringify(result) }],
}

function sessionOf(exec) {
  return exec?.agent?.id || exec?.agent?.session?.id
}

export function createTools(store) {
  return [
    {
      name: 'private_local_status',
      description: '列出本会话私密临时文件的随机引用和已用状态。不读取或返回正文。',
      parameters: { type: 'object', properties: {}, additionalProperties: false }, output: RESULT,
      async execute(_args, exec) {
        try {
          const owner = sessionOf(exec)
          return { ok: true, status: 'local_only', locked: store.isLocked(owner), entries: store.list(owner) }
        } catch { return FAILURE }
      },
    },
    {
      name: 'private_local_process',
      description: '在宿主本地执行固定格式操作，结果保存在新的私密临时文件；仅返回状态和路径，不返回正文、摘要、指纹或解析错误。不能执行代码、shell、联网或语义分析。',
      parameters: {
        type: 'object', additionalProperties: false, required: ['reference', 'operation'],
        properties: {
          reference: { type: 'string', description: '本会话临时文件的随机 ID 或完整路径。禁止使用 read 读取正文。' },
          operation: { type: 'string', enum: OPERATIONS, description: 'copy 原样复制；trim_edges 去首尾空白；normalize_newlines 统一换行；json_pretty/json_compact 格式化 JSON；dedupe_lines 按整行去重。只有明确要求时才选择对应操作；不自动猜测内容格式。' },
        },
      },
      output: RESULT,
      async execute(args, exec) {
        try {
          if (!args || Object.keys(args).some(k => !['reference', 'operation'].includes(k))) return FAILURE
          return await store.process(sessionOf(exec), args.reference, args.operation)
        } catch { return FAILURE }
      },
    },
  ]
}
