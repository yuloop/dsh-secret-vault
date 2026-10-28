/**
 * Exit redaction: every tool result leaves the dispatch pipeline with credential-shaped
 * strings masked, whichever tool produced it. A guard cannot cover this — the agent's own
 * `sed`/`grep`/`bash` output is the realistic leak path, and that is a mistake, not an attack.
 */
import { redactBlocks } from './redact.js'

/** Replace text blocks in place when redaction changed them; other blocks pass through. */
function redacted(content) {
  let changed = false
  const blocks = content.map(block => {
    if (block?.type !== 'text' || typeof block.text !== 'string') return block
    const replaced = redactBlocks([block])[0]
    if (replaced?.text === block.text) return block
    changed = true
    return replaced
  })
  return changed ? blocks : null
}

export function registerExitRedaction(ctx) {
  return ctx.effect(() => ctx.on('tools/post-execute', async (_exec, result, next) => {
    const decision = await next()
    // A `value` replacement re-renders through the tool's own render(); only content is text.
    if (decision.kind !== 'accept' || Object.hasOwn(decision, 'value')) return decision
    const content = decision.content ?? result?.content
    if (!Array.isArray(content)) return decision
    const blocks = redacted(content)
    return blocks === null ? decision : { ...decision, content: blocks }
  }, { prepend: true }))
}
