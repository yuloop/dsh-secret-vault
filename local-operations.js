/** Closed deterministic operations. No evaluation, templates, shell or networking. */
export const OPERATIONS = Object.freeze([
  'copy', 'trim_edges', 'normalize_newlines', 'json_pretty', 'json_compact', 'dedupe_lines',
])

function formatJson(text, pretty) {
  JSON.parse(text) // syntax validation only; never stringify parsed numbers/duplicate keys
  const tokens = text.match(/"(?:\\.|[^"\\])*"|true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|[{}\[\],:]/g)
  if (!pretty) return tokens.join('')
  let depth = 0, output = ''
  const newline = () => `\n${'  '.repeat(depth)}`
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i]
    if (token === '{' || token === '[') {
      output += token; depth++
      if (!['}', ']'].includes(tokens[i + 1])) output += newline()
    } else if (token === '}' || token === ']') {
      depth--
      if (!['{', '['].includes(tokens[i - 1])) output += newline()
      output += token
    } else if (token === ',') output += ',' + newline()
    else if (token === ':') output += ': '
    else output += token
  }
  return output
}

export function transformLocally(text, operation) {
  switch (operation) {
    case 'copy': return text
    case 'trim_edges': return text.trim()
    case 'normalize_newlines': return text.replace(/\r\n?/g, '\n')
    case 'json_pretty': return formatJson(text, true)
    case 'json_compact': return formatJson(text, false)
    case 'dedupe_lines': return [...new Set(text.split(/\r?\n/))].join('\n')
    default: throw new Error('PRIVATE_OPERATION_FAILED')
  }
}
