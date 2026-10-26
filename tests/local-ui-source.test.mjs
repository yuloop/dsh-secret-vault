/** Source-contract regression checks only; not browser interaction or visual tests. */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
const client = await readFile(new URL('../client.js', import.meta.url), 'utf8')
const pkg = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'))

test('UI source: toolbar icon uses a fixed-size SVG', () => {
  assert(!client.includes('⌑'))
  assert.match(client, /function KeyIcon\(\)/)
  assert.match(client, /h\('svg', \{ width: 18, height: 18/)
  assert.match(client, /\.private-local-trigger \{[^}]*width:32px;height:32px;padding:0;border:0/)
})

test('UI source: compact popup uses shell overlay and non-modal top layer', () => {
  assert(pkg.dsh.client.inject.includes('@deepseek-ai/dsh-client-ui-layout'))
  assert.match(client, /name: 'shell.overlay', id: 'private-local-modal'/)
  assert.match(client, /popover: 'auto'/)
  assert.match(client, /node\.showPopover\(\)/)
  assert(!client.includes('showModal'))
  assert.match(client, /width:min\(400px,calc\(100vw - 24px\)\)/)
  assert.match(client, /\.private-local-panel \{[^}]*background:var\(--dsw-alias-bg-layer-1\)/)
  assert.match(client, /getBoundingClientRect/)
  assert.match(client, /Math\.max\(12, Math\.min/)
})

test('UI source: insertion must be accepted AND confirmed in the semantic draft', () => {
  assert.match(client, /const span = inputActions.captureInsertion\(\) \/\/ capture before popup/)
  assert.match(client, /if \(!actions.insertText/)
  assert.match(client, /s.draft.includes\(surface.pendingReference\)/)
  assert.match(client, /inputActions.persistDraft\(\); diagnostic.insertion = 'confirmed'; modal.close\(\)/)
  assert.match(client, /onClick: \(\) => state.insert\(entry, true\)/)
  assert.match(client, /if \(modal\.insert\(`@\$\{entry\.path\}`, fresh, reject\)\)/)
  assert(!client.includes('setDraft('), 'must not overwrite existing text or reference chips')
})

test('UI source: a rejected insertion retries once, then falls back to the clipboard', () => {
  assert.match(client, /!actions\.insertText\(text, actions\.captureInsertion\(\)\)/)
  assert.match(client, /navigator\.clipboard\?\.writeText\(`@\$\{entry\.path\}`\)/)
  assert.match(client, /copiedFallback: '路径没插进输入框/)
  assert.match(client, /copiedFallback: 'Not inserted into the composer/)
})

test('UI source: the user can delete a saved file, with an explicit second confirmation', () => {
  assert.match(client, /function Entry\(\{ entry, state, t \}\)/)
  assert.match(client, /const \[confirm, setConfirm\] = R\.useState\(false\)/)
  assert.match(client, /setConfirm\(false\); state\.run\('delete', entry\.path\)/)
  assert.match(client, /t\('confirmRemove'\)/)
  assert.match(client, /onClick: \(\) => setConfirm\(false\)/, 'cancel button resets the confirmation')
  assert.match(client, /remove: '删除', confirmRemove: '确认删除', cancel: '取消'/)
  assert.match(client, /remove: 'Delete', confirmRemove: 'Confirm delete', cancel: 'Cancel'/)
  assert.match(client, /删除后无法恢复/)
  assert.match(client, /\.pl-danger \{color:var\(--dsw-alias-state-error-primary\)/)
})

test('UI source: diagnostic method reports metadata, never raw input or draft values', () => {
  const status = client.slice(client.indexOf('    function uiStatus()'), client.indexOf('\n    return {\n      inject:'))
  assert(status.includes('geometry'))
  assert(!status.includes('.value'))
  assert(!status.includes('.draft'))
  assert(!status.includes('.path'))
  assert.match(client, /alive.current = false; if \(field\) field.value = ''/)
})
