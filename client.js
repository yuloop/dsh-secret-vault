/* Private bytes stay out of chat. This UI inserts and verifies ONLY random file references. */
window.__ModuleLoader__.load({
  id: 'dsh-secret-vault',
  factory(require) {
    const R = require('react'), h = R.createElement
    const API = '/api/secret-vault', NS = 'private-local-v4'
    const diagnostic = { request: null, insertion: null, phase: 'unknown' }
    const dicts = {
      zh: {
        title: '私密临时内容', close: '关闭', input: '内容', save: '保存并插入', busy: '保存中…',
        insert: '插入路径', used: '标记用完', files: '已保存的临时文件', details: '说明与安全边界',
        subtitle: '原文留在本机，只有文件路径进入会话。', placeholder: '粘贴需要在本地处理的内容…',
        boundary: '正文留在本机、不进聊天；本会话的工具照常可用。',
        limits: '插件不执行任意代码、不联网。其他 root 进程或插件仍可读本地文件；这不是操作系统级隔离。模型也不会收到正文，且任何点名存储路径的调用都会被拒绝。',
        cleanup: '每日北京时间 04:00 清理已用文件；未用文件满 24 小时后在下一次清理删除。你也可以随时手动删除单个文件，删除后无法恢复。',
        transport: '当前入口不支持私密保存。请使用 HTTPS 或本机回环地址。',
        idle: '当前会话正在运行，请等回复结束后再保存。',
        failure: '操作失败，内容未插入会话。请重试。', inserting: '文件已保存，正在确认路径插入…',
        retry: '文件已保存，但路径未成功插入。可以重试插入或复制路径。',
        saved: '待使用', processed: '待清理', done: '已标记用完', copy: '复制路径',
        copied: '路径已复制。请粘贴到会话输入框。', copyFailed: '复制失败，请选中下方路径手动复制。',
        copiedFallback: '路径没插进输入框，已复制到剪贴板，直接粘贴即可。模型也能自己从面板取到句柄，不插也能用。',
        decomposed: '已自动拆解：',
        remove: '删除', confirmRemove: '确认删除', cancel: '取消',
        removed: '文件已删除，无法恢复。', removeFailed: '删除失败，文件可能仍在。请重试。',
        release: '清理完成后恢复普通工具', released: '本会话已恢复普通工具。',
      },
      en: {
        title: 'Private temporary content', close: 'Close', input: 'Content', save: 'Save and insert', busy: 'Saving…',
        insert: 'Insert path', used: 'Mark used', files: 'Saved temporary files', details: 'Details and security',
        subtitle: 'Content stays on this host. Only the file path enters chat.', placeholder: 'Paste content for local processing…',
        boundary: 'The body stays on this host and out of chat; this session keeps its tools.',
        limits: 'No arbitrary code, network requests or semantic analysis. Other root processes/plugins can still read local files. This is not OS isolation.',
        cleanup: 'Daily cleanup at 04:00 Asia/Shanghai removes used files and unused files older than 24 hours. You can also delete a single file at any time; deletion cannot be undone.',
        transport: 'Private saving requires HTTPS or loopback.', idle: 'Wait until the current session finishes running before saving.',
        failure: 'Operation failed; no content was inserted into chat.', inserting: 'File saved; confirming path insertion…',
        retry: 'File saved, but the path was not inserted. Retry insertion or copy the path.',
        saved: 'Pending', processed: 'Awaiting cleanup', done: 'Marked used', copy: 'Copy path',
        copied: 'Path copied. Paste it into the composer.', copyFailed: 'Copy failed. Select and copy the path below.',
        copiedFallback: 'Not inserted into the composer; the path is on your clipboard. The model can also read the handle itself, so insertion is optional.',
        decomposed: 'Decomposed: ',
        remove: 'Delete', confirmRemove: 'Confirm delete', cancel: 'Cancel',
        removed: 'File deleted; it cannot be recovered.', removeFailed: 'Delete failed; the file may still exist. Retry.',
        release: 'Restore tools after cleanup', released: 'Ordinary tools restored.',
      },
    }
    const css = `
      .private-local-trigger {display:inline-flex;align-items:center;justify-content:center;box-sizing:border-box;flex:0 0 32px;width:32px;height:32px;padding:0;border:0;border-radius:8px;background:transparent;color:var(--dsw-alias-label-secondary);cursor:pointer;vertical-align:middle}
      .private-local-trigger:hover,.private-local-trigger[aria-expanded=true] {background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-primary)}
      .private-local-trigger svg {display:block;width:18px;height:18px}
      .private-local-trigger:focus-visible,.private-local-panel :focus-visible {outline:2px solid var(--dsw-alias-brand-primary);outline-offset:2px}
      .private-local-panel {position:fixed;inset:auto;margin:0;box-sizing:border-box;width:min(400px,calc(100vw - 24px));max-height:calc(100dvh - 24px);padding:0;border:1px solid var(--dsw-alias-border-l2);border-radius:12px;background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);font:inherit;font-size:13px;line-height:1.5;overflow:hidden;pointer-events:auto;z-index:1000}
      .private-local-panel:popover-open,.private-local-panel[data-fallback=true] {display:flex;flex-direction:column}
      .private-local-panel::backdrop {background:transparent}
      .private-local-panel .pl-header {display:flex;align-items:center;gap:8px;padding:14px 16px 8px;flex:none}
      .private-local-panel h2 {flex:1;margin:0;font-size:14px;font-weight:600;line-height:1.4}
      .private-local-panel p {margin:6px 0;font-size:12px;color:var(--dsw-alias-label-secondary)}
      .private-local-panel .pl-body {min-height:0;overflow:auto;overscroll-behavior:contain;padding:0 16px 12px}
      .private-local-panel label {display:block;margin:12px 0 6px;font-weight:500}
      .private-local-panel textarea {display:block;box-sizing:border-box;width:100%;min-height:128px;max-height:28vh;resize:vertical;padding:10px;border:1px solid var(--dsw-alias-border-l1);border-radius:8px;background:var(--dsw-alias-bg-base);color:inherit;font:inherit;line-height:1.5}
      .private-local-panel textarea::placeholder {color:var(--dsw-alias-label-secondary)}
      .private-local-panel button {display:inline-flex;align-items:center;justify-content:center;box-sizing:border-box;min-height:28px;padding:5px 10px;font:inherit;font-size:12px;border:1px solid var(--dsw-alias-border-l1);border-radius:7px;background:transparent;color:inherit;cursor:pointer;white-space:nowrap}
      .private-local-panel button:hover {background:var(--dsw-alias-bg-layer-2)}
      .private-local-panel button:disabled,.private-local-panel textarea:disabled {opacity:.5;cursor:not-allowed}
      .private-local-panel .pl-close {width:24px;min-height:24px;padding:0;border:0;color:var(--dsw-alias-label-secondary)}
      .private-local-panel .pl-close svg {width:14px;height:14px}
      .private-local-panel .pl-footer {flex:none;display:flex;justify-content:flex-end;padding:10px 16px;border-top:1px solid var(--dsw-alias-border-l1)}
      .private-local-panel .pl-primary {background:var(--dsw-alias-brand-primary);color:var(--dsw-alias-bg-base);border-color:var(--dsw-alias-brand-primary);min-height:32px;padding:6px 14px}
      .private-local-panel .pl-primary:hover {background:var(--dsw-alias-brand-primary);opacity:.9}
      .private-local-panel .pl-notice {overflow-wrap:anywhere;color:var(--dsw-alias-state-warn-primary)}
      .private-local-panel .pl-shape {color:var(--dsw-alias-label-secondary);font-size:11px;overflow-wrap:anywhere}
      .private-local-panel .pl-warning {color:var(--dsw-alias-state-warn-primary)}
      .private-local-panel details {margin-top:12px;font-size:12px;color:var(--dsw-alias-label-secondary)}
      .private-local-panel summary {cursor:pointer;padding:3px 0}
      .private-local-panel .pl-entry {padding:8px 0;border-top:1px solid var(--dsw-alias-border-l1)}
      .private-local-panel code {display:block;font-size:11px;overflow-wrap:anywhere;color:var(--dsw-alias-label-secondary)}
      .private-local-panel .pl-actions {display:flex;gap:6px;margin-top:6px;justify-content:flex-end;flex-wrap:wrap}
      .private-local-panel .pl-danger {color:var(--dsw-alias-state-error-primary);border-color:var(--dsw-alias-state-error-primary)}
      .private-local-panel .pl-danger:hover {background:var(--dsw-alias-interactive-bg-hover-danger);color:var(--dsw-alias-state-error-primary)}
      .private-local-panel .pl-path {box-sizing:border-box;width:100%;font:inherit;font-size:11px;padding:6px;border:1px solid var(--dsw-alias-border-l1);border-radius:6px;color:inherit;background:var(--dsw-alias-bg-base)}
      @media(max-width:480px) {.private-local-panel textarea {font-size:16px;min-height:112px}}
    `
    const secure = () => location.protocol === 'https:' || ['localhost', '127.0.0.1', '[::1]'].includes(location.hostname)
    async function post(action, body) {
      if (!secure()) throw new Error('transport')
      const r = await fetch(`${API}/${action}`, { method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
      diagnostic.request = { action, status: r.status }
      const data = await r.json()
      if (!r.ok || !data.ok) throw new Error(data.status === 'session_must_be_idle' ? 'idle' :
        data.status === 'local_or_https_required' ? 'transport' : 'failure')
      return data
    }
    function KeyIcon() {
      return h('svg', { width: 18, height: 18, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor',
        strokeWidth: 1.7, strokeLinecap: 'round', strokeLinejoin: 'round', 'aria-hidden': true, focusable: 'false' },
      h('circle', { cx: 8, cy: 8, r: 4.5 }), h('path', { d: 'M11.2 11.2 20 20m-4-4 2-2m0 4 2-2' }))
    }
    function CloseIcon() {
      return h('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 1.8,
        strokeLinecap: 'round', 'aria-hidden': true }, h('path', { d: 'm6 6 12 12M18 6 6 18' }))
    }
    function createSurface() {
      let value = null, timeout
      const listeners = new Set()
      const publish = next => { value = next; for (const fn of listeners) fn() }
      const close = () => { clearTimeout(timeout); publish(null) }
      return {
        getSnapshot: () => value, subscribe: fn => { listeners.add(fn); return () => listeners.delete(fn) },
        close, open: next => publish(next),
        insert(reference, fresh, rejected) {
          const target = value
          try {
            const actions = target?.inputActions
            const text = ` ${reference} `
            const span = fresh ? actions.captureInsertion() : target.span
            // A span captured before the popup opened is the usual rejection cause, so retry
            // once against the current draft instead of reporting a failure we can avoid.
            if (!actions.insertText(text, span) && !actions.insertText(text, actions.captureInsertion())) {
              diagnostic.insertion = 'rejected'; return false
            }
            diagnostic.insertion = 'accepted_unconfirmed'
            publish({ ...target, pendingReference: reference })
            clearTimeout(timeout)
            timeout = setTimeout(() => {
              if (value?.pendingReference === reference) {
                diagnostic.insertion = 'unconfirmed'; publish({ ...value, pendingReference: null }); rejected()
              }
            }, 1000)
            return true
          } catch { diagnostic.insertion = 'unavailable'; return false }
        },
      }
    }
    function Entry({ entry, state, t }) {
      const [confirm, setConfirm] = R.useState(false)
      return h('div', { className: 'pl-entry', key: entry.id },
        h('code', null, entry.id), h('span', null, t(entry.used ? 'processed' : 'saved')),
        entry.summary ? h('span', { className: 'pl-shape' }, entry.summary) : null,
        h('div', { className: 'pl-actions' },
          h('button', { type: 'button', disabled: state.busy, onClick: () => state.insert(entry, true) }, t('insert')),
          h('button', { type: 'button', disabled: state.busy || entry.used, onClick: () => state.run('used', entry.path) }, t('used')),
          confirm ? h(R.Fragment, null,
            h('button', { type: 'button', className: 'pl-danger', disabled: state.busy,
              onClick: () => { setConfirm(false); state.run('delete', entry.path) } }, t('confirmRemove')),
            h('button', { type: 'button', disabled: state.busy, onClick: () => setConfirm(false) }, t('cancel')))
            : h('button', { type: 'button', disabled: state.busy, onClick: () => setConfirm(true) }, t('remove'))))
    }
    function Entries({ state, t }) {
      if (!state.entries.length) return null
      return h('details', null, h('summary', null, `${t('files')} (${state.entries.length})`),
        state.entries.map(e => h(Entry, { key: e.id, entry: e, state, t })))
    }
    function Body({ state, t }) {
      return h('div', { className: 'pl-body' },
        h('p', null, t('subtitle')),
        !secure() ? h('p', { role: 'alert', className: 'pl-warning' }, t('transport')) : null,
        h('label', { htmlFor: 'private-local-text' }, t('input')),
        h('textarea', { id: 'private-local-text', ref: state.input, disabled: !secure() || state.busy,
          placeholder: t('placeholder'), autoComplete: 'off', spellCheck: false, autoCapitalize: 'off', autoCorrect: 'off' }),
        h('p', null, t('boundary')),
        state.notice ? h('p', { role: 'status', className: 'pl-notice' }, t(state.notice)) : null,
        state.shapeText ? h('p', { className: 'pl-shape' }, `${t('decomposed')}${state.shapeText}`) : null,
        state.pending && state.notice !== 'inserting' ? h('div', null,
          h('input', { className: 'pl-path', readOnly: true, value: `@${state.pending.path}`, 'aria-label': t('insert'),
            onFocus: e => e.target.select() }),
          h('div', { className: 'pl-actions' },
            h('button', { type: 'button', disabled: state.busy, onClick: () => state.insert(state.pending, true) }, t('insert')),
            h('button', { type: 'button', onClick: state.copy }, t('copy')))) : null,
        h(Entries, { state, t }),
        h('details', null, h('summary', null, t('details')), h('p', null, t('limits')), h('p', null, t('cleanup'))),
        state.entries.length === 0 && state.locked ? h('button', { type: 'button', disabled: state.busy,
          onClick: () => state.run('release') }, t('release')) : null)
    }
    function usePrivateForm(surface, modal) {
      const { sessionId } = surface, input = R.useRef(null), alive = R.useRef(true)
      const [entries, setEntries] = R.useState([]), [locked, setLocked] = R.useState(false)
      const [busy, setBusy] = R.useState(false), [notice, setNotice] = R.useState(''), [pending, setPending] = R.useState(null)
      const [shapeText, setShapeText] = R.useState('')
      const report = e => { if (alive.current) setNotice(['idle', 'transport'].includes(e.message) ? e.message : 'failure') }
      const refresh = async () => {
        const d = await post('list', { sessionId }); if (alive.current) { setEntries(d.entries); setLocked(d.locked) }
      }
      R.useEffect(() => {
        alive.current = true; if (secure()) refresh().catch(report)
        const field = input.current
        return () => { alive.current = false; if (field) field.value = '' }
      }, [sessionId])
      function insert(entry, fresh = false) {
        setPending(entry)
        const reject = () => { if (alive.current) setNotice('retry') }
        if (modal.insert(`@${entry.path}`, fresh, reject)) { setNotice('inserting'); return }
        // Insertion is only a convenience: the model can read its handle from
        // private_local_status, so fall back to the clipboard instead of a dead end.
        setNotice('retry')
        navigator.clipboard?.writeText(`@${entry.path}`).then(
          () => { if (alive.current) setNotice('copiedFallback') }, () => {})
      }
      async function run(action, reference) {
        setBusy(true)
        try { await post(action, { sessionId, ...(reference ? { reference } : {}) });
          if (alive.current) {
            setNotice(action === 'release' ? 'released' : action === 'delete' ? 'removed' : 'done')
            if (action === 'delete' && pending && pending.path === reference) setPending(null)
            await refresh()
          } }
        catch (e) { if (alive.current) setNotice(['idle', 'transport'].includes(e.message) ? e.message :
          action === 'delete' ? 'removeFailed' : 'failure') }
        finally { if (alive.current) setBusy(false) }
      }
      async function save() {
        const field = input.current; if (!field?.value) return
        setBusy(true)
        try {
          const data = await post('save', { sessionId, value: field.value }); field.value = ''
          if (!alive.current) return
          setEntries(previous => [data.entry, ...previous.filter(e => e.id !== data.entry.id)])
          setLocked(true); setShapeText(data.shapeLine ?? ''); insert(data.entry)
        } catch (e) { report(e) } finally { if (alive.current) setBusy(false) }
      }
      async function copy() {
        try { await navigator.clipboard.writeText(`@${pending.path}`); if (alive.current) setNotice('copied') }
        catch { if (alive.current) setNotice('copyFailed') }
      }
      return { input, entries, locked, busy, notice, pending, shapeText, run, save, insert, copy }
    }
    function placePanel(node, trigger) {
      const anchor = trigger.getBoundingClientRect(), size = node.getBoundingClientRect()
      const width = window.innerWidth, height = window.visualViewport?.height || window.innerHeight
      node.style.left = `${Math.max(12, Math.min(anchor.left, width - size.width - 12))}px`
      const above = anchor.top - size.height - 10
      const below = anchor.bottom + 10
      node.style.top = `${Math.max(12, Math.min(above >= 12 ? above : below, height - size.height - 12))}px`
    }
    function Panel({ surface, modal, t }) {
      const panel = R.useRef(null), state = usePrivateForm(surface, modal)
      R.useLayoutEffect(() => {
        const node = panel.current, trigger = surface.trigger
        if (typeof node.showPopover === 'function') node.showPopover()
        else node.dataset.fallback = 'true'
        const position = () => { if (trigger.isConnected) placePanel(node, trigger) }
        const outside = e => { if (!node.contains(e.target) && !trigger.contains(e.target)) modal.close() }
        const toggled = e => { if (e.newState === 'closed') modal.close() }
        position(); node.querySelector('textarea:not(:disabled)')?.focus({ preventScroll: true })
        const resize = new ResizeObserver(position); resize.observe(node)
        window.addEventListener('resize', position); document.addEventListener('pointerdown', outside)
        document.addEventListener('scroll', position, true); node.addEventListener('toggle', toggled)
        return () => {
          resize.disconnect(); window.removeEventListener('resize', position); node.removeEventListener('toggle', toggled)
          document.removeEventListener('pointerdown', outside); document.removeEventListener('scroll', position, true)
          if (typeof node.hidePopover === 'function' && node.matches(':popover-open')) node.hidePopover()
          if (trigger.isConnected) trigger.focus({ preventScroll: true })
        }
      }, [surface.sessionId, surface.trigger, modal])
      return h('section', { ref: panel, id: 'private-local-panel', className: 'private-local-panel', popover: 'auto',
        role: 'dialog', 'aria-labelledby': 'private-local-title',
        onKeyDown: e => { e.stopPropagation(); if (e.key === 'Escape') modal.close() } },
        h('header', { className: 'pl-header' }, h('h2', { id: 'private-local-title' }, t('title')),
          h('button', { type: 'button', className: 'pl-close', onClick: modal.close, 'aria-label': t('close') }, h(CloseIcon))),
        h(Body, { state, t }), h('footer', { className: 'pl-footer' },
          h('button', { type: 'button', className: 'pl-primary', disabled: state.busy || !secure(),
            onClick: state.save }, t(state.busy ? 'busy' : 'save'))))
    }
    function ModalLayer({ modal, locale }) {
      const surface = R.useSyncExternalStore(modal.subscribe, modal.getSnapshot)
      R.useSyncExternalStore(fn => locale.subscribe(fn), () => locale.getSnapshot())
      return h(R.Fragment, null, h('style', null, css), surface ?
        h(Panel, { key: surface.sessionId, surface, modal, t: locale.bind(NS) }) : null)
    }
    function Control({ sessionId, inputActions, useInput, locale, modal }) {
      const trigger = R.useRef(null), surface = R.useSyncExternalStore(modal.subscribe, modal.getSnapshot)
      R.useSyncExternalStore(fn => locale.subscribe(fn), () => locale.getSnapshot())
      const phase = useInput(s => s.phase)
      const confirmed = useInput(s => Boolean(surface?.pendingReference && s.draft.includes(surface.pendingReference)))
      const t = locale.bind(NS), open = surface?.sessionId === sessionId
      R.useEffect(() => { diagnostic.phase = phase }, [phase])
      R.useEffect(() => {
        if (!open || !confirmed || !surface.pendingReference) return
        inputActions.persistDraft(); diagnostic.insertion = 'confirmed'; modal.close()
      }, [confirmed, open, surface, inputActions, modal])
      R.useEffect(() => {
        const node = trigger.current
        return () => { if (modal.getSnapshot()?.trigger === node) modal.close() }
      }, [sessionId, modal])
      function openPanel() {
        if (open) return modal.close()
        const span = inputActions.captureInsertion() // capture before popup steals editor focus
        modal.open({ sessionId, inputActions, span, trigger: trigger.current })
      }
      return h(R.Fragment, null, h('style', null, css), h('button', { ref: trigger, type: 'button',
        className: 'private-local-trigger', title: t('title'), 'aria-label': t('title'), 'aria-expanded': open,
        'aria-haspopup': 'dialog', 'aria-controls': 'private-local-panel',
        onMouseDown: e => e.preventDefault(), onClick: openPanel }, h(KeyIcon)))
    }
    function uiStatus() {
      const node = document.querySelector('.private-local-panel')
      const trigger = document.querySelector('.private-local-trigger')
      const style = trigger ? getComputedStyle(trigger) : null
      const r = node?.getBoundingClientRect()
      return { version: '4.3.0', popupOpen: Boolean(node), request: diagnostic.request, insertion: diagnostic.insertion,
        phase: diagnostic.phase, geometry: r ? { width: r.width, height: r.height, x: r.x, y: r.y } : null,
        colors: style ? { background: style.getPropertyValue('--dsw-alias-bg-overlay'),
          base: style.getPropertyValue('--dsw-alias-bg-base'), layer: style.getPropertyValue('--dsw-alias-bg-layer-1'),
          nested: style.getPropertyValue('--dsw-alias-bg-layer-2'), text: style.getPropertyValue('--dsw-alias-label-primary'),
          accent: style.getPropertyValue('--dsw-alias-brand-primary') } : null }
    }
    return {
      inject: ['slots', 'locale'],
      apply(ctx) {
        const modal = createSurface()
        ctx.effect(() => () => modal.close())
        for (const [lang, dict] of Object.entries(dicts)) ctx.effect(() => ctx.locale.register(NS, lang, dict))
        ctx.slots.inject('conversation.input.left', () => ctx.slots.register({
          name: 'conversation.input.left', id: 'dsh-secret-vault', order: 20,
          label: () => ctx.locale.bind(NS)('title'),
        }, props => h(Control, { ...props, locale: ctx.locale, modal })))
        ctx.slots.inject('shell.overlay', () => ctx.slots.register({ name: 'shell.overlay', id: 'private-local-modal', order: 80 },
          () => h(ModalLayer, { modal, locale: ctx.locale })))
        ctx.inject(['cordisInspect'], child => child.effect(() => child.cordisInspect.register({
          manifest: { id: 'PrivateLocalUI', description: 'Read-only private popup geometry and operation status. Never reads text, paths or drafts.',
            methods: [{ name: 'status', description: 'Return only version, UI geometry, HTTP status and insertion confirmation.',
              inputSchema: { type: 'object', properties: {}, additionalProperties: false },
              outputSchema: { description: 'Content-free local UI diagnostics.' } },
              { name: 'transport', description: 'Read-only check of the current browser-to-host list route. Returns status only; never consumes response content.',
                inputSchema: { type: 'object', properties: {}, additionalProperties: false },
                outputSchema: { description: 'HTTP status only; 409 is expected while the requesting agent is running.' } }] },
          query: async (method, _input, context) => {
            if (method === 'status') return uiStatus()
            const response = await fetch(`${API}/list`, { method: 'POST', credentials: 'same-origin', cache: 'no-store',
              headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sessionId: context.sessionId }) })
            await response.body?.cancel()
            return { status: response.status, expectedWhileRunning: 409 }
          },
        })))
      },
    }
  },
})
