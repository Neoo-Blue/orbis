import { useCallback, useEffect, useRef, useState } from 'react'
import { api, askAssistant } from '../api'
import { usePoll } from '../hooks'
import { Banner, Bar, Dot, Icons, Spinner, useToast } from '../ui'
import { ago, num } from '../format'
import type { AIBrief, ChatTurn, Recommendation } from '../types'
import { uuid } from '../uuid'

interface Bubble {
  id: string
  role: 'user' | 'assistant'
  text: string
  tools: Array<{ tool: string; input?: unknown; result?: string; error?: boolean; pending: boolean }>
  model?: string
}

const SUGGESTIONS = [
  'What is on my network right now?',
  'Anything unusual in the last few hours?',
  'Which device is using the most bandwidth, and what for?',
  'Why is doubleclick.net blocked?',
  'What did the TV talk to overnight?',
  'How many YouTube ads were skipped this week?',
  'When was the network busiest today?',
  'Which countries does my traffic go to?',
  'Explain what port 5353 is and whether I should block it',
  'How do I install the certificate on an iPhone?',
]

export function AssistantPage({ initialQuestion, onConsumed }: { initialQuestion?: string; onConsumed?: () => void } = {}) {
  const [conversation, setConversation] = useState<string>(() => uuid())
  const [bubbles, setBubbles] = useState<Bubble[]>([])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const logRef = useRef<HTMLDivElement>(null)
  const abortRef = useRef<AbortController | null>(null)
  const toast = useToast()

  const { data: status } = usePoll(() => api.status(), 30000)
  const { data: convs, refresh: refreshConvs } = usePoll(() => api.chat.conversations(), 0)
  const { data: models } = usePoll(() => api.ai.models(), 60000)
  const { data: briefs, refresh: refreshBriefs } = usePoll(() => api.ai.briefs(1), 120000)
  const [briefBusy, setBriefBusy] = useState(false)
  const { data: recData, refresh: refreshRecs } = usePoll(() => api.ai.recommendations('open'), 60000)
  const { data: notesData, refresh: refreshNotes } = usePoll(() => api.ai.notes(), 120000)
  const [reviewBusy, setReviewBusy] = useState(false)
  const [decideBusy, setDecideBusy] = useState<string | null>(null)
  const [noteDraft, setNoteDraft] = useState('')
  const [showNotes, setShowNotes] = useState(false)

  const runReview = async () => {
    setReviewBusy(true)
    try {
      const res = await api.ai.runReview()
      toast(res.added.length ? `${res.added.length} new suggestion${res.added.length === 1 ? '' : 's'}` : 'Nothing new to suggest', 'ok')
      refreshRecs()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Review failed', 'err')
    } finally {
      setReviewBusy(false)
    }
  }
  const decide = async (r: Recommendation, decision: 'accept' | 'dismiss') => {
    setDecideBusy(r.id)
    try {
      await api.ai.decide(r.id, decision)
      toast(decision === 'accept'
        ? (r.kind === 'allow' ? `${r.domain} allowed` : r.kind === 'block' ? `${r.domain} blocked` : 'Noted')
        : 'Dismissed, and remembered', 'ok')
      refreshRecs()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not apply that', 'err')
    } finally {
      setDecideBusy(null)
    }
  }
  const addNote = async () => {
    const n = noteDraft.trim()
    if (!n) return
    try {
      await api.ai.addNote(n)
      setNoteDraft('')
      refreshNotes()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not save the note', 'err')
    }
  }

  const aiStatus = (status?.ai ?? {}) as Record<string, unknown>
  const configured = Boolean(aiStatus.configured)
  const canWrite = Boolean(aiStatus.allow_write)
  const activeModel = typeof aiStatus.active_model === 'string' ? aiStatus.active_model : ''
  const briefEvery = typeof aiStatus.brief_enabled === 'boolean' ? aiStatus.brief_enabled : false
  const latestBrief: AIBrief | undefined = briefs?.briefs?.[0]

  const runBrief = async () => {
    setBriefBusy(true)
    try {
      await api.ai.runBrief()
      refreshBriefs()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not write a brief', 'err')
    } finally {
      setBriefBusy(false)
    }
  }

  const scrollToBottom = useCallback(() => {
    requestAnimationFrame(() => {
      const el = logRef.current
      if (el) el.scrollTop = el.scrollHeight
    })
  }, [])

  useEffect(scrollToBottom, [bubbles, scrollToBottom])

  // A question handed over from another page (the simple home's ask box) is
  // sent once, as soon as we know the assistant is configured.
  const fired = useRef(false)
  useEffect(() => {
    if (!initialQuestion || fired.current || !configured) return
    fired.current = true
    onConsumed?.()
    void send(initialQuestion)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialQuestion, configured])

  const loadConversation = async (id: string) => {
    try {
      const { messages } = await api.chat.history(id)
      const out: Bubble[] = []
      for (const m of messages) {
        if (m.role === 'user') {
          out.push({ id: m.id, role: 'user', text: m.content, tools: [] })
        } else if (m.role === 'assistant') {
          const tools: Bubble['tools'] = []
          if (m.tool_calls) {
            try {
              for (const c of JSON.parse(m.tool_calls) as Array<{ name: string; input: unknown }>) {
                tools.push({ tool: c.name, input: c.input, pending: false })
              }
            } catch { /* a corrupt row should not blank the transcript */ }
          }
          out.push({ id: m.id, role: 'assistant', text: m.content, tools, model: m.model })
        } else if (m.role === 'tool') {
          const last = out[out.length - 1]
          if (last?.role === 'assistant') {
            const slot = last.tools.find((t) => t.tool === m.tool_result && !t.result)
            if (slot) slot.result = m.content
          }
        }
      }
      setBubbles(out)
      setConversation(id)
      scrollToBottom()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not load that conversation', 'err')
    }
  }

  const send = async (text: string) => {
    const message = text.trim()
    if (!message || busy) return
    setInput('')
    setBusy(true)

    const userBubble: Bubble = { id: uuid(), role: 'user', text: message, tools: [] }
    const assistantBubble: Bubble = { id: uuid(), role: 'assistant', text: '', tools: [] }
    setBubbles((b) => [...b, userBubble, assistantBubble])

    const controller = new AbortController()
    abortRef.current = controller

    const onTurn = (turn: ChatTurn) => {
      setBubbles((prev) => {
        const next = [...prev]
        const idx = next.findIndex((b) => b.id === assistantBubble.id)
        if (idx < 0) return prev
        const bubble = { ...next[idx], tools: [...next[idx].tools] }

        switch (turn.kind) {
          case 'text':
            bubble.text = bubble.text ? `${bubble.text}\n\n${turn.text ?? ''}` : (turn.text ?? '')
            if (turn.model) bubble.model = turn.model
            break
          case 'tool_call':
            bubble.tools.push({ tool: turn.tool ?? '', input: turn.input, pending: true })
            break
          case 'tool_result': {
            // Match the most recent pending call with this name, so parallel
            // calls to the same tool resolve in order.
            for (let i = bubble.tools.length - 1; i >= 0; i--) {
              if (bubble.tools[i].tool === turn.tool && bubble.tools[i].pending) {
                bubble.tools[i] = {
                  ...bubble.tools[i], result: turn.result, error: turn.is_error, pending: false,
                }
                break
              }
            }
            break
          }
          case 'error':
            bubble.text = bubble.text
              ? `${bubble.text}\n\n${turn.text ?? 'Something went wrong.'}`
              : (turn.text ?? 'Something went wrong.')
            break
        }
        next[idx] = bubble
        return next
      })
      scrollToBottom()
    }

    try {
      const id = await askAssistant(conversation, message, onTurn, controller.signal)
      setConversation(id)
      refreshConvs()
    } catch (e) {
      if (!controller.signal.aborted) {
        toast(e instanceof Error ? e.message : 'The assistant could not be reached', 'err')
      }
    } finally {
      setBusy(false)
      abortRef.current = null
    }
  }

  return (
    <div className="chat">
      <div className="chat-log" ref={logRef}>
        {!configured && (
          <Banner tone="warn">
            <strong style={{ display: 'block', marginBottom: 3 }}>The assistant is not configured</strong>
            Add a provider and API key under Settings → Assistant. Anthropic, OpenAI, OpenRouter
            and a local Ollama are all supported.
          </Banner>
        )}
        {configured && !canWrite && bubbles.length === 0 && (
          <Banner tone="info">
            Read-only mode: the assistant can inspect everything but cannot change the firewall,
            blocklists or device access. Turn on write access in Settings when you trust it to act.
          </Banner>
        )}

        {bubbles.length === 0 ? (
          <div style={{ maxWidth: 760, margin: '5vh auto 0', width: '100%' }}>
            <div style={{ textAlign: 'center', marginBottom: 22 }}>
              <div style={{ fontSize: 17, fontWeight: 560, marginBottom: 6 }}>
                Ask about your network
              </div>
              <div style={{ color: 'var(--text-dim)', fontSize: 13, lineHeight: 1.6 }}>
                The assistant reads the flow table, DNS log, device list, events, rules and the
                YouTube engine, explains why a domain is blocked, places any IP address, and
                answers general networking questions. With write access on, it can also make changes.
              </div>
            </div>

            {configured && (
              <div className="brief" style={{ marginBottom: 20 }}>
                <div className="brief-head">
                  <Dot state={!latestBrief ? 'off' : latestBrief.severity === 'warning' ? 'err' : latestBrief.severity === 'notice' ? 'warn' : 'on'} />
                  <strong>{latestBrief ? latestBrief.headline : 'No network check yet'}</strong>
                  <button className="btn sm" disabled={briefBusy} onClick={runBrief}>
                    {briefBusy ? <><Spinner /> checking…</> : latestBrief ? 'Check now' : 'Run first check'}
                  </button>
                </div>
                {latestBrief ? (
                  <>
                    <div className="brief-body"><Markdown text={latestBrief.body} /></div>
                    <div className="brief-foot">
                      <span>{ago(latestBrief.ts)}</span>
                      <span>·</span>
                      <span>last {latestBrief.hours}h</span>
                      <span>·</span>
                      <span className="mono">{latestBrief.model}</span>
                      {!briefEvery && <span>· scheduled briefs are off (Settings → Assistant)</span>}
                    </div>
                  </>
                ) : (
                  <div className="brief-body">
                    A network check reads the last few hours of traffic, blocks, new devices and node
                    health and writes a short note. {briefEvery ? 'The first scheduled one is on its way.' : 'Turn on scheduled briefs in Settings → Assistant, or run one now.'}
                  </div>
                )}
              </div>
            )}

            {configured && (
              <div className="brief" style={{ marginBottom: 20 }}>
                <div className="brief-head">
                  <Dot state={(recData?.recommendations.length ?? 0) > 0 ? 'warn' : 'on'} />
                  <strong>
                    {recData && recData.recommendations.length > 0
                      ? `${recData.recommendations.length} blocklist suggestion${recData.recommendations.length === 1 ? '' : 's'} waiting`
                      : 'Blocklist specialist: nothing waiting'}
                  </strong>
                  <button className="btn sm" disabled={reviewBusy} onClick={runReview}>
                    {reviewBusy ? <><Spinner /> reviewing…</> : 'Review now'}
                  </button>
                </div>
                {recData && recData.recommendations.length > 0 ? (
                  <div>
                    {recData.recommendations.map((r) => (
                      <div className="rec" key={r.id}>
                        <span className={`kind ${r.kind}`}>{r.kind}</span>
                        <div style={{ minWidth: 0 }}>
                          <div className="domain">{r.domain}</div>
                          <div className="reason">{r.reason}</div>
                          <div className="hint" style={{ fontSize: 11, marginTop: 3 }}>
                            {Math.round(r.confidence * 100)}% sure
                            {r.evidence && 'devices' in r.evidence ? ` · blocked for ${String(r.evidence.devices)} device(s), ${String(r.evidence.lookups)} lookups` : ''}
                            {r.evidence && 'blocked_by' in r.evidence && r.evidence.blocked_by ? ` · by ${String(r.evidence.blocked_by)}` : ''}
                            {' · '}{ago(r.ts)}
                          </div>
                        </div>
                        <div className="actions">
                          <button className="btn sm primary" disabled={decideBusy === r.id} onClick={() => decide(r, 'accept')}>
                            {r.kind === 'allow' ? 'Allow' : r.kind === 'block' ? 'Block' : 'Noted'}
                          </button>
                          <button className="btn sm" disabled={decideBusy === r.id} onClick={() => decide(r, 'dismiss')}>Dismiss</button>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="brief-body">
                    Reviews look at what was blocked, for how many devices and by which list, plus what smart capture
                    wants blocked, and suggest changes. {recData?.review.enabled ? `Scheduled every ${recData.review.interval_hours}h.` : 'Scheduled reviews are off (Settings → Assistant).'}
                  </div>
                )}
                <div className="brief-foot" style={{ justifyContent: 'space-between' }}>
                  <button className="btn sm" onClick={() => setShowNotes((v) => !v)}>
                    {showNotes ? 'Hide' : 'Show'} remembered facts ({notesData?.notes.length ?? 0})
                  </button>
                </div>
                {showNotes && (
                  <div style={{ marginTop: 10, display: 'grid', gap: 8 }}>
                    <div className="hint" style={{ lineHeight: 1.6 }}>
                      Facts the assistant keeps in mind for every answer, brief and review. Tell it "remember that…" in chat, or add one here.
                    </div>
                    {(notesData?.notes ?? []).map((n) => (
                      <div key={n.id} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', fontSize: 12.5 }}>
                        <span style={{ flex: 1 }}>{n.note} <span className="hint" style={{ fontSize: 11 }}>· {n.source}, {ago(n.ts)}</span></span>
                        <button className="btn sm" title="Forget" onClick={async () => { await api.ai.deleteNote(n.id); refreshNotes() }}>Forget</button>
                      </div>
                    ))}
                    <div style={{ display: 'flex', gap: 8 }}>
                      <input className="input" value={noteDraft} placeholder="192.168.50.111 is the NAS; it backs up to Backblaze nightly"
                        onChange={(e) => setNoteDraft(e.target.value)}
                        onKeyDown={(e) => { if (e.key === 'Enter') addNote() }} />
                      <button className="btn" disabled={!noteDraft.trim()} onClick={addNote}>Remember</button>
                    </div>
                  </div>
                )}
              </div>
            )}

            <div className="chat-suggestions" style={{ justifyContent: 'center' }}>
              {SUGGESTIONS.map((s) => (
                <button key={s} className="btn sm" onClick={() => send(s)} disabled={!configured}>{s}</button>
              ))}
            </div>
            {convs && convs.conversations.length > 0 && (
              <div style={{ marginTop: 34 }}>
                <div style={{
                  fontSize: 10.5, letterSpacing: '.11em', textTransform: 'uppercase',
                  color: 'var(--text-faint)', fontWeight: 600, marginBottom: 9,
                }}>Earlier conversations</div>
                <div style={{ display: 'grid', gap: 5 }}>
                  {convs.conversations.slice(0, 8).map((c) => (
                    <button key={c.id} className="nav-item" style={{ width: '100%' }}
                      onClick={() => loadConversation(c.id)}>
                      <span className="truncate" style={{ flex: 1, textAlign: 'left' }}>
                        {c.title || 'Untitled'}
                      </span>
                      <span style={{ fontSize: 11, color: 'var(--text-faint)' }}>{ago(c.last)}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          bubbles.map((b) => <MessageBubble key={b.id} bubble={b} />)
        )}

        {busy && (
          <div className="msg assistant">
            <div className="msg-avatar">AI</div>
            <div className="msg-body" style={{ color: 'var(--text-faint)', fontSize: 12.5 }}>
              <Spinner /> <span style={{ marginLeft: 7 }}>Working…</span>
            </div>
          </div>
        )}
      </div>

      <div className="chat-input">
        <div className="row">
          <textarea
            value={input}
            placeholder={configured ? 'Ask anything about the network…' : 'Configure a provider in Settings first'}
            disabled={!configured}
            onChange={(e) => {
              setInput(e.target.value)
              e.target.style.height = 'auto'
              e.target.style.height = `${Math.min(180, e.target.scrollHeight)}px`
            }}
            onKeyDown={(e) => {
              // Enter sends; Shift+Enter is a newline. Matches every chat
              // surface people already use.
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault()
                send(input)
              }
            }}
          />
          {busy ? (
            <button className="btn danger" onClick={() => abortRef.current?.abort()}>Stop</button>
          ) : (
            <button className="btn primary" disabled={!input.trim() || !configured} onClick={() => send(input)}>
              Send
            </button>
          )}
          {bubbles.length > 0 && (
            <button className="btn" title="Start a new conversation" onClick={() => {
              setBubbles([])
              setConversation(uuid())
            }}><Icons.plus size={14} /></button>
          )}
        </div>
        <div className="chat-status">
          {activeModel && (
            <span>Answering with <span className="mono">{activeModel}</span>
              {models && models.chat_chain.length > 1 ? ` (+${models.chat_chain.length - 1} fallback${models.chat_chain.length > 2 ? 's' : ''})` : ''}
            </span>
          )}
          {models?.openrouter && models.prefer_free && (
            <span title="Free-tier requests used today, all models. Resets at midnight UTC.">
              <Bar value={models.free_today} max={models.free_budget} tone={models.free_today / Math.max(1, models.free_budget) > 0.85 ? 'warn' : undefined} />
              {' '}<span className="mono">{num(models.free_today)}/{num(models.free_budget)}</span> free today
            </span>
          )}
          {canWrite && (
            <span>Write access is on — changes land in the audit log.</span>
          )}
        </div>
      </div>
    </div>
  )
}

function MessageBubble({ bubble }: { bubble: Bubble }) {
  return (
    <div className={`msg ${bubble.role}`}>
      <div className="msg-avatar">{bubble.role === 'user' ? 'You' : 'AI'}</div>
      <div className="msg-body">
        {bubble.tools.map((t, i) => (
          <details key={i} className="tool-call" data-error={t.error ? 'true' : 'false'}>
            <summary>
              {t.pending ? <Spinner /> : t.error ? <Icons.alert size={12} /> : <Icons.check size={12} />}
              <span className="name">{t.tool}</span>
              <span style={{ color: 'var(--text-faint)' }}>
                {t.pending ? 'running…' : t.error ? 'failed' : 'done'}
              </span>
            </summary>
            {t.input !== undefined && Object.keys(t.input as object ?? {}).length > 0 && (
              <pre>{JSON.stringify(t.input, null, 2)}</pre>
            )}
            {t.result && <pre>{t.result}</pre>}
          </details>
        ))}
        {bubble.text && <Markdown text={bubble.text} />}
        {bubble.role === 'assistant' && bubble.model && (
          <div className="msg-meta" title="The model that wrote this answer">{bubble.model}</div>
        )}
      </div>
    </div>
  )
}

/**
 * A deliberately small Markdown renderer. The assistant is instructed to write
 * prose, short lists and the occasional table, so pulling in a full parser
 * (and a sanitizer to go with it) would cost more than it returns.
 */
function Markdown({ text }: { text: string }) {
  const blocks: React.ReactNode[] = []
  const lines = text.split('\n')
  let i = 0
  let key = 0

  const inline = (s: string): React.ReactNode[] => {
    const out: React.ReactNode[] = []
    // Inline code first so bold markers inside code are not consumed.
    const parts = s.split(/(`[^`]+`)/g)
    for (const part of parts) {
      if (part.startsWith('`') && part.endsWith('`') && part.length > 2) {
        out.push(<code key={key++}>{part.slice(1, -1)}</code>)
        continue
      }
      const bolded = part.split(/(\*\*[^*]+\*\*)/g)
      for (const b of bolded) {
        if (b.startsWith('**') && b.endsWith('**') && b.length > 4) {
          out.push(<strong key={key++}>{b.slice(2, -2)}</strong>)
        } else if (b) {
          out.push(<span key={key++}>{b}</span>)
        }
      }
    }
    return out
  }

  while (i < lines.length) {
    const line = lines[i]

    if (line.startsWith('```')) {
      const body: string[] = []
      i++
      while (i < lines.length && !lines[i].startsWith('```')) body.push(lines[i++])
      i++
      blocks.push(<pre key={key++}><code>{body.join('\n')}</code></pre>)
      continue
    }

    if (/^\s*\|.*\|\s*$/.test(line) && i + 1 < lines.length && /^\s*\|[\s:|-]+\|\s*$/.test(lines[i + 1])) {
      const header = splitRow(line)
      i += 2
      const rows: string[][] = []
      while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) rows.push(splitRow(lines[i++]))
      blocks.push(
        <table key={key++}>
          <thead><tr>{header.map((h, hi) => <th key={hi}>{inline(h)}</th>)}</tr></thead>
          <tbody>{rows.map((r, ri) => (
            <tr key={ri}>{r.map((c, ci) => <td key={ci}>{inline(c)}</td>)}</tr>
          ))}</tbody>
        </table>,
      )
      continue
    }

    if (/^\s*[-*]\s+/.test(line)) {
      const items: string[] = []
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*[-*]\s+/, ''))
        i++
      }
      blocks.push(<ul key={key++}>{items.map((it, ii) => <li key={ii}>{inline(it)}</li>)}</ul>)
      continue
    }

    if (/^\s*\d+\.\s+/.test(line)) {
      const items: string[] = []
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*\d+\.\s+/, ''))
        i++
      }
      blocks.push(<ol key={key++}>{items.map((it, ii) => <li key={ii}>{inline(it)}</li>)}</ol>)
      continue
    }

    if (line.trim() === '') { i++; continue }

    const para: string[] = []
    while (i < lines.length && lines[i].trim() !== '' &&
      !/^\s*[-*\d]/.test(lines[i]) && !lines[i].startsWith('```') && !/^\s*\|/.test(lines[i])) {
      para.push(lines[i++])
    }
    blocks.push(<p key={key++}>{inline(para.join(' '))}</p>)
  }

  return <>{blocks}</>
}

function splitRow(line: string): string[] {
  return line.trim().replace(/^\||\|$/g, '').split('|').map((c) => c.trim())
}
