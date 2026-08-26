import { useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Card, Empty, Icons, Loading, Segmented, Stat, Switch, useConfirm, useToast } from '../ui'
import { ago } from '../format'
import type {
  MultiWANConfig, PingResult, ShapingConfig, SpeedResult, StaticRoute, TracerouteHop, WANLink,
} from '../types'

type Tab = 'wan' | 'routes' | 'shaping' | 'portmap' | 'tools'

export function GatewayPage() {
  const [tab, setTab] = useState<Tab>('wan')
  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <div className="toolbar" style={{ marginBottom: 0 }}>
        <Segmented
          value={tab} onChange={setTab}
          options={[
            { value: 'wan', label: 'Uplinks' },
            { value: 'routes', label: 'Routes' },
            { value: 'shaping', label: 'Shaping' },
            { value: 'portmap', label: 'Port mappings' },
            { value: 'tools', label: 'Tools' },
          ]}
        />
      </div>
      {tab === 'wan' && <WAN />}
      {tab === 'routes' && <Routes />}
      {tab === 'shaping' && <Shaping />}
      {tab === 'portmap' && <PortMap />}
      {tab === 'tools' && <Tools />}
    </div>
  )
}

/* ---------- multi-WAN ---------- */

function WAN() {
  const { data, refresh } = usePoll(() => api.wan.status(), 5000)
  const toast = useToast()

  if (!data) return <Loading what="uplinks" />
  const cfg = data.config

  const save = async (next: MultiWANConfig) => {
    try {
      await api.wan.save(next)
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not save', 'err')
    }
  }

  const addLink = () => {
    const link: WANLink = {
      name: `wan${(cfg.links?.length ?? 0) + 1}`,
      enabled: true, interface: '', priority: (cfg.links?.length ?? 0) + 1, weight: 1,
    }
    save({ ...cfg, links: [...(cfg.links ?? []), link] })
  }

  const patchLink = (i: number, patch: Partial<WANLink>) => {
    const links = [...(cfg.links ?? [])]
    links[i] = { ...links[i], ...patch }
    save({ ...cfg, links })
  }

  const removeLink = (i: number) =>
    save({ ...cfg, links: (cfg.links ?? []).filter((_, j) => j !== i) })

  return (
    <>
      <Card
        title="Failover"
        actions={<Switch checked={cfg.enabled} onChange={(v) => save({ ...cfg, enabled: v })}
          label={cfg.enabled ? 'On' : 'Off'} />}
      >
        <div className="hint" style={{ marginBottom: 12 }}>
          Each uplink is probed independently. When the active one stops answering, the default
          route moves to the healthy uplink with the lowest priority number. Probes go out through
          the uplink's own interface, so a link that is down is detected even while another works.
        </div>
        <div className="grid c3" style={{ marginBottom: 12 }}>
          <Stat label="Active uplink" value={data.active || 'none'} tone={data.active ? 'accent' : undefined} />
          <Stat label="Monitor" value={data.running ? 'running' : 'stopped'} />
          <Stat label="Uplinks up"
            value={`${data.links.filter((l) => l.up).length}/${data.links.length}`} />
        </div>

        <div style={{ display: 'grid', gap: 8, opacity: cfg.enabled ? 1 : 0.55 }}>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <label className="field" style={{ flex: '1 1 140px' }}>
              <span>Probe every (s)</span>
              <input className="input" type="number" min={2} value={cfg.interval_seconds}
                onChange={(e) => save({ ...cfg, interval_seconds: Number(e.target.value) })} />
            </label>
            <label className="field" style={{ flex: '1 1 140px' }}>
              <span>Failures to mark down</span>
              <input className="input" type="number" min={1} value={cfg.failures_to_down}
                onChange={(e) => save({ ...cfg, failures_to_down: Number(e.target.value) })} />
            </label>
            <label className="field" style={{ flex: '1 1 140px' }}>
              <span>Successes to mark up</span>
              <input className="input" type="number" min={1} value={cfg.successes_to_up}
                onChange={(e) => save({ ...cfg, successes_to_up: Number(e.target.value) })} />
            </label>
          </div>
          <Switch checked={cfg.load_balance} onChange={(v) => save({ ...cfg, load_balance: v })}
            label="Load balance across healthy uplinks" />
          <div className="hint" style={{ marginTop: -4 }}>
            Off by default. Balancing splits new connections across uplinks, which changes your
            source address between them and logs you out of anything that pins a session to one.
          </div>
        </div>
      </Card>

      <Card title="Uplinks" actions={
        <button className="btn sm" onClick={addLink}><Icons.plus size={13} /> Add uplink</button>
      }>
        {(cfg.links ?? []).length === 0 ? (
          <Empty title="No uplinks defined">
            Add one per WAN connection. The lowest priority number wins while it is healthy.
          </Empty>
        ) : (
          <div style={{ display: 'grid', gap: 12 }}>
            {(cfg.links ?? []).map((l, i) => {
              const st = data.links.find((s) => s.name === l.name)
              return (
                <div key={i} style={{ border: '1px solid var(--line-soft)', borderRadius: 8, padding: 11 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 9 }}>
                    <span className={`dot ${st?.active ? 'on' : st?.up ? 'warn' : 'off'}`} />
                    <strong style={{ fontSize: 13 }}>{l.name}</strong>
                    <span style={{ fontSize: 11, color: 'var(--text-faint)' }}>
                      {st
                        ? `${st.up ? 'up' : 'down'}${st.active ? ' · carrying traffic' : ''}` +
                          `${st.latency_ms ? ` · ${st.latency_ms.toFixed(0)}ms` : ''}` +
                          `${st.loss_percent ? ` · ${st.loss_percent.toFixed(0)}% loss` : ''}`
                        : 'not probed yet'}
                    </span>
                    <div className="spacer" style={{ flex: 1 }} />
                    <Switch checked={l.enabled} onChange={(v) => patchLink(i, { enabled: v })} label="" />
                    <button className="btn sm" onClick={() => removeLink(i)}><Icons.trash size={13} /></button>
                  </div>
                  {st?.last_error && (
                    <div style={{ fontSize: 11, color: 'var(--amber)', marginBottom: 8 }}>{st.last_error}</div>
                  )}
                  <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                    <label className="field" style={{ flex: '1 1 120px' }}>
                      <span>Name</span>
                      <input className="input" value={l.name}
                        onChange={(e) => patchLink(i, { name: e.target.value })} />
                    </label>
                    <label className="field" style={{ flex: '1 1 120px' }}>
                      <span>Interface</span>
                      <input className="input mono" placeholder="eth0" value={l.interface}
                        onChange={(e) => patchLink(i, { interface: e.target.value })} />
                    </label>
                    <label className="field" style={{ flex: '1 1 120px' }}>
                      <span>Gateway (optional)</span>
                      <input className="input mono" placeholder="auto" value={l.gateway ?? ''}
                        onChange={(e) => patchLink(i, { gateway: e.target.value })} />
                    </label>
                    <label className="field" style={{ flex: '0 0 90px' }}>
                      <span>Priority</span>
                      <input className="input" type="number" value={l.priority}
                        onChange={(e) => patchLink(i, { priority: Number(e.target.value) })} />
                    </label>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </Card>
    </>
  )
}

/* ---------- static routes ---------- */

function Routes() {
  const { data, refresh } = usePoll(() => api.routes.list(), 0)
  const toast = useToast()
  const confirm = useConfirm()
  const [draft, setDraft] = useState<StaticRoute>({
    name: '', enabled: true, destination: '', gateway: '', interface: '',
  })

  const add = async () => {
    try {
      await api.routes.save(draft)
      setDraft({ name: '', enabled: true, destination: '', gateway: '', interface: '' })
      refresh()
      toast('Route saved', 'ok')
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not save', 'err')
    }
  }

  const remove = async (name: string) => {
    if (!(await confirm(`Delete route "${name}"?`))) return
    try {
      await api.routes.remove(name)
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not delete', 'err')
    }
  }

  if (!data) return <Loading what="routes" />

  return (
    <>
      <Card title="Static routes">
        {data.configured.length === 0 ? (
          <Empty title="No static routes">
            Add one to reach a network that sits behind another router.
          </Empty>
        ) : (
          <div style={{ display: 'grid', gap: 8 }}>
            {data.configured.map((r) => (
              <div key={r.name} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span className={`dot ${r.enabled ? 'on' : 'off'}`} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 13 }}>{r.name}</div>
                  <div className="mono" style={{ fontSize: 11, color: 'var(--text-faint)' }}>
                    {r.destination}
                    {r.gateway ? ` via ${r.gateway}` : ''}
                    {r.interface ? ` dev ${r.interface}` : ''}
                    {r.metric ? ` metric ${r.metric}` : ''}
                  </div>
                </div>
                <button className="btn sm" onClick={() => remove(r.name)}><Icons.trash size={13} /></button>
              </div>
            ))}
          </div>
        )}

        <div style={{ borderTop: '1px solid var(--line-soft)', marginTop: 13, paddingTop: 12 }}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
            <label className="field" style={{ flex: '1 1 110px' }}>
              <span>Name</span>
              <input className="input" value={draft.name}
                onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
            </label>
            <label className="field" style={{ flex: '1 1 130px' }}>
              <span>Destination</span>
              <input className="input mono" placeholder="10.0.0.0/8" value={draft.destination}
                onChange={(e) => setDraft({ ...draft, destination: e.target.value })} />
            </label>
            <label className="field" style={{ flex: '1 1 120px' }}>
              <span>Gateway</span>
              <input className="input mono" placeholder="192.168.1.1" value={draft.gateway ?? ''}
                onChange={(e) => setDraft({ ...draft, gateway: e.target.value })} />
            </label>
            <label className="field" style={{ flex: '1 1 100px' }}>
              <span>Interface</span>
              <input className="input mono" placeholder="optional" value={draft.interface ?? ''}
                onChange={(e) => setDraft({ ...draft, interface: e.target.value })} />
            </label>
            <button className="btn primary" disabled={!draft.name || !draft.destination} onClick={add}>
              <Icons.plus size={13} /> Add
            </button>
          </div>
        </div>
      </Card>

      <Card title="Kernel routing table" actions={
        <button className="btn sm" onClick={() => refresh()}><Icons.refresh size={13} /> Refresh</button>
      }>
        <div className="hint" style={{ marginBottom: 8 }}>
          What the kernel actually has, which is the ground truth when a route is not behaving.
        </div>
        <pre className="mono" style={{
          fontSize: 11, margin: 0, maxHeight: 260, overflow: 'auto',
          color: 'var(--text-dim)', whiteSpace: 'pre-wrap',
        }}>{(data.kernel ?? []).join('\n') || 'no routes reported'}</pre>
      </Card>
    </>
  )
}

/* ---------- shaping ---------- */

function Shaping() {
  const { data, refresh } = usePoll(() => api.shaping.status(), 0)
  const toast = useToast()
  const [draft, setDraft] = useState<ShapingConfig | null>(null)
  const cfg = draft ?? data?.config ?? null

  if (!data || !cfg) return <Loading what="shaping" />

  const apply = async () => {
    try {
      const res = await api.shaping.apply(cfg)
      setDraft(null)
      refresh()
      toast(res.status.applied ? 'Shaping applied' : 'Saved, but nothing was installed', 'ok')
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not apply', 'err')
    }
  }

  return (
    <Card title="Traffic shaping" actions={
      <button className="btn sm primary" onClick={apply}>Apply</button>
    }>
      <div className="hint" style={{ marginBottom: 12 }}>
        This targets bufferbloat, not throughput. Set the rates slightly below what the line
        actually delivers so the queue forms here rather than in the modem, which is the only place
        it can be managed. Latency under load is what improves; the speed test number will not.
      </div>

      <div style={{ display: 'grid', gap: 10 }}>
        <Switch checked={cfg.enabled} onChange={(v) => setDraft({ ...cfg, enabled: v })}
          label="Shape traffic on the WAN interface" />
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', opacity: cfg.enabled ? 1 : 0.55 }}>
          <label className="field" style={{ flex: '1 1 120px' }}>
            <span>Interface</span>
            <input className="input mono" placeholder="eth0" value={cfg.interface}
              onChange={(e) => setDraft({ ...cfg, interface: e.target.value })} />
          </label>
          <label className="field" style={{ flex: '1 1 130px' }}>
            <span>Download (kbps)</span>
            <input className="input" type="number" value={cfg.download_kbps}
              onChange={(e) => setDraft({ ...cfg, download_kbps: Number(e.target.value) })} />
          </label>
          <label className="field" style={{ flex: '1 1 130px' }}>
            <span>Upload (kbps)</span>
            <input className="input" type="number" value={cfg.upload_kbps}
              onChange={(e) => setDraft({ ...cfg, upload_kbps: Number(e.target.value) })} />
          </label>
          <label className="field" style={{ flex: '0 0 110px' }}>
            <span>Headroom %</span>
            <input className="input" type="number" value={cfg.headroom_percent}
              onChange={(e) => setDraft({ ...cfg, headroom_percent: Number(e.target.value) })} />
          </label>
        </div>
        <Switch checked={cfg.prioritise_interactive}
          onChange={(v) => setDraft({ ...cfg, prioritise_interactive: v })}
          label="Prioritise DNS, ACKs and interactive traffic" />
      </div>

      <div style={{ borderTop: '1px solid var(--line-soft)', marginTop: 13, paddingTop: 12 }}>
        <dl className="kv">
          <dt>Installed</dt>
          <dd>{data.status.applied ? `yes (${data.status.discipline})` : 'no'}</dd>
          {data.status.egress_kbps > 0 && (<><dt>Egress</dt><dd>{data.status.egress_kbps} kbps</dd></>)}
          {data.status.ingress_kbps > 0 && (<><dt>Ingress</dt><dd>{data.status.ingress_kbps} kbps</dd></>)}
        </dl>
        {data.status.detail && (
          <div style={{ fontSize: 11.5, color: 'var(--amber)', marginTop: 6 }}>{data.status.detail}</div>
        )}
        {data.status.qdisc && (
          <pre className="mono" style={{
            fontSize: 10.5, marginTop: 8, color: 'var(--text-faint)', whiteSpace: 'pre-wrap',
          }}>{data.status.qdisc}</pre>
        )}
      </div>
    </Card>
  )
}

/* ---------- NAT-PMP ---------- */

function PortMap() {
  const { data, refresh } = usePoll(() => api.portmap.list(), 5000)
  const toast = useToast()
  if (!data) return <Loading what="port mappings" />

  return (
    <Card title="NAT-PMP port mappings">
      <div className="hint" style={{ marginBottom: 12 }}>
        Consoles and some apps ask the gateway to open an inbound port for them. Each mapping here
        was requested by a device and expires on its own unless the device renews it. UPnP is
        deliberately not implemented; anything that only speaks UPnP needs a manual port forward.
      </div>
      {!data.running && (
        <div style={{ fontSize: 12, color: 'var(--amber)', marginBottom: 10 }}>
          The service is not running. It only starts in inline mode with NAT-PMP enabled.
        </div>
      )}
      {data.mappings.length === 0 ? (
        <Empty title="No active mappings">Nothing has asked for an inbound port.</Empty>
      ) : (
        <div style={{ display: 'grid', gap: 8 }}>
          {data.mappings.map((m) => (
            <div key={`${m.protocol}-${m.external_port}`}
              style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span className="dot on" />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="mono" style={{ fontSize: 12.5 }}>
                  {m.protocol}/{m.external_port} → {m.client}:{m.internal_port}
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-faint)' }}>
                  expires {ago(m.expires)}
                </div>
              </div>
              <button className="btn sm" onClick={async () => {
                try {
                  await api.portmap.remove(m.protocol, m.external_port)
                  refresh()
                } catch (e) {
                  toast(e instanceof Error ? e.message : 'Could not remove', 'err')
                }
              }}><Icons.trash size={13} /></button>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}

/* ---------- live tools ---------- */

function Tools() {
  const toast = useToast()
  const [target, setTarget] = useState('1.1.1.1')
  const [ping, setPing] = useState<PingResult | null>(null)
  const [hops, setHops] = useState<TracerouteHop[] | null>(null)
  const [raw, setRaw] = useState('')
  const [speed, setSpeed] = useState<SpeedResult | null>(null)
  const [mac, setMac] = useState('')
  const [busy, setBusy] = useState('')

  const run = async (what: string, fn: () => Promise<void>) => {
    setBusy(what)
    try {
      await fn()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Failed', 'err')
    } finally {
      setBusy('')
    }
  }

  return (
    <>
      <Card title="Reachability">
        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          <input className="input mono" style={{ flex: 1 }} value={target}
            placeholder="host or address" onChange={(e) => setTarget(e.target.value)} />
          <button className="btn" disabled={!!busy} onClick={() => run('ping', async () => {
            setPing(await api.tools.ping(target))
          })}>{busy === 'ping' ? 'Pinging…' : 'Ping'}</button>
          <button className="btn" disabled={!!busy} onClick={() => run('trace', async () => {
            const r = await api.tools.traceroute(target)
            setHops(r.hops); setRaw(r.raw)
          })}>{busy === 'trace' ? 'Tracing…' : 'Traceroute'}</button>
        </div>

        {ping && (
          <div className="grid c3" style={{ marginBottom: 12 }}>
            <Stat label="Loss" value={`${ping.loss_percent}%`}
              tone={ping.loss_percent > 0 ? 'red' : 'accent'} />
            <Stat label="Average" value={`${ping.avg_ms.toFixed(1)} ms`} />
            <Stat label="Range" value={`${ping.min_ms.toFixed(0)}-${ping.max_ms.toFixed(0)} ms`} />
          </div>
        )}

        {hops && hops.length > 0 && (
          <div style={{ display: 'grid', gap: 4 }}>
            {hops.map((h) => (
              <div key={h.hop} className="mono" style={{ fontSize: 11.5, display: 'flex', gap: 10 }}>
                <span style={{ color: 'var(--text-faint)', width: 24 }}>{h.hop}</span>
                <span style={{ flex: 1 }}>{h.host}</span>
                <span style={{ color: 'var(--text-faint)' }}>{(h.rtts ?? []).join(' ')}</span>
              </div>
            ))}
          </div>
        )}
        {hops && hops.length === 0 && raw && (
          <pre className="mono" style={{ fontSize: 11, whiteSpace: 'pre-wrap', color: 'var(--text-dim)' }}>{raw}</pre>
        )}
      </Card>

      <div className="grid c2">
        <Card title="Speed test" actions={
          <button className="btn sm" disabled={!!busy} onClick={() => run('speed', async () => {
            setSpeed(await api.tools.speedtest())
          })}>{busy === 'speed' ? 'Running…' : 'Run'}</button>
        }>
          <div className="hint" style={{ marginBottom: 10 }}>
            Measures what this node can reach, not what a laptop gets over WiFi.
          </div>
          {speed ? (
            <>
              <div className="grid c2" style={{ marginBottom: 10 }}>
                <Stat label="Download" value={`${speed.download_mbps.toFixed(1)} Mbps`} tone="accent" />
                <Stat label="Upload" value={`${speed.upload_mbps.toFixed(1)} Mbps`} />
              </div>
              <dl className="kv">
                <dt>Latency</dt><dd>{speed.latency_ms.toFixed(1)} ms</dd>
                <dt>Jitter</dt><dd>{speed.jitter_ms.toFixed(1)} ms</dd>
                <dt>Server</dt><dd>{speed.server}</dd>
              </dl>
              {speed.note && (
                <div style={{ fontSize: 11.5, color: 'var(--amber)', marginTop: 6 }}>{speed.note}</div>
              )}
            </>
          ) : <Empty title="Not run yet" />}
        </Card>

        <Card title="Wake on LAN">
          <div className="hint" style={{ marginBottom: 10 }}>
            Sends a magic packet to the device's subnet broadcast. The device has to have
            Wake-on-LAN enabled in its own firmware for this to do anything.
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <input className="input mono" style={{ flex: 1 }} placeholder="aa:bb:cc:dd:ee:ff"
              value={mac} onChange={(e) => setMac(e.target.value)} />
            <button className="btn primary" disabled={!mac || !!busy} onClick={() => run('wol', async () => {
              const r = await api.tools.wol(mac)
              toast(`Magic packet sent to ${r.broadcast}`, 'ok')
            })}>Wake</button>
          </div>
        </Card>
      </div>
    </>
  )
}
