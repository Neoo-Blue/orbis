import { useMemo } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Banner, Card, Empty, Loading, Stat, Switch, useConfirm, useToast } from '../ui'
import { clientName } from '../format'
import type { InterceptStatus } from '../types'

/**
 * ARP interception.
 *
 * This is the highest-consequence screen in the product: enrolling a device
 * makes Orbis lie to it about where the gateway is, so its traffic detours
 * through here. Done right the device notices nothing. Done wrong, or if Orbis
 * dies while a device is enrolled, that device loses its connection until the
 * ARP cache heals. The UI is built to make that trade explicit rather than
 * bury it under a toggle.
 */
export function InterceptPage() {
  const { data, refresh } = usePoll<InterceptStatus>(() => api.intercept.get(), 5000)
  const { data: clients } = usePoll(() => api.clients.list(), 20000)
  const toast = useToast()
  const confirm = useConfirm()

  const enrolled = useMemo(
    () => new Set(Object.keys(data?.config.clients ?? {})),
    [data],
  )

  if (!data) return <Loading what="interception" />
  const cfg = data.config
  const stats = data.stats

  const save = async (body: Parameters<typeof api.intercept.settings>[0], warn?: string) => {
    if (warn && !(await confirm(warn))) return
    try {
      await api.intercept.settings(body)
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not apply', 'err')
    }
  }

  const toggleDevice = async (ip: string, mac: string) => {
    try {
      if (enrolled.has(ip)) await api.intercept.remove(ip)
      else await api.intercept.enroll(ip, mac)
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Failed', 'err')
    }
  }

  // Only real LAN devices with a MAC can be enrolled: the poisoning reply has
  // to be addressed to the device, and Tailscale/anycast peers have none.
  const candidates = (clients?.clients ?? []).filter(
    (c) => c.mac && c.ip.startsWith('192.168.') || (c.mac && /^10\.|^172\.(1[6-9]|2\d|3[01])\./.test(c.ip)),
  )

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <Banner tone={cfg.enabled ? 'warn' : 'info'}>
        <strong style={{ display: 'block', marginBottom: 3 }}>
          Insert Orbis in front of a device without becoming the gateway
        </strong>
        For each enrolled device, Orbis answers ARP for the router with its own address, so the
        device sends its traffic here to be filtered and forwarded. Nothing changes on the router
        or the device. The catch is real: while a device is enrolled, its internet depends on this
        node, so if Orbis stops, that device drops offline until its ARP cache clears, usually under
        a minute. Enrol the devices you want filtered, not the whole house.
      </Banner>

      <Card
        title="Interception"
        actions={
          <Switch
            checked={cfg.enabled}
            onChange={(v) => save({ enabled: v },
              v ? undefined
                : 'Turn interception off? Enrolled devices are restored to the real gateway first.')}
            label={cfg.enabled ? (stats.running ? 'Active' : 'Starting…') : 'Off'}
          />
        }
      >
        <div className="grid c3" style={{ marginBottom: 12 }}>
          <Stat label="Enrolled devices" value={String(stats.targets)}
            tone={stats.targets ? 'accent' : undefined} />
          <Stat label="Real gateway" value={data.gateway || '—'}
            sub={stats.gateway_mac ? `at ${stats.gateway_mac}` : 'not resolved'} />
          <Stat label="Re-asserts" value={String(stats.reasserts)}
            sub={stats.last_reassert ? new Date(stats.last_reassert).toLocaleTimeString() : 'idle'} />
        </div>

        <div style={{ display: 'grid', gap: 9, opacity: cfg.enabled ? 1 : 0.55 }}>
          <Switch checked={cfg.redirect_dns} onChange={(v) => save({ redirect_dns: v })}
            label="Filter DNS for enrolled devices" />
          <div className="hint" style={{ marginTop: -4 }}>
            Steers their DNS into this resolver even if they have a hardcoded one. Recommended;
            this is most of the value.
          </div>
          <Switch checked={cfg.redirect_http}
            onChange={(v) => save({ redirect_http: v },
              v ? 'Turn on TLS interception for enrolled devices? Any enrolled device without the Orbis certificate installed will fail to load HTTPS sites. Only do this for devices you have set up.' : undefined)}
            label="Intercept HTTPS (needs the CA on each device)" />
          <div className="hint" style={{ marginTop: -4 }}>
            Off by default. Without the certificate installed, an intercepted device shows every
            site as broken. This is the setting that made Google fail earlier.
          </div>
        </div>
      </Card>

      <Card title="Devices">
        <div className="hint" style={{ marginBottom: 10 }}>
          Pick the devices to route through Orbis. Each keeps its own address and configuration.
          A device with no MAC cannot be enrolled, because the takeover reply has to be addressed
          to it.
        </div>
        {candidates.length === 0 ? (
          <Empty title="No eligible devices yet">
            Devices appear here once Orbis has seen them on the LAN with a MAC address.
          </Empty>
        ) : (
          <div style={{ display: 'grid', gap: 6, maxHeight: 460, overflow: 'auto' }}>
            {candidates.map((c) => {
              const on = enrolled.has(c.ip)
              return (
                <label key={c.id} style={{
                  display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer',
                  padding: '4px 0', fontSize: 12.5,
                }}>
                  <input type="checkbox" checked={on} onChange={() => toggleDevice(c.ip, c.mac ?? "")} />
                  <span className={`dot ${c.online ? 'on' : 'off'}`} />
                  <span style={{ flex: 1, minWidth: 0 }}>{clientName(c)}</span>
                  <span className="mono" style={{ fontSize: 11, color: 'var(--text-faint)' }}>
                    {c.ip}
                  </span>
                  {on && stats.running && (
                    <span className="tag" style={{ fontSize: 10 }}>routing</span>
                  )}
                </label>
              )
            })}
          </div>
        )}
      </Card>

      {stats.running && (
        <Card title="Safety">
          <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.7 }}>
            <div>· Enrolled devices are re-asserted every couple of seconds, so a device does not
              drift back to the real gateway.</div>
            <div>· Turning a device off, or turning the whole feature off, sends the real gateway's
              address back to it several times before stopping, so it recovers immediately rather
              than waiting for its cache to expire.</div>
            <div>· If this node reboots, enrolled devices recover on their own within a minute as
              their ARP entries time out. The eero is still the real gateway underneath.</div>
          </div>
        </Card>
      )}
    </div>
  )
}
