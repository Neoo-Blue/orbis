import { useEffect, useState } from 'react'
import { api } from '../api'
import { Card, Field, useToast } from '../ui'

export function Login({ onSuccess }: { onSuccess: () => void }) {
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [setup, setSetup] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const toast = useToast()

  useEffect(() => {
    api.auth.status().then((s) => setSetup(s.setup_required)).catch(() => {})
  }, [])

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    if (setup && password !== confirm) {
      setError('The two passwords do not match.')
      return
    }
    setBusy(true)
    try {
      if (setup) {
        await api.auth.setPassword('', password)
        toast('Password set. Orbis is now protected.', 'ok')
      } else {
        await api.auth.login(password)
      }
      onSuccess()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login">
      <div className="login-card">
        <div style={{ textAlign: 'center', marginBottom: 22 }}>
          <svg width="42" height="42" viewBox="0 0 32 32" fill="none" style={{ margin: '0 auto 10px' }}>
            <circle cx="16" cy="16" r="11" stroke="var(--accent)" strokeWidth="1.6" />
            <ellipse cx="16" cy="16" rx="11" ry="4.4" stroke="var(--accent)" strokeWidth="1.1" opacity=".55" />
            <circle cx="16" cy="16" r="2.6" fill="var(--accent)" />
          </svg>
          <div style={{ fontSize: 15, letterSpacing: '.16em', textTransform: 'uppercase', fontWeight: 620 }}>
            Orbis
          </div>
          <div style={{ color: 'var(--text-faint)', fontSize: 12, marginTop: 3 }}>
            {setup ? 'Choose an admin password to finish setup' : 'Sign in to continue'}
          </div>
        </div>

        <Card>
          <form onSubmit={submit} style={{ display: 'grid', gap: 13 }}>
            <Field label="Password" hint={setup ? 'At least 10 characters. There is no recovery — store it somewhere.' : undefined}>
              <input className="input" type="password" value={password} autoFocus
                autoComplete={setup ? 'new-password' : 'current-password'}
                onChange={(e) => setPassword(e.target.value)} />
            </Field>
            {setup && (
              <Field label="Confirm password">
                <input className="input" type="password" value={confirm}
                  autoComplete="new-password" onChange={(e) => setConfirm(e.target.value)} />
              </Field>
            )}
            {error && <div style={{ color: 'var(--red)', fontSize: 12.5 }}>{error}</div>}
            <button className="btn primary" type="submit" disabled={busy || password.length < 1}>
              {busy ? 'Working…' : setup ? 'Set password' : 'Sign in'}
            </button>
          </form>
        </Card>
      </div>
    </div>
  )
}
