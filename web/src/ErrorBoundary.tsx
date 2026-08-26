import { Component, type ErrorInfo, type ReactNode } from 'react'

/**
 * A per-page error boundary.
 *
 * Without one, a single undefined field in one panel unmounts the entire app
 * and leaves a blank screen with no indication of what went wrong — which is
 * the worst possible failure mode for a tool you reach for when the network
 * is already misbehaving. This keeps the shell and navigation alive and shows
 * what actually broke.
 */
interface Props {
  children: ReactNode
  /** name identifies which page failed, in the message and in the console. */
  name: string
}

interface State {
  error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error(`[orbis] the ${this.props.name} page failed to render`, error, info.componentStack)
  }

  componentDidUpdate(prev: Props) {
    // Navigating away from a broken page should clear the error, or the
    // boundary keeps showing it after the user has moved on.
    if (prev.name !== this.props.name && this.state.error) {
      this.setState({ error: null })
    }
  }

  render() {
    const { error } = this.state
    if (!error) return this.props.children

    return (
      <div style={{ padding: 18 }}>
        <div className="banner err" style={{ alignItems: 'flex-start' }}>
          <div style={{ flex: 1 }}>
            <strong style={{ display: 'block', marginBottom: 5 }}>
              The {this.props.name} page could not be displayed
            </strong>
            <div style={{ fontSize: 12.5, color: 'var(--text-dim)', marginBottom: 10 }}>
              Everything else still works — pick another page from the sidebar. The details below
              are also in the browser console.
            </div>
            <pre style={{
              background: 'var(--bg-2)', border: '1px solid var(--line-soft)', borderRadius: 7,
              padding: '9px 11px', fontSize: 11, overflow: 'auto', maxHeight: 220,
              whiteSpace: 'pre-wrap', wordBreak: 'break-word',
            }}>{error.message}{error.stack ? `\n\n${error.stack}` : ''}</pre>
            <div style={{ display: 'flex', gap: 8, marginTop: 11 }}>
              <button className="btn sm" onClick={() => this.setState({ error: null })}>Try again</button>
              <button className="btn sm" onClick={() => location.reload()}>Reload</button>
            </div>
          </div>
        </div>
      </div>
    )
  }
}
