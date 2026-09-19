import { Component } from 'react';

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    console.error('[ErrorBoundary] caught:', error, info);
  }

  render() {
    if (this.state.error) {
      const label = this.props.label || 'PAGE';
      const msg = this.state.error?.message
        ? this.state.error.message
        : String(this.state.error);

      return (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            minHeight: '100vh',
            background: '#0B1120',
            padding: '2rem',
          }}
        >
          <div
            style={{
              background: '#0F172A',
              border: '1px solid #EF4444',
              borderRadius: '8px',
              padding: '2rem',
              maxWidth: '600px',
              width: '100%',
              fontFamily: "'Inter', sans-serif",
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.75rem',
                marginBottom: '1rem',
              }}
            >
              <span style={{ fontSize: '1.5rem' }}>⚠</span>
              <h1
                style={{
                  color: '#EF4444',
                  fontFamily: "'Inter', sans-serif",
                  fontSize: '1rem',
                  fontWeight: 700,
                  letterSpacing: '0.1em',
                  margin: 0,
                }}
              >
                {label === 'APPLICATION' ? 'APPLICATION ERROR' : `RENDER ERROR // ${label}`}
              </h1>
            </div>

            <p style={{ color: '#94A3B8', fontSize: '0.875rem', marginBottom: '0.5rem' }}>
              Unable to render the command center.
            </p>

            <pre
              style={{
                background: '#1E293B',
                color: '#F87171',
                fontSize: '0.75rem',
                padding: '1rem',
                borderRadius: '4px',
                overflowX: 'auto',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                marginBottom: '1.5rem',
              }}
            >
              {msg}
            </pre>

            <button
              onClick={() => window.location.reload()}
              style={{
                background: '#2563EB',
                color: '#fff',
                border: 'none',
                borderRadius: '6px',
                padding: '0.625rem 1.25rem',
                fontFamily: "'Inter', sans-serif",
                fontSize: '0.75rem',
                fontWeight: 700,
                letterSpacing: '0.08em',
                cursor: 'pointer',
                transition: 'background 0.2s',
              }}
              onMouseOver={(e) => (e.target.style.background = '#1D4ED8')}
              onMouseOut={(e) => (e.target.style.background = '#2563EB')}
            >
              RELOAD DASHBOARD
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}