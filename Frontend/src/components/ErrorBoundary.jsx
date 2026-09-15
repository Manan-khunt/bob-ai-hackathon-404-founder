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
    console.warn('[ErrorBoundary] caught:', error, info);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="hacker-panel p-6 m-4">
          <div className="hacker-title text-sm mb-2">&gt; RENDER ERROR // {this.props.label || 'PAGE'}</div>
          <div className="font-mono text-hacker-red text-[11px] whitespace-pre-wrap">
            {String(this.state.error && this.state.error.message ? this.state.error.message : this.state.error)}
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}