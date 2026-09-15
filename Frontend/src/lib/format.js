export function timeAgo(isoString) {
  if (!isoString) return '';
  try {
    const then = new Date(isoString);
    const diffMs = Date.now() - then.getTime();
    const secs = Math.floor(diffMs / 1000);
    if (secs < 60) return `${secs}s ago`;
    const mins = Math.floor(secs / 60);
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  } catch {
    return '';
  }
}

export function shortTime(isoOrTimeStr) {
  if (!isoOrTimeStr) return '';
  try {
    const s = String(isoOrTimeStr).trim();
    if (/^\d{1,2}:\d{2}(:\d{2})?\s*(AM|PM)$/i.test(s)) return s;
    const d = new Date(s);
    if (isNaN(d.getTime())) return s.slice(0, 12);
    return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  } catch {
    return String(isoOrTimeStr).slice(0, 12);
  }
}

export function formatConf(val) {
  if (val == null) return '0%';
  const v = typeof val === 'number' ? val : parseFloat(val);
  return v > 1 ? `${Math.round(v)}%` : `${Math.round(v * 100)}%`;
}

export function confColor(val) {
  if (val == null) return 'good';
  const v = typeof val === 'number' ? val : parseFloat(val);
  const p = v > 1 ? v / 100 : v;
  if (p >= 0.60) return 'good';
  if (p >= 0.40) return 'warn';
  return 'bad';
}

export const NODE_DISPLAY = {
  'node-alpha': { icon: '\u03B1', color: '#00FF41' },
  'node-beta':  { icon: '\u03B2', color: '#FF2D2D' },
  'node-gamma': { icon: '\u03B3', color: '#FFB300' },
  'node-delta': { icon: '\u03B4', color: '#00B4D8' },
  'node-epsilon': { icon: '\u03B5', color: '#00C032' },
  'node-zeta':  { icon: '\u03B6', color: '#7C3AED' },
  'node-eta':   { icon: '\u03B7', color: '#00B4D8' },
  'node-theta': { icon: '\u03B8', color: '#C8FAD6' },
  'node-decoy': { icon: '\u03A8', color: '#7C3AED' },
};

export const NODE_GRID = [
  ['node-alpha', 'node-beta', 'node-gamma'],
  ['node-delta', 'node-theta', 'node-epsilon'],
  ['node-zeta', 'node-eta', 'node-decoy'],
];