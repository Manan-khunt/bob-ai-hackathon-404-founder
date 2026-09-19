export default function HackerLogo({ compact = false }) {
  if (compact) {
    return (
      <div className="text-center select-none" style={{ color: '#38BDF8' }}>
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" className="inline-block">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="#38BDF8" strokeWidth="1.6" strokeLinejoin="round" fill="none" />
          <path d="M8.5 11.5l2.4 2.4 4.6-5" stroke="#38BDF8" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </div>
    );
  }

  return (
    <div className="select-none text-center px-2">
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" className="mx-auto mb-1">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="#38BDF8" strokeWidth="1.5" strokeLinejoin="round" fill="none" />
        <path d="M8.5 11.5l2.4 2.4 4.6-5" stroke="#38BDF8" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <div style={{ fontFamily: "'Orbitron', sans-serif", fontWeight: 900, color: '#38BDF8', fontSize: '0.65rem', letterSpacing: '0.16em' }}>
        IMMUNE-NET
      </div>
    </div>
  );
}