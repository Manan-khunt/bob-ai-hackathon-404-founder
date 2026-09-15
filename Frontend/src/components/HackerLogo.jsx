export default function HackerLogo({ compact = false }) {
  if (compact) {
    return (
      <div className="text-hacker-green font-orbitron text-lg leading-none select-none text-center">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" className="inline-block">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="#00FF41" strokeWidth="1.6" strokeLinejoin="round" fill="none" />
          <path d="M8.5 11.5l2.4 2.4 4.6-5" stroke="#00FF41" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </div>
    );
  }

  return (
    <div className="select-none text-center">
      <pre className="font-orbitron text-hacker-green leading-tight text-xs sm:text-sm" style={{ lineHeight: 1.1 }}>
{`╔═══════╗
║   ▲   ║
╚═══════╝`}
      </pre>
      <div className="mt-1 font-orbitron font-black text-hacker-green tracking-[0.18em] text-base sm:text-lg">
        IMMUNE-NET
      </div>
      <div className="font-mono text-hacker-muted text-[9px] tracking-[0.42em] uppercase">
        Cyber Defence
      </div>
    </div>
  );
}