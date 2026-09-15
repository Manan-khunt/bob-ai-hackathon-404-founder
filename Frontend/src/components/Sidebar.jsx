import { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import { FaTerminal, FaServer, FaBell, FaFlask, FaBug, FaRobot, FaSearch } from 'react-icons/fa';
import HackerLogo from './HackerLogo';

const NAV = [
  { to: '/', label: 'Dashboard', Icon: FaTerminal },
  { to: '/investigation', label: 'Investigations', Icon: FaSearch },
  { to: '/nodes', label: 'Nodes', Icon: FaServer },
  { to: '/incidents', label: 'Incidents', Icon: FaBell },
  { to: '/antibodies', label: 'Antibodies', Icon: FaFlask },
  { to: '/honeypot', label: 'Honeypot', Icon: FaBug },
  { to: '/bob', label: 'Bob', Icon: FaRobot },
];

export default function Sidebar() {
  const [expanded, setExpanded] = useState(false);

  return (
    <aside
      className="fixed left-0 top-0 bottom-0 z-40 bg-hacker-black border-r border-hacker-border transition-all duration-200 overflow-hidden"
      style={{ width: expanded ? 200 : 56 }}
      onMouseEnter={() => setExpanded(true)}
      onMouseLeave={() => setExpanded(false)}
    >
      <div className="h-16 flex items-center justify-center border-b border-hacker-border">
        {expanded ? <HackerLogo /> : <HackerLogo compact />}
      </div>

      <nav className="mt-3 flex flex-col gap-1 px-2">
        {NAV.map(({ to, label, Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 h-10 px-2 rounded-hard font-mono text-[12px] uppercase tracking-wider transition-colors ${
                isActive
                  ? 'text-hacker-green border-l-2 border-hacker-green bg-hacker-panel'
                  : 'text-hacker-muted hover:text-hacker-green-dim border-l-2 border-transparent'
              }`
            }
          >
            <Icon className="text-sm shrink-0" />
            {expanded && <span className="whitespace-nowrap">{label}</span>}
          </NavLink>
        ))}
      </nav>

      <div className="absolute bottom-3 left-0 right-0 text-center font-mono text-hacker-muted text-[10px] tracking-wider px-2">
        {expanded ? 'v2.0.0 // ARMED' : 'v2'}
      </div>
    </aside>
  );
}