import { useEffect, useRef, useState } from 'react';
import { useStore } from '../store';
import MatrixRain from './MatrixRain';
import HackerLogo from './HackerLogo';

const LINES = [
  '> IMMUNE-NET v2.0 \u2014 CYBER DEFENCE MESH',
  '> initializing innate anomaly detectors............[OK]',
  '> loading antibody memory store...................[OK]',
  '> connecting swarm peers (8/8)....................[OK]',
  '> APT fingerprint engine..........................[OK]',
  '> blast radius predictor..........................[OK]',
  '> honeypot decoy node active......................[OK]',
  '> IBM Bob MCP server listening....................[OK]',
  '> ALL SYSTEMS NOMINAL ' +
    '\u2014 FLEET IMMUNITY: 87.5%'.padStart(0),
];

const CHAR_DELAY = 40;
const LINE_GAP = 90;

export default function TerminalBoot() {
  const setBooted = useStore(s => s.setBooted);
  const [progress, setProgress] = useState([]);
  const bootedRef = useRef(false);

  useEffect(() => {
    let raf;
    const tick = (start) => (now) => {
      const rendered = [];
      let elapsed = (now - start) / 1;
      for (const line of LINES) {
        const charsForLine = Math.min(line.length, Math.max(0, Math.floor(elapsed / CHAR_DELAY)));
        rendered.push(line.slice(0, charsForLine));
        elapsed -= line.length * CHAR_DELAY + LINE_GAP;
        if (elapsed < 0) break;
      }
      setProgress([...rendered]);
      if (elapsed >= -LINE_GAP && rendered.length >= LINES.length && rendered[rendered.length - 1].length >= LINES[LINES.length - 1].length) {
        const wait = setTimeout(() => {
          if (!bootedRef.current) {
            bootedRef.current = true;
            setBooted();
          }
        }, 700);
        setTimeout(() => cancelAnimationFrame(raf), 720);
        return () => clearTimeout(wait);
      }
      raf = requestAnimationFrame(tick(start));
    };
    raf = requestAnimationFrame(tick(performance.now()));
    return () => cancelAnimationFrame(raf);
  }, [setBooted]);

  return (
    <div className="fixed inset-0 bg-hacker-black flex items-center justify-center overflow-hidden">
      <MatrixRain />
      <div className="relative z-10 w-full max-w-2xl px-6">
        <div className="mb-8">
          <HackerLogo />
        </div>
        <div className="hacker-panel p-6 font-mono text-hacker-green text-xs sm:text-sm leading-6 tracking-wide">
          {LINES.map((line, i) => (
            <div key={i} className="whitespace-pre-wrap min-h-[1.5rem]">
              {progress[i] || ''}
              {i === progress.length - 1 && <span className="cursor inline-block w-2" />}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}