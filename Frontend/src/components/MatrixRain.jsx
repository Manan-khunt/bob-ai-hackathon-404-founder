import { useEffect, useRef } from 'react';

const GLYPHS = 'アィウェカキクケサシスセソタチツテトナニヌネノユヨラリルレロ0123456789#$%&*+<=>?@¥ABCDEFZX';

export default function MatrixRain() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let width, height, cols, drops = [];
    const fontSize = 14;

    const resize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
      cols = Math.floor(width / fontSize);
      drops = Array.from({ length: cols }, () => Math.floor(Math.random() * -100));
    };
    resize();
    window.addEventListener('resize', resize);

    const draw = () => {
      ctx.fillStyle = 'rgba(8,12,8,0.08)';
      ctx.fillRect(0, 0, width, height);
      ctx.font = `${fontSize}px "Share Tech Mono", monospace`;
      ctx.fillStyle = 'rgba(0,255,65,0.5)';
      for (let i = 0; i < cols; i++) {
        const glyph = GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
        ctx.fillText(glyph, i * fontSize, drops[i] * fontSize);
        if (drops[i] * fontSize > height && Math.random() > 0.975) drops[i] = 0;
        drops[i]++;
      }
    };

    const id = setInterval(draw, 50);
    return () => {
      clearInterval(id);
      window.removeEventListener('resize', resize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 -z-10"
      style={{ opacity: 0.035, pointerEvents: 'none' }}
      aria-hidden
    />
  );
}