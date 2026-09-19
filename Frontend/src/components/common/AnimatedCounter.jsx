import React, { useEffect, useState } from 'react';

export default function AnimatedCounter({
  value,
  duration = 900,
  formatter = (v) => Math.round(v).toLocaleString(),
  prefix = '',
  suffix = '',
  className = '',
}) {
  const numericValue = typeof value === 'number' ? value : parseFloat(String(value).replace(/,/g, '')) || 0;
  const [displayValue, setDisplayValue] = useState(0);

  useEffect(() => {
    let startTimestamp = null;
    const startValue = displayValue;
    const endValue = numericValue;
    let animationFrameId;

    const step = (timestamp) => {
      if (!startTimestamp) startTimestamp = timestamp;
      const progress = Math.min((timestamp - startTimestamp) / duration, 1);
      // Ease out quart
      const easeProgress = 1 - Math.pow(1 - progress, 4);
      const current = startValue + (endValue - startValue) * easeProgress;
      setDisplayValue(current);

      if (progress < 1) {
        animationFrameId = requestAnimationFrame(step);
      } else {
        setDisplayValue(endValue);
      }
    };

    animationFrameId = requestAnimationFrame(step);
    return () => cancelAnimationFrame(animationFrameId);
  }, [numericValue, duration]);

  return (
    <span className={`inline-block tabular-nums font-mono ${className}`}>
      {prefix}
      {formatter(displayValue)}
      {suffix}
    </span>
  );
}
