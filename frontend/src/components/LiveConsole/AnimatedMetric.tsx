import { useState, useEffect } from 'react';

interface Props {
  value: number;
  duration?: number;
  className?: string;
}

export default function AnimatedMetric({ value, duration = 1000, className = "" }: Props) {
  const [displayedValue, setDisplayedValue] = useState(0);

  useEffect(() => {
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReducedMotion || value === 0) {
      setDisplayedValue(value);
      return;
    }

    let startTimestamp: number | null = null;
    const startValue = displayedValue;
    const endValue = value;

    const step = (timestamp: number) => {
      if (!startTimestamp) startTimestamp = timestamp;
      const progress = Math.min((timestamp - startTimestamp) / duration, 1);
      
      // smooth out-cubic easing
      const easeProgress = 1 - Math.pow(1 - progress, 3);
      
      setDisplayedValue(Math.floor(startValue + (endValue - startValue) * easeProgress));

      if (progress < 1) {
        window.requestAnimationFrame(step);
      } else {
        setDisplayedValue(endValue);
      }
    };

    window.requestAnimationFrame(step);
  }, [value, duration]);

  return <span className={className}>{displayedValue}</span>;
}
