import { useState, useEffect } from 'react';

interface Props {
  text: string;
  delay?: number;
  speed?: number;
  onComplete?: () => void;
  className?: string;
}

export default function TypewriterText({ text, delay = 0, speed = 30, onComplete, className = "" }: Props) {
  const [displayedText, setDisplayedText] = useState("");
  const [isTyping, setIsTyping] = useState(false);

  useEffect(() => {
    // Check for reduced motion
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    
    if (prefersReducedMotion) {
      setDisplayedText(text);
      if (onComplete) onComplete();
      return;
    }

    let timeout: ReturnType<typeof setTimeout>;
    let interval: ReturnType<typeof setInterval>;
    let i = 0;

    timeout = setTimeout(() => {
      setIsTyping(true);
      interval = setInterval(() => {
        i++;
        setDisplayedText(text.slice(0, i));
        if (i >= text.length) {
          clearInterval(interval);
          setIsTyping(false);
          if (onComplete) onComplete();
        }
      }, speed);
    }, delay);

    return () => {
      clearTimeout(timeout);
      clearInterval(interval);
    };
  }, [text, delay, speed, onComplete]);

  return (
    <span className={className}>
      {displayedText}
      {isTyping && <span className="inline-block w-1.5 h-3 ml-0.5 bg-current animate-pulse align-middle" style={{ content: '""' }} />}
    </span>
  );
}
