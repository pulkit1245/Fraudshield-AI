import { useEffect, useRef, useState, useCallback } from 'react';
import { TerminalEvent } from '../../hooks/useLiveEvents';

interface Props {
  events: TerminalEvent[];
}

export default function LiveEventStream({ events }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [isPaused, setIsPaused] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [userScrolledUp, setUserScrolledUp] = useState(false);
  const [copied, setCopied] = useState(false);

  // Handle automatic scrolling
  useEffect(() => {
    if (!isPaused && !userScrolledUp && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [events, isPaused, userScrolledUp, isExpanded]);

  // Handle scroll events to detect if user manually scrolled up
  const handleScroll = useCallback(() => {
    if (!containerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
    
    // If we are within 20px of the bottom, we are at the bottom
    const isAtBottom = scrollHeight - scrollTop <= clientHeight + 20;
    
    if (isAtBottom && userScrolledUp) {
      setUserScrolledUp(false);
    } else if (!isAtBottom && !userScrolledUp) {
      setUserScrolledUp(true);
    }
  }, [userScrolledUp]);

  const scrollToBottom = () => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
      setUserScrolledUp(false);
    }
  };

  const getColorClass = (type: TerminalEvent['type'], isHist: boolean) => {
    const base = (() => {
      switch (type) {
        case 'INFO': return 'text-primary-cyan/70';
        case 'SCAN': return 'text-primary-cyan';
        case 'STATIC': return 'text-primary-blue';
        case 'RUNTIME': return 'text-primary-cyan';
        case 'NETWORK': return 'text-primary-blue';
        case 'AI': return 'text-ai';
        case 'WARN': return 'text-status-warning';
        case 'THREAT': return 'text-status-threat';
        case 'SUCCESS': return 'text-status-success';
        case 'ERROR': return 'text-status-threat';
        default: return 'text-text-muted';
      }
    })();
    return isHist ? `${base} opacity-60` : base;
  };

  const copyLogs = () => {
    const text = events.map(e => {
      const time = e.timestamp ? `[${new Date(e.timestamp).toLocaleTimeString([], { hour12: false })}] ` : '';
      return `${time}[${e.type}] ${e.message}`;
    }).join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={`premium-card flex flex-col transition-all duration-300 relative ${isExpanded ? 'h-96' : 'h-48'}`}>
      <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-background-surface/80 backdrop-blur">
        <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted flex items-center gap-2">
          {!isPaused && !userScrolledUp ? (
            <div className="w-1.5 h-1.5 rounded-full bg-primary-cyan animate-pulse" />
          ) : (
            <div className="w-1.5 h-1.5 rounded-full bg-text-muted" />
          )}
          Live Event Stream
        </h3>
        <div className="flex items-center gap-3">
          <button 
            onClick={() => setIsPaused(!isPaused)} 
            className={`text-xs font-mono transition-colors ${isPaused ? 'text-primary-cyan' : 'text-text-muted hover:text-text-bright'}`}
          >
            {isPaused ? 'RESUMED' : 'PAUSE'}
          </button>
          <button 
            onClick={copyLogs} 
            className="text-xs font-mono text-text-muted hover:text-text-bright transition-colors"
          >
            {copied ? 'COPIED' : 'COPY'}
          </button>
          <button 
            onClick={() => setIsExpanded(!isExpanded)} 
            className="text-xs font-mono text-text-muted hover:text-text-bright transition-colors"
          >
            {isExpanded ? 'COLLAPSE' : 'EXPAND'}
          </button>
        </div>
      </div>
      
      <div 
        ref={containerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto p-4 bg-[#030408] font-mono text-[11px] leading-relaxed tracking-wide space-y-1 relative"
      >
        {events.map((evt, idx) => {
          const isLatest = !evt.isHistorical && idx === events.length - 1;
          const opacityClass = isLatest ? 'opacity-100' : 'opacity-70 hover:opacity-100';
          
          return (
            <div key={evt.id} className={`flex gap-3 transition-opacity duration-300 ${opacityClass}`}>
              <span className="text-text-muted/50 shrink-0 min-w-[70px]">
                {evt.timestamp 
                  ? `[${new Date(evt.timestamp).toLocaleTimeString([], { hour12: false })}]`
                  : evt.isHistorical 
                    ? '[HIST]' 
                    : '[LIVE]'}
              </span>
              <span className={`shrink-0 w-16 ${getColorClass(evt.type, evt.isHistorical)}`}>
                [{evt.type}]
              </span>
              <span className={evt.isHistorical ? 'text-text-muted/80' : 'text-text-bright/90'}>
                {evt.message}
              </span>
            </div>
          );
        })}
        {!isPaused && events.length > 0 && !events[events.length - 1].isHistorical && (
          <div className="flex gap-3 opacity-100 mt-2">
            <span className="text-text-muted/50 shrink-0 min-w-[70px]">
              [{new Date().toLocaleTimeString([], { hour12: false })}]
            </span>
            <span className="w-2 h-3 bg-primary-cyan animate-pulse inline-block" />
          </div>
        )}
      </div>

      {/* New Events floating indicator */}
      {userScrolledUp && (
        <button
          onClick={scrollToBottom}
          className="absolute bottom-4 right-4 bg-background-elevated/90 backdrop-blur border border-primary-cyan/30 text-primary-cyan font-mono text-[10px] px-3 py-1.5 rounded-full shadow-lg flex items-center gap-2 hover:bg-primary-cyan/10 transition-colors z-10 animate-fade-in"
        >
          NEW EVENTS <span>↓</span>
        </button>
      )}
    </div>
  );
}
