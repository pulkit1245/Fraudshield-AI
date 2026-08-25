import { useEffect, useState } from 'react';
import SceneContainer from './SceneContainer';
import { useLiveEvents } from '../../hooks/useLiveEvents';
import LiveEventStream from './LiveEventStream';
import TypewriterText from './TypewriterText';
import AnimatedMetric from './AnimatedMetric';

// Extracted from AnalysisTimeline.tsx
const EXPECTED_STAGES = [
  "APK Received",
  "Static Analysis",
  "Dynamic Analysis",
  "Threat Intelligence",
  "ML Risk Scoring",
  "LLM Security Report",
  "Final Verdict",
] as const;



interface Props {
  statusData: any;
  detail: any;
  virustotal?: any;
  mlScore?: any;
  report?: any;
}

function ElapsedTime({ startedAt }: { startedAt: string }) {
  const [elapsed, setElapsed] = useState("");

  useEffect(() => {
    const start = new Date(startedAt).getTime();
    const update = () => {
      const now = Date.now();
      const diff = Math.max(0, Math.floor((now - start) / 1000));
      const m = Math.floor(diff / 60).toString().padStart(2, "0");
      const s = (diff % 60).toString().padStart(2, "0");
      setElapsed(`${m}:${s}`);
    };
    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, [startedAt]);
  return <span className="font-mono">{elapsed || "00:00"}</span>;
}

export default function LiveAnalysisConsole({ statusData, detail, virustotal, mlScore, report }: Props) {
  const [sceneOpacity, setSceneOpacity] = useState(1);
  const [renderStage, setRenderStage] = useState('');

  const backendStages = statusData?.analysis_stages ?? [];
  const isGlobalTerminal = statusData?.status === "completed" || statusData?.status === "failed";
  const hasAnyFailedOrSkipped = backendStages.some((s: any) => s.status === "failed" || s.status === "skipped");
  const isPartiallyComplete = statusData?.status === "completed" && hasAnyFailedOrSkipped;
  
  const allEvents = useLiveEvents(statusData, detail);

  const derivedStages = EXPECTED_STAGES.map((expectedName) => {
    if (expectedName === "APK Received") return { name: expectedName, state: "completed" };
    if (expectedName === "Final Verdict") return { name: expectedName, state: isGlobalTerminal ? "completed" : "pending" };
    const match = backendStages.find((s: any) => s.stage === expectedName);
    if (!match) return { name: expectedName, state: "pending" };
    return { name: expectedName, state: match.status, errorMessage: match.error_message, startedAt: match.started_at };
  });

  const activeStageObj =
    derivedStages.find((s) => s.state === "running") ||
    [...derivedStages].reverse().find((s) => s.state === "completed" || s.state === "failed") ||
    derivedStages[0];

  const activeStage = activeStageObj.name;
  
  useEffect(() => {
    if (!renderStage) {
      setRenderStage(activeStage);
      return;
    }
    if (renderStage !== activeStage) {
      setSceneOpacity(0);
      const timeout = setTimeout(() => {
        setRenderStage(activeStage);
        setSceneOpacity(1);
      }, 300);
      return () => clearTimeout(timeout);
    }
  }, [activeStage, renderStage]);


  const getStatusColor = (state: string) => {
    switch(state) {
      case 'completed': return 'text-status-success bg-status-success/10 border-status-success/30';
      case 'running': return 'text-primary-cyan bg-primary-cyan/10 border-primary-cyan/30 shadow-[0_0_12px_rgba(94,231,255,0.4)]';
      case 'failed': return 'text-status-threat bg-status-threat/10 border-status-threat/30';
      case 'skipped': return 'text-status-warning bg-status-warning/10 border-status-warning/30';
      default: return 'text-text-muted bg-background-elevated border-border';
    }
  };

  const getStatusDot = (state: string) => {
    switch(state) {
      case 'completed': return <div className="w-2 h-2 rounded-full bg-status-success" />;
      case 'running': return (
        <div className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary-cyan opacity-75"></span>
          <span className="relative inline-flex rounded-full h-2 w-2 bg-primary-cyan"></span>
        </div>
      );
      case 'failed': return <div className="w-2 h-2 rounded-full bg-status-threat" />;
      case 'skipped': return <div className="w-2 h-2 rounded-full bg-status-warning" />;
      default: return <div className="w-2 h-2 rounded-full bg-border" />;
    }
  };

  const activeStageData = derivedStages.find(s => s.name === activeStage);
  const activeEvents = allEvents.filter(e => e.stage === activeStage);

  return (
    <div className="flex flex-col gap-6 mb-8">
      <div className="premium-card flex flex-col">
        {/* HEADER */}
        <div className="border-b border-border bg-background-surface/50 p-5 flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold text-text-bright tracking-wide uppercase flex items-center gap-3">
              <svg className="w-6 h-6 text-primary-cyan" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 21v-8.25M15.75 21v-8.25M8.25 21v-8.25M3 9l9-6 9 6m-1.5 12V10.332A48.315 48.315 0 0012 9.75c-2.551 0-5.056.2-7.5.582V21M3 21h18M12 6.75h.008v.008H12V6.75z" />
              </svg>
              Live Analysis Console
            </h2>
            <div className="mt-2 flex items-center gap-4 text-xs font-mono text-text-muted">
              <span className="flex items-center gap-1"><span className="text-text">TARGET:</span> {detail?.original_filename || "Unknown"}</span>
              <span className="flex items-center gap-1"><span className="text-text">HASH:</span> {(detail?.sha256 || "").substring(0, 16)}...</span>
            </div>
          </div>
          <div className="flex flex-col items-end gap-2">
            {isGlobalTerminal ? (
              <div className="badge badge-primary bg-status-success/10 text-status-success border-status-success/30">Analysis Complete</div>
            ) : (
              <div className="badge badge-primary bg-primary-cyan/10 text-primary-cyan border-primary-cyan/30">
                <span className="w-1.5 h-1.5 bg-primary-cyan rounded-full animate-pulse mr-2" />
                Analysis In Progress
              </div>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 h-full min-h-[500px]">
          {/* LEFT PIPELINE TIMELINE */}
          <div className="col-span-1 lg:border-r border-border bg-background-elevated/50 p-5">
            <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted mb-6">Pipeline Timeline</h3>
            <div className="space-y-4">
              {derivedStages.map((stage) => (
                <div 
                  key={stage.name} 
                  className={`flex flex-col p-3 rounded-lg border transition-all duration-300 ${getStatusColor(stage.state)} ${stage.name === activeStage ? 'scale-105 shadow-lg relative z-10' : 'opacity-80'}`}
                >
                  <div className="flex items-center gap-3">
                    {getStatusDot(stage.state)}
                    <span className="text-sm font-semibold tracking-wide uppercase">{stage.name}</span>
                  </div>
                  {stage.state === 'running' && (
                    <div className="mt-2 w-full h-1 bg-background-surface rounded-full overflow-hidden">
                      <div className="h-full bg-primary-cyan w-1/2 animate-[pulse_1.5s_ease-in-out_infinite]" />
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* CENTER 3D VIEWPORT */}
          <div className="col-span-1 lg:col-span-2 relative min-h-[400px] lg:min-h-0 border-y lg:border-y-0 lg:border-r border-border">
            <div className="absolute inset-0 transition-opacity duration-300" style={{ opacity: sceneOpacity }}><SceneContainer activeStage={renderStage} statusData={statusData} detail={detail} virustotal={virustotal} mlScore={mlScore} report={report} /></div>
            
            <div className="absolute top-4 left-4 right-4 flex justify-between pointer-events-none z-20">
              <div className="data-container py-1 px-3 !bg-background-elevated/60 text-xs font-mono text-primary-cyan backdrop-blur-md">
                FPS: 60 | RENDER: GPU_ACCEL
              </div>
              <div className="data-container py-1 px-3 !bg-background-elevated/60 text-xs font-mono text-text-muted backdrop-blur-md">
                STAGE ID: {renderStage.toUpperCase().replace(/\s/g, '_')}
              </div>
            </div>
          </div>

          {/* RIGHT TELEMETRY & INFO */}
          <div className="col-span-1 border-border bg-background-elevated/50 p-5 flex flex-col">
            <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted mb-4 flex items-center justify-between">
              Stage Telemetry
              {activeStageData?.state === 'running' && <span className="w-1.5 h-1.5 bg-primary-cyan rounded-full animate-pulse" />}
            </h3>
            
            <div className="flex-1 flex flex-col gap-4">
              <div className="data-container flex flex-col gap-1">
                <span className="text-xs text-text-muted uppercase">Current Phase</span>
                <span className="text-sm font-semibold text-text-bright">{activeStage}</span>
              </div>
              
              <div className="data-container flex flex-col gap-1">
                <span className="text-xs text-text-muted uppercase">Status</span>
                <span className={`text-sm font-mono font-semibold uppercase ${activeStageData?.state === 'running' ? 'text-primary-cyan' : activeStageData?.state === 'failed' ? 'text-status-threat' : 'text-status-success'}`}>
                  {activeStageData?.state || 'WAITING'}
                </span>
              </div>

              {activeStageData?.startedAt && activeStageData.state === 'running' && (
                <div className="data-container flex flex-col gap-1">
                  <span className="text-xs text-text-muted uppercase">Execution Time</span>
                  <span className="text-sm font-mono text-text-bright"><ElapsedTime startedAt={activeStageData.startedAt} /></span>
                </div>
              )}

              {/* LIVE TERMINAL READOUT FOR CURRENT STAGE */}
              <div className="data-container flex-1 bg-[#030408] font-mono text-xs overflow-hidden flex flex-col">
                <div className="text-primary-cyan/50 mb-2 pb-2 border-b border-border/30">Terminal Output</div>
                <div className="flex-1 overflow-y-auto space-y-1">
                  {activeEvents.map((e) => (
                    <div key={e.id} className="text-text-bright/90">
                      <span className="text-primary-cyan mr-2">&gt;</span>
                      <TypewriterText text={e.message} speed={20} />
                    </div>
                  ))}
                  {activeStageData?.state === 'running' && (
                    <div className="mt-1">
                      <span className="text-primary-cyan mr-2">&gt;</span>
                      <span className="inline-block w-1.5 h-3 bg-primary-cyan animate-pulse align-middle" />
                    </div>
                  )}
                </div>
              </div>

              {/* LIVE METRICS */}
              {activeStage === 'Static Analysis' && activeStageData?.state !== 'pending' && (
                <div className="data-container grid grid-cols-2 gap-2 text-xs">
                  <div className="text-text-muted">Permissions</div>
                  <div className="text-right font-mono text-primary-cyan">
                    <AnimatedMetric value={detail?.static_finding?.permissions?.length || 0} />
                  </div>
                  <div className="text-text-muted">Services</div>
                  <div className="text-right font-mono text-primary-cyan">
                    <AnimatedMetric value={detail?.static_finding?.services?.length || 0} />
                  </div>
                </div>
              )}

              {activeStageData?.errorMessage && (
                <div className="data-container flex flex-col gap-2 border-status-threat/30 bg-status-threat/10 mt-auto">
                  <span className="text-xs text-status-threat font-semibold uppercase">Exception</span>
                  <span className="text-xs font-mono text-status-threat/80 break-words">{activeStageData.errorMessage}</span>
                </div>
              )}

              {isPartiallyComplete && activeStage === 'Final Verdict' && (
                <div className="data-container border-status-warning/30 bg-status-warning/10 mt-auto">
                  <span className="text-xs text-status-warning font-semibold uppercase mb-1 block">Warning</span>
                  <p className="text-xs text-status-warning/80">Analysis partially complete. Verdict is based on available signals.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
      
      {/* GLOBAL LIVE EVENT STREAM */}
      <LiveEventStream events={allEvents} />
    </div>
  );
}
