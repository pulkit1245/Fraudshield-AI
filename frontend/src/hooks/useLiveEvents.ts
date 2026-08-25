import { useMemo } from 'react';

export interface TerminalEvent {
  id: string;
  timestamp: string | null;
  isHistorical: boolean;
  type: 'INFO' | 'SCAN' | 'STATIC' | 'RUNTIME' | 'NETWORK' | 'AI' | 'WARN' | 'THREAT' | 'SUCCESS' | 'ERROR';
  message: string;
  stage: string;
}

export function useLiveEvents(statusData: any, detail: any) {
  return useMemo(() => {
    const events: TerminalEvent[] = [];
    if (!statusData) return events;

    let idCounter = 0;
    const addEvent = (
      type: TerminalEvent['type'], 
      message: string, 
      stage: string, 
      timestamp?: string | null,
      isHistorical: boolean = false
    ) => {
      events.push({
        id: `evt-${idCounter++}`,
        timestamp: timestamp || null,
        isHistorical,
        type,
        message,
        stage
      });
    };

    const stages = statusData.analysis_stages || [];

    // Stage 1: APK Received
    const apkStage = stages.find((s: any) => s.stage === 'APK Received');
    if (apkStage || statusData.status !== 'pending') {
      const ts = apkStage?.started_at || statusData.submitted_at;
      const isHist = apkStage?.status === 'completed' || statusData.status === 'completed';
      
      addEvent('SCAN', 'receiving APK...', 'APK Received', ts, isHist);
      if (detail?.original_filename) addEvent('INFO', `target: ${detail.original_filename}`, 'APK Received', ts, isHist);
      if (detail?.sha256) addEvent('SCAN', 'calculating SHA-256...', 'APK Received', ts, isHist);
      addEvent('SUCCESS', 'APK integrity verified', 'APK Received', apkStage?.completed_at || ts, isHist);
    }

    // Stage 2: Static Analysis
    const staticStage = stages.find((s: any) => s.stage === 'Static Analysis');
    if (staticStage) {
      const isHist = staticStage.status === 'completed' || staticStage.status === 'failed';
      addEvent('INFO', 'opening APK archive...', 'Static Analysis', staticStage.started_at, isHist);
      if (staticStage.status === 'completed') {
        addEvent('STATIC', 'parsing AndroidManifest.xml...', 'Static Analysis', null, true);
        addEvent('STATIC', 'extracting permissions...', 'Static Analysis', null, true);
        addEvent('SUCCESS', 'static analysis complete', 'Static Analysis', staticStage.completed_at, true);
      } else if (staticStage.status === 'running') {
        addEvent('STATIC', statusData.stage_detail?.current_step || 'scanning DEX bytecode...', 'Static Analysis', new Date().toISOString(), false);
      } else if (staticStage.status === 'failed') {
        addEvent('ERROR', staticStage.error_message || 'static analysis failed', 'Static Analysis', staticStage.completed_at, true);
      }
    }

    // Stage 3: Dynamic Analysis
    const dynStage = stages.find((s: any) => s.stage === 'Dynamic Analysis');
    if (dynStage) {
      const isHist = dynStage.status === 'completed' || dynStage.status === 'failed';
      addEvent('INFO', 'initializing isolated environment...', 'Dynamic Analysis', dynStage.started_at, isHist);
      if (dynStage.status === 'completed') {
        addEvent('RUNTIME', 'installing APK...', 'Dynamic Analysis', null, true);
        addEvent('RUNTIME', 'attaching runtime observers...', 'Dynamic Analysis', null, true);
        addEvent('NETWORK', 'capturing network events...', 'Dynamic Analysis', null, true);
        addEvent('SUCCESS', 'dynamic observation complete', 'Dynamic Analysis', dynStage.completed_at, true);
      } else if (dynStage.status === 'running') {
        addEvent('RUNTIME', statusData.stage_detail?.current_step || 'monitoring process activity...', 'Dynamic Analysis', new Date().toISOString(), false);
      } else if (dynStage.status === 'failed') {
        addEvent('ERROR', dynStage.error_message || 'sandbox failure', 'Dynamic Analysis', dynStage.completed_at, true);
      }
    }

    // Stage 4: Threat Intelligence
    const tiStage = stages.find((s: any) => s.stage === 'Threat Intelligence');
    if (tiStage) {
      const isHist = tiStage.status === 'completed' || tiStage.status === 'failed';
      addEvent('INFO', 'extracting indicators...', 'Threat Intelligence', tiStage.started_at, isHist);
      if (tiStage.status === 'completed') {
        addEvent('SCAN', 'querying reputation sources...', 'Threat Intelligence', null, true);
        addEvent('SUCCESS', 'intelligence correlation complete', 'Threat Intelligence', tiStage.completed_at, true);
      } else if (tiStage.status === 'running') {
        addEvent('SCAN', 'correlating indicators...', 'Threat Intelligence', new Date().toISOString(), false);
      } else if (tiStage.status === 'failed') {
        addEvent('ERROR', 'intelligence lookup failed', 'Threat Intelligence', tiStage.completed_at, true);
      }
    }

    // Stage 5: ML Risk Scoring
    const mlStage = stages.find((s: any) => s.stage === 'ML Risk Scoring');
    if (mlStage) {
      const isHist = mlStage.status === 'completed' || mlStage.status === 'failed';
      addEvent('INFO', 'loading evidence vector...', 'ML Risk Scoring', mlStage.started_at, isHist);
      if (mlStage.status === 'completed') {
        addEvent('AI', 'calculating feature weights...', 'ML Risk Scoring', null, true);
        addEvent('SUCCESS', 'risk score stabilized', 'ML Risk Scoring', mlStage.completed_at, true);
      } else if (mlStage.status === 'running') {
        addEvent('AI', 'evaluating evidence...', 'ML Risk Scoring', new Date().toISOString(), false);
      }
    }

    // Stage 6: LLM Security Report
    const llmStage = stages.find((s: any) => s.stage === 'LLM Security Report');
    if (llmStage) {
      const isHist = llmStage.status === 'completed' || llmStage.status === 'failed';
      addEvent('INFO', 'collecting evidence...', 'LLM Security Report', llmStage.started_at, isHist);
      if (llmStage.status === 'completed') {
        addEvent('AI', 'generating security reasoning...', 'LLM Security Report', null, true);
        addEvent('SUCCESS', 'report generation complete', 'LLM Security Report', llmStage.completed_at, true);
      } else if (llmStage.status === 'running') {
        addEvent('AI', 'constructing security report...', 'LLM Security Report', new Date().toISOString(), false);
      } else if (llmStage.status === 'failed') {
        addEvent('ERROR', 'report generation failed', 'LLM Security Report', llmStage.completed_at, true);
      }
    }

    // Stage 7: Final Verdict
    const finalStage = stages.find((s: any) => s.stage === 'Final Verdict');
    if (finalStage || statusData.status === 'completed') {
      const isHist = finalStage?.status === 'completed' || statusData.status === 'completed';
      addEvent('INFO', 'aggregating evidence...', 'Final Verdict', finalStage?.started_at, isHist);
      if (statusData.status === 'completed') {
        addEvent('SUCCESS', 'final verdict calculated', 'Final Verdict', finalStage?.completed_at, true);
        const band = detail?.verdict?.severity_band;
        if (band === 'high' || band === 'critical') {
          addEvent('THREAT', 'malicious indicator confirmed', 'Final Verdict', finalStage?.completed_at, true);
        } else if (band === 'medium') {
          addEvent('WARN', 'suspicious behavior observed', 'Final Verdict', finalStage?.completed_at, true);
        }
      } else if (finalStage?.status === 'running') {
        addEvent('SCAN', 'evaluating final risk...', 'Final Verdict', new Date().toISOString(), false);
      }
    }

    return events;
  }, [statusData, detail]);
}
