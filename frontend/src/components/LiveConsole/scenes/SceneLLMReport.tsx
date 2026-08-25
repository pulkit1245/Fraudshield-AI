import { useRef, useMemo, useState, useEffect } from 'react';
import { useFrame } from '@react-three/fiber';
import { Box, Plane, Line, Html, Cylinder } from '@react-three/drei';
import * as THREE from 'three';

interface Props {
  statusData?: any;
  detail?: any;
  report?: any;
}

export default function SceneLLMReport({ statusData, detail, report }: Props) {
  const groupRef = useRef<THREE.Group>(null);
  const evidenceGroupRef = useRef<THREE.Group>(null);
  const reasoningCoreRef = useRef<THREE.Group>(null);
  const documentRef = useRef<THREE.Group>(null);
  const signalRefs = useRef<THREE.Mesh[]>([]);

  // Stage state
  const stages = statusData?.analysis_stages || [];
  const llmStage = stages.find((s: any) => s.stage === 'LLM Security Report');
  
  const isRunning = llmStage?.status === 'running';
  const isCompleted = llmStage?.status === 'completed';
  const isFailed = llmStage?.status === 'failed';
  const isActive = isRunning || isCompleted || isFailed;

  const prefersReducedMotion = typeof window !== 'undefined' 
    ? window.matchMedia('(prefers-reduced-motion: reduce)').matches 
    : false;

  // Real Data Bindings
  const severityBand = detail?.verdict?.severity_band;
  const hasThreat = severityBand === 'high' || severityBand === 'critical';
  const hasWarning = severityBand === 'medium';
  

  const hasStatic = !!detail?.static_finding;
  const hasDynamic = !!detail?.dynamic_finding;
  const hasThreatIntel = !!detail?.sha256;
  const mlScore = detail?.verdict?.final_risk_score !== undefined;

  // Colors
  const aiColor = '#A78BFA'; // Violet for reasoning
  const aiSecondary = '#6C7BFF'; // Indigo
  const normalColor = '#5EE7FF'; // Cyan
  
  const severityColor = hasThreat ? '#FF4D67' : hasWarning ? '#FBBF24' : '#4ADE80';

  const errorColor = hasThreat ? '#FF4D67' : '#FBBF24';

  // Animation interpolation state for document construction
  const [docProgress, setDocProgress] = useState(0);

  useEffect(() => {
    if (isCompleted || prefersReducedMotion) {
      setDocProgress(1);
      return;
    }
    if (isRunning) {
      const interval = setInterval(() => {
        setDocProgress(p => {
          if (p >= 1) {
            clearInterval(interval);
            return 1;
          }
          return p + 0.02; // Take ~2.5 seconds to build
        });
      }, 50);
      return () => clearInterval(interval);
    }
  }, [isRunning, isCompleted, prefersReducedMotion]);

  // Generate deterministic evidence nodes (ZONE 1) based on real data
  const evidenceNodes = useMemo(() => {
    const nodes = [];
    if (hasStatic || isRunning) nodes.push({ id: 'static', pos: [-3, 3, 0], color: normalColor, label: 'STATIC' });
    if (hasDynamic || isRunning) nodes.push({ id: 'dynamic', pos: [-1, 3.5, -2], color: aiSecondary, label: 'DYNAMIC' });
    if (hasThreatIntel || isRunning) nodes.push({ id: 'threat', pos: [1, 3.5, -2], color: severityColor, label: 'INTEL' });
    if (mlScore || isRunning) nodes.push({ id: 'ml', pos: [3, 3, 0], color: normalColor, label: 'ML RISK' });
    return nodes;
  }, [hasStatic, hasDynamic, hasThreatIntel, mlScore, normalColor, aiSecondary, severityColor, isRunning]);

  useFrame((state) => {
    const t = state.clock.getElapsedTime();

    // Group floating
    if (groupRef.current && !prefersReducedMotion) {
      groupRef.current.position.y = Math.sin(t * 0.5) * 0.1;
    }

    // Evidence Node hover
    if (evidenceGroupRef.current && !prefersReducedMotion) {
      evidenceGroupRef.current.children.forEach((child, i) => {
        if (isRunning) {
          child.position.y += Math.sin(t * 2 + i) * 0.005;
        } else {
          child.position.y = THREE.MathUtils.lerp(child.position.y, 0, 0.05);
        }
      });
    }

    // Reasoning Core rotation (ZONE 2)
    if (reasoningCoreRef.current && !prefersReducedMotion) {
      if (isRunning) {
        reasoningCoreRef.current.rotation.y = t * 0.5;
        reasoningCoreRef.current.rotation.x = Math.sin(t * 0.5) * 0.2;
      } else {
        reasoningCoreRef.current.rotation.y = THREE.MathUtils.lerp(reasoningCoreRef.current.rotation.y, Math.PI / 4, 0.02);
        reasoningCoreRef.current.rotation.x = THREE.MathUtils.lerp(reasoningCoreRef.current.rotation.x, 0, 0.02);
      }
    }

    // Traveling signals from evidence to core
    if (isRunning && !prefersReducedMotion) {
      evidenceNodes.forEach((node, i) => {
        const signal = signalRefs.current[i];
        if (signal) {
          const progress = (t * 1.5 + i * 0.4) % 1;
          const startVec = new THREE.Vector3(...node.pos);
          // Core is at [0, 1, 0]
          const endVec = new THREE.Vector3(0, 1, 0);
          
          signal.position.copy(startVec).lerp(endVec, progress);
          signal.visible = true;
        }
      });
    } else {
      signalRefs.current.forEach(s => { if (s) s.visible = false; });
    }

    // Document assembly animation (ZONE 3)
    if (documentRef.current) {
      if (isRunning && !prefersReducedMotion) {
        // Document jitters slightly as it compiles
        documentRef.current.position.y = -1.5 + (Math.random() - 0.5) * 0.02;
      } else {
        documentRef.current.position.y = THREE.MathUtils.lerp(documentRef.current.position.y, -1.5, 0.1);
      }
    }
  });

  if (!isActive && llmStage?.status !== 'pending') return null;

  return (
    <group ref={groupRef}>
      
      {/* ZONE 1: EVIDENCE */}
      <group ref={evidenceGroupRef}>
        {evidenceNodes.map((node, i) => (
          <group key={node.id}>
            {/* The Node */}
            <Box args={[0.3, 0.3, 0.3]} position={new THREE.Vector3(...node.pos)}>
              <meshStandardMaterial color={node.color} transparent opacity={0.8} wireframe={isRunning} />
            </Box>
            
            {/* Connection Line to Core */}
            <Line
              points={[new THREE.Vector3(...node.pos), new THREE.Vector3(0, 1, 0)]}
              color={aiSecondary}
              lineWidth={1}
              transparent
              opacity={isRunning ? 0.3 : 0.05}
            />

            {/* Signal Pulse */}
            <mesh ref={(el) => (signalRefs.current[i] = el as THREE.Mesh)} visible={false}>
              <sphereGeometry args={[0.08, 8, 8]} />
              <meshBasicMaterial color={node.color} />
            </mesh>
          </group>
        ))}
      </group>

      {/* ZONE 2: REASONING CORE */}
      <group ref={reasoningCoreRef} position={[0, 1, 0]}>
        {/* Abstract semantic lattice / nested planes */}
        <Plane args={[2, 2]} rotation={[-Math.PI / 2, 0, 0]} position={[0, 0, 0]}>
          <meshStandardMaterial color={aiColor} transparent opacity={0.15} side={THREE.DoubleSide} depthWrite={false} />
        </Plane>
        <Plane args={[1.5, 1.5]} rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.3, 0]}>
          <meshStandardMaterial color={aiSecondary} transparent opacity={0.2} side={THREE.DoubleSide} wireframe depthWrite={false} />
        </Plane>
        <Plane args={[1, 1]} rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.3, 0]}>
          <meshStandardMaterial color={aiColor} transparent opacity={0.3} side={THREE.DoubleSide} wireframe depthWrite={false} />
        </Plane>
        {/* Central prism */}
        <Cylinder args={[0, 0.5, 1, 4]} rotation={[0, Math.PI / 4, 0]}>
          <meshStandardMaterial color={aiColor} emissive={aiColor} emissiveIntensity={isRunning ? 0.5 : 0.1} transparent opacity={0.8} />
        </Cylinder>
      </group>

      {/* Output Line to Document */}
      <Line
        points={[[0, 0.5, 0], [0, -1.5, 0]]}
        color={aiColor}
        lineWidth={2}
        transparent
        opacity={isRunning ? 0.5 : 0.2}
      />

      {/* ZONE 3: SECURITY REPORT */}
      <group ref={documentRef} position={[0, -1.5, 0]}>
        {/* Physical Document Base */}
        <Plane args={[3.2, 4.2]} rotation={[-Math.PI / 2, 0, 0]} position={[0, 0, 0]}>
          <meshStandardMaterial color="#0A0E17" transparent opacity={0.9} />
        </Plane>
        <Plane args={[3.2, 4.2]} rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.01, 0]}>
          <meshBasicMaterial color={isFailed ? errorColor : aiColor} wireframe transparent opacity={0.4} />
        </Plane>

        {/* Dynamic HTML Document Content */}
        <Html transform rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.05, 0]} scale={0.1} zIndexRange={[100, 0]} occlude="blending">
          <div 
            className="w-[800px] h-[1050px] p-10 bg-background-elevated/80 border border-border backdrop-blur-md rounded-lg overflow-hidden flex flex-col font-mono"
            style={{ 
              opacity: Math.max(0.2, docProgress),
              boxShadow: `0 0 50px ${isFailed ? errorColor : aiColor}20` 
            }}
          >
            {isFailed ? (
              <div className="flex-1 flex flex-col items-center justify-center text-center">
                <span className="text-6xl text-status-threat mb-4 font-bold tracking-widest uppercase">Report Generation Failed</span>
                <span className="text-2xl text-status-threat/70 uppercase">Error in reasoning correlation engine</span>
              </div>
            ) : report || isCompleted ? (
              <div className="flex flex-col h-full opacity-100 transition-opacity duration-1000">
                <header className="border-b border-border pb-6 mb-6">
                  <h1 className="text-4xl font-bold tracking-widest text-primary-cyan uppercase">Security Analysis Report</h1>
                  <div className="flex gap-4 mt-4 text-xl">
                    <span className="text-text-muted">SEVERITY:</span>
                    <span style={{ color: severityColor }} className="font-bold uppercase">{severityBand || 'UNKNOWN'}</span>
                  </div>
                </header>
                
                {/* Simulated Content appearing block by block */}
                <div className="space-y-8 flex-1">
                  <div style={{ opacity: docProgress > 0.2 ? 1 : 0 }} className="transition-opacity">
                    <h2 className="text-2xl text-primary-violet font-bold mb-4 uppercase">Executive Summary</h2>
                    <p className="text-xl text-text-secondary leading-relaxed border-l-4 border-primary-violet pl-4">
                      {report?.summary_text 
                        ? report.summary_text.length > 250 ? report.summary_text.substring(0, 250) + '...' : report.summary_text
                        : 'SECURITY REPORT UNAVAILABLE'}
                    </p>
                  </div>
                  
                  <div style={{ opacity: docProgress > 0.5 ? 1 : 0 }} className="transition-opacity">
                    <h2 className="text-2xl text-primary-violet font-bold mb-4 uppercase">Key Findings & Risks</h2>
                    <ul className="list-none space-y-3">
                      {report?.ttp_mapping?.report?.key_risks?.slice(0, 3).map((risk: string, idx: number) => (
                        <li key={idx} className="flex gap-3 text-xl text-text-secondary">
                          <span className="text-primary-violet">■</span>
                          {risk}
                        </li>
                      )) || (
                        <>
                          <li className="flex gap-3 text-xl text-text-secondary"><span className="text-primary-violet">■</span> NO KEY RISKS AVAILABLE.</li>
                          
                          
                        </>
                      )}
                    </ul>
                  </div>

                  <div style={{ opacity: docProgress > 0.8 ? 1 : 0 }} className="transition-opacity mt-auto">
                    <div className="p-4 bg-background-surface border border-border rounded">
                      <span className="text-lg text-text-muted">MODEL USED:</span>
                      <span className="text-lg text-text-primary ml-4">{report?.model_used || 'FraudShield Advanced Analytics'}</span>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="flex-1 flex flex-col items-center justify-center text-center">
                <div className="w-16 h-16 rounded-full border-4 border-primary-violet border-t-transparent animate-spin mb-6" />
                <span className="text-4xl text-primary-violet font-bold tracking-widest uppercase animate-pulse">Constructing Report...</span>
                <span className="text-xl text-text-muted mt-4 uppercase">Correlating Evidence</span>
              </div>
            )}
          </div>
        </Html>
      </group>
    </group>
  );
}
