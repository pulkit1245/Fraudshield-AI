import { useRef, useMemo, useState, useEffect } from 'react';
import { useFrame } from '@react-three/fiber';
import { Icosahedron, Sphere, Line, Html, Octahedron } from '@react-three/drei';
import * as THREE from 'three';

interface Props {
  statusData?: any;
  detail?: any;
}

export default function SceneFinalVerdict({ statusData, detail }: Props) {
  const groupRef = useRef<THREE.Group>(null);
  const coreRef = useRef<THREE.Mesh>(null);
  const shellRef = useRef<THREE.Mesh>(null);
  const signalRefs = useRef<THREE.Mesh[]>([]);

  // Stage state
  const stages = statusData?.analysis_stages || [];
  const verdictStage = stages.find((s: any) => s.stage === 'Final Verdict');
  
  const isRunning = verdictStage?.status === 'running';
  const isCompleted = verdictStage?.status === 'completed';
  const isFailed = verdictStage?.status === 'failed';
  // Final Verdict scene should also be active if we are fully done
  const isPipelineCompleted = statusData?.status === 'completed' || statusData?.status === 'failed';
  const isActive = isRunning || isCompleted || isFailed || isPipelineCompleted;

  const prefersReducedMotion = typeof window !== 'undefined' 
    ? window.matchMedia('(prefers-reduced-motion: reduce)').matches 
    : false;

  // Real Data Bindings
  const finalScore = detail?.verdict?.final_risk_score;
  const severityBand = detail?.verdict?.severity_band;
  
  const hasScore = finalScore !== undefined && finalScore !== null;
  const hasThreat = severityBand === 'high' || severityBand === 'critical';
  const hasWarning = severityBand === 'medium';

  // Available Evidence Categories
  const hasStatic = !!detail?.static_finding;
  const hasDynamic = !!detail?.dynamic_finding;
  const hasThreatIntel = !!detail?.sha256;
  const hasML = detail?.verdict?.final_risk_score !== undefined;
  const hasLLM = !!stages.find((s: any) => s.stage === 'LLM Security Report' && s.status === 'completed');

  // Colors
  const severityColor = hasThreat ? '#FF4D67' : hasWarning ? '#FBBF24' : '#4ADE80';
  const errorColor = hasThreat ? '#FF4D67' : '#FBBF24';

  // Animation interpolation state
  const [displayScore, setDisplayScore] = useState(0);
  const [revealOpacity, setRevealOpacity] = useState(0);

  useEffect(() => {
    if (!hasScore) return;
    
    if (isCompleted || isPipelineCompleted || prefersReducedMotion) {
      setDisplayScore(finalScore);
      setRevealOpacity(1);
      return;
    }
    
    if (isRunning) {
      const scoreInterval = setInterval(() => {
        setDisplayScore(prev => {
          const diff = finalScore - prev;
          if (Math.abs(diff) < 0.5) {
            clearInterval(scoreInterval);
            return finalScore;
          }
          return prev + diff * 0.1;
        });
      }, 50);

      // Fade in the final text slightly later in the running cycle
      const fadeInterval = setInterval(() => {
        setRevealOpacity(prev => Math.min(1, prev + 0.05));
      }, 100);

      return () => {
        clearInterval(scoreInterval);
        clearInterval(fadeInterval);
      };
    }
  }, [finalScore, isRunning, isCompleted, isPipelineCompleted, hasScore, prefersReducedMotion]);

  // Evidence Sources mapped to a circle
  const sources = useMemo(() => {
    const s = [];
    if (hasStatic || isRunning) s.push({ id: 'static', color: '#5EE7FF', label: 'STATIC' }); // Cyan
    if (hasDynamic || isRunning) s.push({ id: 'dynamic', color: '#3B82F6', label: 'DYNAMIC' }); // Blue
    if (hasThreatIntel || isRunning) s.push({ id: 'threat', color: '#A78BFA', label: 'INTEL' }); // Violet
    if (hasML || isRunning) s.push({ id: 'ml', color: '#6366F1', label: 'ML RISK' }); // Indigo
    if (hasLLM || isRunning) s.push({ id: 'llm', color: '#C4B5FD', label: 'LLM REPORT' }); // Light Violet
    
    const radius = 3.5;
    return s.map((source, i) => {
      const angle = (i / s.length) * Math.PI * 2 - Math.PI / 2; // start from top
      return {
        ...source,
        pos: [Math.cos(angle) * radius, Math.sin(angle) * radius, 0]
      };
    });
  }, [hasStatic, hasDynamic, hasThreatIntel, hasML, hasLLM, isRunning]);

  useFrame((state) => {
    const t = state.clock.getElapsedTime();

    // Cinematic Focus: Slowly scale up the entire group during RUNNING to simulate camera push
    if (groupRef.current && !prefersReducedMotion) {
      const targetScale = isRunning ? 1.15 : (isCompleted || isPipelineCompleted) ? 1.2 : 1.0;
      groupRef.current.scale.lerp(new THREE.Vector3(targetScale, targetScale, targetScale), 0.02);
      
      // Ambient scene float
      groupRef.current.position.y = Math.sin(t * 0.5) * 0.05;
    }

    // Core Evaluation Animation
    if (coreRef.current && !prefersReducedMotion) {
      if (isRunning) {
        // High energy processing
        coreRef.current.rotation.x = t * 1.5;
        coreRef.current.rotation.y = t * 2.0;
        const pulse = 1 + Math.sin(t * 10) * 0.05;
        coreRef.current.scale.set(pulse, pulse, pulse);
      } else {
        // Authoritative stable state
        coreRef.current.rotation.x = THREE.MathUtils.lerp(coreRef.current.rotation.x, Math.PI / 4, 0.05);
        coreRef.current.rotation.y = THREE.MathUtils.lerp(coreRef.current.rotation.y, 0, 0.05);
        coreRef.current.scale.lerp(new THREE.Vector3(1, 1, 1), 0.1);
      }
    }

    // Containment shell subtle spin
    if (shellRef.current && !prefersReducedMotion) {
      shellRef.current.rotation.y = -t * 0.2;
      shellRef.current.rotation.z = t * 0.1;
    }

    // Evidence Converging Signals
    if (isRunning && !prefersReducedMotion) {
      sources.forEach((source, i) => {
        const signal = signalRefs.current[i];
        if (signal) {
          const progress = (t * 2 + i * 0.5) % 1; // traveling 0 to 1
          const startVec = new THREE.Vector3(...source.pos);
          const endVec = new THREE.Vector3(0, 0, 0); // Core
          
          signal.position.copy(startVec).lerp(endVec, progress);
          signal.visible = true;
        }
      });
    } else {
      signalRefs.current.forEach(s => { if (s) s.visible = false; });
    }
  });

  if (!isActive) return null;

  return (
    <group ref={groupRef}>
      
      {/* EVIDENCE CONVERGENCE */}
      {sources.map((source, i) => (
        <group key={source.id}>
          {/* Source Node */}
          <Sphere args={[0.08, 16, 16]} position={new THREE.Vector3(...source.pos)}>
            <meshBasicMaterial color={source.color} transparent opacity={isRunning ? 0.6 : 0.2} />
          </Sphere>
          
          {/* Path Line to Core */}
          <Line
            points={[new THREE.Vector3(...source.pos), new THREE.Vector3(0, 0, 0)]}
            color={source.color}
            lineWidth={isRunning ? 1.5 : 1}
            transparent
            opacity={isRunning ? 0.3 : 0.05}
          />
          
          {/* Converging Signal Pulse */}
          <mesh ref={(el) => (signalRefs.current[i] = el as THREE.Mesh)} visible={false}>
            <sphereGeometry args={[0.05, 8, 8]} />
            <meshBasicMaterial color={source.color} />
          </mesh>
        </group>
      ))}

      {/* CENTRAL VERDICT CORE */}
      <group position={[0, 0, 0]}>
        
        {/* Subtle Containment Shell */}
        <Sphere ref={shellRef} args={[1.6, 32, 32]}>
          <meshStandardMaterial 
            color={severityColor} 
            transparent 
            opacity={0.05} 
            wireframe 
          />
        </Sphere>

        {/* Forensic Core Crystalline Structure */}
        <Icosahedron ref={coreRef} args={[1, 0]}>
          <meshStandardMaterial 
            color={severityColor} 
            emissive={severityColor} 
            emissiveIntensity={isRunning ? 0.6 : (isCompleted || isPipelineCompleted) ? 0.3 : 0.1} 
            transparent
            opacity={0.9}
            roughness={0.2}
            metalness={0.8}
          />
        </Icosahedron>
        
        {/* Inner solid geometry to provide depth */}
        <Octahedron args={[0.8, 0]}>
          <meshStandardMaterial color="#05070B" />
        </Octahedron>

      </group>

      {/* FINAL VERDICT DIGITAL DISPLAY */}
      <Html center position={[0, 0, 1]} zIndexRange={[100, 0]} transform scale={0.25} occlude="blending">
        <div 
          className="w-[480px] p-8 border border-border bg-background-elevated/95 backdrop-blur-xl rounded-xl flex flex-col items-center justify-center font-mono text-center shadow-2xl transition-all duration-1000"
          style={{ 
            opacity: isCompleted || isPipelineCompleted || isFailed ? 1 : Math.max(0, revealOpacity - 0.2),
            transform: `scale(${(isCompleted || isPipelineCompleted || isFailed) ? 1 : 0.95})`,
            boxShadow: `0 0 80px ${isFailed ? errorColor : severityColor}20` 
          }}
        >
          {isFailed ? (
            <>
              <span className="text-xl tracking-[0.3em] text-text-muted mb-2 uppercase">Analysis Status</span>
              <span className="text-3xl font-bold tracking-widest text-status-threat uppercase mb-6">Verdict Unavailable</span>
              <div className="w-full h-px bg-border my-4" />
              <span className="text-sm text-text-secondary uppercase">Pipeline execution failed.</span>
            </>
          ) : (
            <>
              <span className="text-sm tracking-[0.4em] text-text-muted mb-4 uppercase">Final Verdict</span>
              
              <div className="flex flex-col items-center justify-center my-6">
                {hasScore ? (
                  <span 
                    className="text-8xl font-bold tabular-nums leading-none tracking-tighter"
                    style={{ color: severityColor, textShadow: `0 0 30px ${severityColor}40` }}
                  >
                    {Math.round(displayScore)}
                  </span>
                ) : (
                  <span className="text-2xl font-bold uppercase text-text-muted">
                    Score Unavailable
                  </span>
                )}
                
                <div 
                  className="mt-6 px-6 py-2 rounded-full border bg-opacity-10 backdrop-blur-sm"
                  style={{ borderColor: `${severityColor}40`, backgroundColor: `${severityColor}10` }}
                >
                  <span 
                    className="text-xl font-bold tracking-widest uppercase"
                    style={{ color: severityColor }}
                  >
                    {severityBand || 'UNKNOWN RISK'}
                  </span>
                </div>
              </div>
              
              <div className="w-full h-px bg-border my-6" />
              
              <span className="text-sm tracking-[0.2em] text-text-secondary uppercase">
                {isRunning ? 'Evaluating Evidence...' : 'Forensic Analysis Complete'}
              </span>
            </>
          )}
        </div>
      </Html>

    </group>
  );
}
