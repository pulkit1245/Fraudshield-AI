import { useRef, useMemo, useState, useEffect } from 'react';
import { useFrame } from '@react-three/fiber';
import { Torus, Line, Sphere, Html, Icosahedron } from '@react-three/drei';
import * as THREE from 'three';

interface Props {
  statusData?: any;
  detail?: any;
  mlScore?: any;
}

export default function SceneMLScoring({ statusData, detail }: Props) {
  const coreRef = useRef<THREE.Group>(null);
  const outerRingRef = useRef<THREE.Mesh>(null);
  const innerRingRef = useRef<THREE.Mesh>(null);
  const signalRefs = useRef<THREE.Mesh[]>([]);

  // Stage state
  const stages = statusData?.analysis_stages || [];
  const mlStage = stages.find((s: any) => s.stage === 'ML Risk Scoring');
  
  const isRunning = mlStage?.status === 'running';
  const isCompleted = mlStage?.status === 'completed' || mlStage?.status === 'failed';
  const isActive = isRunning || isCompleted;

  const prefersReducedMotion = typeof window !== 'undefined' 
    ? window.matchMedia('(prefers-reduced-motion: reduce)').matches 
    : false;

  // Real Data Bindings
  const finalScore = detail?.verdict?.final_risk_score;
  const severityBand = detail?.verdict?.severity_band;
  const hasScore = finalScore !== undefined && finalScore !== null;
  const hasThreat = severityBand === 'high' || severityBand === 'critical';
  const hasWarning = severityBand === 'medium';
  
  // ML feature indicators (if we want to bind stream activity to actual presence of data)
  const hasStatic = !!detail?.static_finding;
  const hasDynamic = !!detail?.dynamic_finding;
  const hasThreatIntel = !!detail?.sha256; // Proxy for threat intel lookup

  // Interpolated score for animation
  const [displayScore, setDisplayScore] = useState(0);

  useEffect(() => {
    if (!hasScore) return;
    
    if (isCompleted || prefersReducedMotion) {
      setDisplayScore(finalScore);
      return;
    }
    
    if (isRunning) {
      // Simulate the model converging by lerping toward the final score over a few seconds.
      // We'll manage this safely in a RAF or interval.
      const interval = setInterval(() => {
        setDisplayScore(prev => {
          const diff = finalScore - prev;
          if (Math.abs(diff) < 0.5) {
            clearInterval(interval);
            return finalScore;
          }
          // Ease out towards target
          return prev + diff * 0.1;
        });
      }, 50);
      return () => clearInterval(interval);
    }
  }, [finalScore, isRunning, isCompleted, hasScore, prefersReducedMotion]);

  // Colors
  const coreColor = hasThreat ? '#FF4D67' : hasWarning ? '#FBBF24' : '#5EE7FF';
  
  // Evidence streams logic
  const streams = useMemo(() => {
    const s = [];
    // Static Evidence Stream (Top Left)
    if (hasStatic || isRunning) {
      s.push({ id: 'static', start: [-4, 2, -2], color: '#5EE7FF' }); // Cyan
    }
    // Dynamic Evidence Stream (Top Right)
    if (hasDynamic || isRunning) {
      s.push({ id: 'dynamic', start: [4, 2, -2], color: '#3B82F6' }); // Blue
    }
    // Threat Intel Stream (Bottom Left)
    if (hasThreatIntel || isRunning) {
      s.push({ id: 'threat', start: [-4, -2, 2], color: '#A78BFA' }); // Violet
    }
    // Network/Behavioral Stream (Bottom Right)
    if (hasDynamic || isRunning) {
      s.push({ id: 'network', start: [4, -2, 2], color: '#6366F1' }); // Indigo
    }
    return s;
  }, [hasStatic, hasDynamic, hasThreatIntel, isRunning]);

  useFrame((state) => {
    const t = state.clock.getElapsedTime();
    
    if (coreRef.current && !prefersReducedMotion) {
      // Subtle ambient hover
      coreRef.current.position.y = Math.sin(t * 0.5) * 0.1;
    }

    if (outerRingRef.current && innerRingRef.current && !prefersReducedMotion) {
      if (isRunning) {
        outerRingRef.current.rotation.x = t * 0.5;
        outerRingRef.current.rotation.y = t * 0.8;
        
        innerRingRef.current.rotation.x = -t * 0.8;
        innerRingRef.current.rotation.y = -t * 0.5;
        
        const pulseScale = 1 + Math.sin(t * 5) * 0.05;
        outerRingRef.current.scale.set(pulseScale, pulseScale, pulseScale);
      } else if (isCompleted) {
        // Settle smoothly
        outerRingRef.current.rotation.x = THREE.MathUtils.lerp(outerRingRef.current.rotation.x, Math.PI / 4, 0.02);
        outerRingRef.current.rotation.y = THREE.MathUtils.lerp(outerRingRef.current.rotation.y, 0, 0.02);
        
        innerRingRef.current.rotation.x = THREE.MathUtils.lerp(innerRingRef.current.rotation.x, -Math.PI / 4, 0.02);
        innerRingRef.current.rotation.y = THREE.MathUtils.lerp(innerRingRef.current.rotation.y, 0, 0.02);
        
        outerRingRef.current.scale.lerp(new THREE.Vector3(1, 1, 1), 0.05);
      }
    }

    // Signal traveling along lines
    if (isRunning && !prefersReducedMotion) {
      streams.forEach((stream, i) => {
        const signal = signalRefs.current[i];
        if (signal) {
          const progress = (t * 1.5 + i * 0.3) % 1;
          const startVec = new THREE.Vector3(...stream.start);
          const endVec = new THREE.Vector3(0, 0, 0);
          
          signal.position.copy(startVec).lerp(endVec, progress);
          signal.visible = true;
        }
      });
    } else {
      signalRefs.current.forEach(s => { if (s) s.visible = false; });
    }
  });

  if (!isActive && mlStage?.status !== 'pending') return null;

  return (
    <group>
      {/* Evidence Streams Converging */}
      {streams.map((stream, i) => (
        <group key={stream.id}>
          {/* Path Line */}
          <Line
            points={[new THREE.Vector3(...stream.start), new THREE.Vector3(0, 0, 0)]}
            color={stream.color}
            lineWidth={isRunning && !prefersReducedMotion ? 1.5 : 1}
            transparent
            opacity={isRunning ? 0.4 : 0.15}
          />
          {/* Source Node Marker */}
          <Sphere args={[0.08, 8, 8]} position={new THREE.Vector3(...stream.start)}>
            <meshBasicMaterial color={stream.color} />
          </Sphere>
          {/* Traveling Signal Pulse */}
          <mesh ref={(el) => (signalRefs.current[i] = el as THREE.Mesh)} visible={false}>
            <sphereGeometry args={[0.06, 8, 8]} />
            <meshBasicMaterial color={stream.color} />
          </mesh>
        </group>
      ))}

      {/* Analytical Core */}
      <group ref={coreRef} position={[0, 0, 0]}>
        
        {/* Outer Computational Ring */}
        <Torus ref={outerRingRef} args={[1.5, 0.02, 16, 64]}>
          <meshStandardMaterial 
            color={coreColor} 
            emissive={coreColor} 
            emissiveIntensity={isRunning ? 0.8 : 0.2} 
            wireframe 
          />
        </Torus>

        {/* Inner Evidence Lattice */}
        <Icosahedron ref={innerRingRef} args={[1.2, 1]}>
          <meshStandardMaterial 
            color={coreColor} 
            emissive={coreColor} 
            emissiveIntensity={isRunning ? 0.4 : 0.1}
            transparent 
            opacity={isRunning ? 0.15 : 0.05}
            wireframe
          />
        </Icosahedron>

        {/* Central Core Sphere */}
        <Sphere args={[0.7, 32, 32]}>
          <meshStandardMaterial 
            color="#05070B" 
            emissive={coreColor} 
            emissiveIntensity={0.1}
            transparent
            opacity={0.9}
          />
        </Sphere>

        {/* HTML Numeric Score */}
        <Html center zIndexRange={[100, 0]} className="pointer-events-none">
          <div className="flex flex-col items-center justify-center">
            {hasScore ? (
              <>
                <span 
                  className="font-mono text-5xl font-bold tabular-nums" 
                  style={{ 
                    color: coreColor,
                    textShadow: `0 0 20px ${coreColor}80` 
                  }}
                >
                  {Math.round(displayScore)}
                </span>
                {isCompleted && (
                  <span className="text-[10px] uppercase font-bold tracking-widest mt-1 opacity-70" style={{ color: coreColor }}>
                    Risk Score
                  </span>
                )}
              </>
            ) : (
              <span className="text-xs uppercase font-bold tracking-widest opacity-50" style={{ color: coreColor }}>
                {isRunning ? 'EVALUATING...' : 'UNAVAILABLE'}
              </span>
            )}
          </div>
        </Html>
      </group>
    </group>
  );
}
