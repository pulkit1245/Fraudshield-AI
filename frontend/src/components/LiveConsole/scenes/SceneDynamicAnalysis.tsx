import { useRef, useMemo } from 'react';
import { useFrame } from '@react-three/fiber';
import { Box, Sphere, Wireframe, Line } from '@react-three/drei';
import * as THREE from 'three';

interface Props {
  statusData?: any;
  detail?: any;
}

export default function SceneDynamicAnalysis({ statusData, detail }: Props) {
  const containerRef = useRef<THREE.Mesh>(null);
  const coreRef = useRef<THREE.Mesh>(null);
  const internalGroup = useRef<THREE.Group>(null);
  const externalGroup = useRef<THREE.Group>(null);

  // Determine State
  const stages = statusData?.analysis_stages || [];
  const dynStage = stages.find((s: any) => s.stage === 'Dynamic Analysis');
  
  const isRunning = dynStage?.status === 'running';
  const isCompleted = dynStage?.status === 'completed' || dynStage?.status === 'failed';
  const isActive = isRunning || isCompleted;

  // Actual dynamic data flags
  const dyn = detail?.dynamic_finding;
  const hasNetwork = dyn?.network_events && dyn.network_events.length > 0;
  const processCount = dyn?.processes?.length || 10;
  const severityBand = detail?.verdict?.severity_band;
  const hasThreat = severityBand === 'high' || severityBand === 'critical';
  const hasWarning = severityBand === 'medium';

  // Colors
  const normalColor = '#5EE7FF';
  const coreColor = '#A78BFA';
  const threatColor = '#FF4D67';
  const warningColor = '#FBBF24';

  const determineThreatColor = () => {
    if (hasThreat) return threatColor;
    if (hasWarning) return warningColor;
    return normalColor;
  };

  // Generate deterministic particle offsets
  const internalParticles = useMemo(() => {
    return Array.from({ length: Math.min(processCount, 30) }).map(() => ({
      x: (Math.random() - 0.5) * 3,
      y: (Math.random() - 0.5) * 3,
      z: (Math.random() - 0.5) * 3,
      speed: Math.random() * 2 + 1,
      isThreat: hasThreat && Math.random() > 0.8 // Only highlight a few as actual threats if confirmed
    }));
  }, [processCount, hasThreat]);

  const externalNodes = useMemo(() => {
    if (!hasNetwork && !isRunning) return []; // Only show network if we have data or are currently scanning
    return Array.from({ length: 3 }).map((_, i) => ({
      x: (Math.random() > 0.5 ? 1 : -1) * (3 + Math.random() * 2),
      y: (Math.random() - 0.5) * 4,
      z: (Math.random() > 0.5 ? 1 : -1) * (3 + Math.random() * 2),
      isMalicious: hasThreat && i === 0, // One node is the threat node
    }));
  }, [hasNetwork, isRunning, hasThreat]);

  // Refs for animated lines
  const lineRefs = useRef<any[]>([]);

  useFrame((state) => {
    const t = state.clock.getElapsedTime();
    
    // Core spin
    if (coreRef.current && isActive) {
      const targetSpeed = isRunning ? 2 : 0.2;
      coreRef.current.rotation.y += 0.01 * targetSpeed;
      coreRef.current.rotation.x = Math.sin(t) * 0.1;
      
      const scale = isRunning ? 1 + Math.sin(t * 4) * 0.05 : 1;
      coreRef.current.scale.lerp(new THREE.Vector3(scale, scale, scale), 0.1);
    }

    // Container boundary pulse
    if (containerRef.current) {
      containerRef.current.rotation.y = Math.sin(t * 0.2) * 0.05;
    }

    // Internal activity (processes/fs)
    if (internalGroup.current && isActive) {
      internalGroup.current.children.forEach((mesh, i) => {
        const p = internalParticles[i];
        if (p) {
          if (isRunning) {
            // Active floating
            mesh.position.y = p.y + Math.sin(t * p.speed + i) * 0.5;
            mesh.position.x = p.x + Math.cos(t * p.speed * 0.5 + i) * 0.5;
          } else {
            // Settled state (pull towards bottom or freeze)
            mesh.position.y = THREE.MathUtils.lerp(mesh.position.y, p.y * 0.2 - 1, 0.05);
          }
        }
      });
    }

    // External activity (network out)
    if (externalGroup.current && isRunning) {
      externalGroup.current.rotation.y = t * 0.1;
    }

    // Animate line dashes
    if (isRunning) {
      lineRefs.current.forEach((line) => {
        if (line && line.material) {
          line.material.dashOffset -= 0.02;
        }
      });
    }
  });

  if (!isActive && dynStage?.status !== 'pending') {
    return null; // Don't render until at least pending/started
  }

  return (
    <group>
      {/* 1. CONTAINMENT BOUNDARY */}
      <Box ref={containerRef} args={[4, 5, 4]}>
        <meshStandardMaterial 
          color="#080C14" 
          transparent 
          opacity={isRunning ? 0.3 : 0.1} 
          depthWrite={false}
        />
        <Wireframe 
          thickness={0.015} 
          stroke={isRunning ? "#5EE7FF" : "#334155"} 
          fillOpacity={0} 
        />
      </Box>

      {/* 2. APPLICATION CORE */}
      <Sphere ref={coreRef} args={[0.8, 32, 32]} position={[0, 0, 0]}>
        <meshStandardMaterial 
          color={coreColor} 
          emissive={coreColor} 
          emissiveIntensity={isRunning ? 0.6 : 0.2} 
          wireframe={!isCompleted}
          transparent
          opacity={0.8}
        />
      </Sphere>

      {/* 3. INTERNAL RUNTIME ACTIVITY (Processes/FS) */}
      <group ref={internalGroup}>
        {internalParticles.map((p, i) => (
          <mesh key={i} position={[p.x, p.y, p.z]}>
            <boxGeometry args={[0.08, 0.08, 0.08]} />
            <meshStandardMaterial 
              color={p.isThreat ? determineThreatColor() : normalColor}
              emissive={p.isThreat ? determineThreatColor() : normalColor}
              emissiveIntensity={isRunning ? 0.8 : 0.2}
            />
          </mesh>
        ))}
      </group>

      {/* 4. EXTERNAL NETWORK DESTINATIONS */}
      <group ref={externalGroup}>
        {externalNodes.map((node, i) => (
          <group key={`ext-${i}`}>
            <Sphere args={[0.15, 16, 16]} position={[node.x, node.y, node.z]}>
              <meshStandardMaterial 
                color={node.isMalicious ? determineThreatColor() : normalColor}
                emissive={node.isMalicious ? determineThreatColor() : normalColor}
                emissiveIntensity={0.5}
              />
            </Sphere>
            <Line
              ref={(el) => (lineRefs.current[i] = el)}
              points={[[0, 0, 0], [node.x, node.y, node.z]]}
              color={node.isMalicious ? determineThreatColor() : normalColor}
              lineWidth={1}
              transparent
              opacity={isRunning ? 0.4 : 0.1}
              dashed={isRunning}
              dashScale={10}
              dashSize={1}
            />
          </group>
        ))}
      </group>
    </group>
  );
}
