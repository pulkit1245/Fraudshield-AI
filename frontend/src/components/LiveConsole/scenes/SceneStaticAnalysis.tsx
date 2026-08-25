import { useRef, useMemo } from 'react';
import { useFrame } from '@react-three/fiber';
import { Box, Plane, Wireframe } from '@react-three/drei';
import * as THREE from 'three';

interface Props {
  statusData?: any;
  detail?: any;
}

export default function SceneStaticAnalysis({ statusData, detail }: Props) {
  const groupRef = useRef<THREE.Group>(null);
  const scannerRef = useRef<THREE.Mesh>(null);

  // States
  const stages = statusData?.analysis_stages || [];
  const staticStage = stages.find((s: any) => s.stage === 'Static Analysis');
  
  const isRunning = staticStage?.status === 'running';
  const isCompleted = staticStage?.status === 'completed' || staticStage?.status === 'failed';
  const isActive = isRunning || isCompleted;
  
  const prefersReducedMotion = typeof window !== 'undefined' 
    ? window.matchMedia('(prefers-reduced-motion: reduce)').matches 
    : false;

  // Real Data Bindings
  const st = detail?.static_finding;
  const severityBand = detail?.verdict?.severity_band;
  const hasThreat = severityBand === 'high' || severityBand === 'critical';
  const hasWarning = severityBand === 'medium';
  
  const hasSuspiciousAPIs = st?.suspicious_apis && Object.keys(st.suspicious_apis).length > 0;
  const numPermissions = st?.permissions?.length || 0;
  
  const getThreatColor = (isThreatNode: boolean) => {
    if (!isThreatNode) return '#5EE7FF';
    if (hasThreat) return '#FF4D67';
    if (hasWarning) return '#FBBF24';
    return '#5EE7FF';
  };

  // Layers semantic definitions
  const layers = useMemo(() => [
    { 
      id: 'manifest',
      name: 'AndroidManifest.xml', 
      color: getThreatColor(numPermissions > 20 && (hasWarning || hasThreat)), 
      baseY: 1.5,
      components: Math.min(numPermissions, 15) || 5
    },
    { 
      id: 'dex',
      name: 'classes.dex', 
      color: getThreatColor(hasSuspiciousAPIs), 
      baseY: 0.5,
      components: 12
    },
    { 
      id: 'resources',
      name: 'resources.arsc', 
      color: '#6C7BFF', 
      baseY: -0.5,
      components: 8
    },
    { 
      id: 'meta',
      name: 'META-INF/', 
      color: '#CBD5E1', 
      baseY: -1.5,
      components: 3
    },
  ], [numPermissions, hasWarning, hasThreat, hasSuspiciousAPIs]);

  const layerRefs = useRef<THREE.Mesh[]>([]);

  useFrame((state) => {
    const t = state.clock.getElapsedTime();
    
    // Group subtle rotation
    if (groupRef.current && !prefersReducedMotion) {
      groupRef.current.rotation.y = Math.sin(t * 0.1) * 0.2;
      groupRef.current.rotation.x = Math.cos(t * 0.15) * 0.1;
    }

    // Layer separation and rotation
    layerRefs.current.forEach((layer, i) => {
      if (!layer) return;
      
      // If active, separate them out to their baseY. If idle, compact them at 0.
      const targetY = isActive ? layers[i].baseY : (i - 1.5) * 0.2;
      layer.position.y = THREE.MathUtils.lerp(layer.position.y, targetY, 0.05);

      if (isActive && !prefersReducedMotion) {
        // Individual layer floating
        layer.position.y += Math.sin(t + i) * 0.005;
        // The active stage might subtly rotate
        if (isRunning) {
          layer.rotation.y = Math.sin(t * 0.2 + i) * 0.05;
        } else {
          layer.rotation.y = THREE.MathUtils.lerp(layer.rotation.y, 0, 0.05);
        }
      }
    });

    // Scanner Plane Animation
    if (scannerRef.current) {
      if (isRunning && !prefersReducedMotion) {
        scannerRef.current.visible = true;
        // Sweep up and down across the layers (-2 to 2)
        scannerRef.current.position.y = Math.sin(t * 1.5) * 2;
        // Pulse opacity
        const mat = scannerRef.current.material as THREE.MeshBasicMaterial;
        mat.opacity = 0.3 + Math.sin(t * 5) * 0.2;
      } else {
        scannerRef.current.visible = false;
      }
    }
  });

  if (!isActive && staticStage?.status !== 'pending') {
    return null;
  }

  return (
    <group ref={groupRef}>
      {/* Structural Layers */}
      {layers.map((layer, i) => (
        <group key={layer.id}>
          <Box 
            ref={(el) => (layerRefs.current[i] = el as THREE.Mesh)} 
            args={[2.5, 0.15, 2.5]} 
            position={[0, 0, 0]}
          >
            <meshStandardMaterial 
              color={layer.color} 
              metalness={0.6} 
              roughness={0.2} 
              transparent 
              opacity={0.8}
            />
            <Wireframe thickness={0.03} stroke={layer.color} fillOpacity={0} />
            
            {/* Semantic internal structure representing data blocks */}
            {Array.from({ length: layer.components }).map((_, j) => {
              const x = (Math.random() - 0.5) * 1.8;
              const z = (Math.random() - 0.5) * 1.8;
              return (
                <mesh key={j} position={[x, 0.15, z]}>
                  <boxGeometry args={[0.15, 0.1, 0.15]} />
                  <meshStandardMaterial 
                    color={layer.color} 
                    emissive={layer.color}
                    emissiveIntensity={isRunning ? 0.5 : 0.1}
                  />
                </mesh>
              );
            })}
          </Box>
        </group>
      ))}
      
      {/* Forensic Scanning Plane */}
      <Plane 
        ref={scannerRef}
        args={[3.5, 3.5]} 
        rotation={[-Math.PI / 2, 0, 0]} 
        visible={false}
      >
        <meshBasicMaterial 
          color="#5EE7FF" 
          transparent 
          opacity={0.4} 
          side={THREE.DoubleSide}
          depthWrite={false}
          blending={THREE.AdditiveBlending}
        />
      </Plane>

      {/* Central Axis Core */}
      <mesh position={[0, 0, 0]}>
        <cylinderGeometry args={[0.02, 0.02, 4, 8]} />
        <meshBasicMaterial color="#334155" transparent opacity={isActive ? 0.3 : 0} />
      </mesh>
    </group>
  );
}
