import { useRef, useMemo } from 'react';
import { useFrame } from '@react-three/fiber';
import { Line, Sphere, Octahedron, Ring } from '@react-three/drei';
import * as THREE from 'three';

interface Props {
  statusData?: any;
  detail?: any;
  virustotal?: any;
}

type NodeType = 'apk' | 'hash' | 'domain' | 'ip' | 'vt' | 'family' | 'cluster';

interface GraphNode {
  id: string;
  type: NodeType;
  isThreat: boolean;
  isWarning: boolean;
  isUnknown: boolean;
  parentIndex: number;
  targetPos: [number, number, number];
}

export default function SceneThreatIntel({ statusData, detail, virustotal }: Props) {
  const groupRef = useRef<THREE.Group>(null);
  const pulsesRef = useRef<THREE.Mesh[]>([]);

  // State checks
  const stages = statusData?.analysis_stages || [];
  const tiStage = stages.find((s: any) => s.stage === 'Threat Intelligence');
  
  const isRunning = tiStage?.status === 'running';
  const isCompleted = tiStage?.status === 'completed' || tiStage?.status === 'failed';
  const isActive = isRunning || isCompleted;

  const prefersReducedMotion = typeof window !== 'undefined' 
    ? window.matchMedia('(prefers-reduced-motion: reduce)').matches 
    : false;

  // Colors
  const normalColor = '#5EE7FF';
  const aiColor = '#A78BFA';
  const unknownColor = '#64748B'; // slate
  const warningColor = '#FBBF24';
  const threatColor = '#FF4D67';
  const safeColor = '#4ADE80';

  const getNodeColor = (node: GraphNode) => {
    if (node.isThreat) return threatColor;
    if (node.isWarning) return warningColor;
    if (node.isUnknown) return unknownColor;
    if (node.type === 'vt' && !node.isThreat && !node.isWarning && !node.isUnknown) return safeColor;
    if (node.type === 'cluster' || node.type === 'family') return aiColor;
    return normalColor;
  };

  // Build the constellation graph deterministically based on REAL data
  const nodes = useMemo(() => {
    const g: GraphNode[] = [];
    if (!detail) return g;

    const severityBand = detail.verdict?.severity_band;
    const overallThreat = severityBand === 'high' || severityBand === 'critical';
    const overallWarning = severityBand === 'medium';

    const vtMalicious = virustotal?.malicious || 0;
    const vtSuspicious = virustotal?.suspicious || 0;
    const isVtThreat = vtMalicious > 0;
    const isVtWarning = vtSuspicious > 0 && !isVtThreat;

    // 0: Central APK Node
    g.push({
      id: 'apk',
      type: 'apk',
      isThreat: overallThreat,
      isWarning: overallWarning,
      isUnknown: false,
      parentIndex: -1,
      targetPos: [0, 0, 0]
    });

    // 1: Hash Indicator
    if (detail.sha256) {
      g.push({
        id: 'hash',
        type: 'hash',
        isThreat: isVtThreat || overallThreat,
        isWarning: isVtWarning || overallWarning,
        isUnknown: false,
        parentIndex: 0,
        targetPos: [0, 1.5, -1]
      });
    }
    const hashIndex = g.findIndex(n => n.id === 'hash');
    const hashParent = hashIndex !== -1 ? hashIndex : 0;

    // 2: VT Reputation
    if (virustotal && virustotal.status === 'ok') {
      g.push({
        id: 'vt',
        type: 'vt',
        isThreat: isVtThreat,
        isWarning: isVtWarning,
        isUnknown: false,
        parentIndex: hashParent,
        targetPos: [-1.5, 2.5, -1.5]
      });
      
      // 3: Malware Family
      if (virustotal.malware_family) {
        g.push({
          id: 'family',
          type: 'family',
          isThreat: true,
          isWarning: false,
          isUnknown: false,
          parentIndex: g.length - 1, // connect to VT
          targetPos: [-2.5, 3.2, -2]
        });
      }
    } else if (virustotal && virustotal.status !== 'not_configured') {
      // VT checked but not found / error
      g.push({
        id: 'vt-unknown',
        type: 'vt',
        isThreat: false,
        isWarning: false,
        isUnknown: true,
        parentIndex: hashParent,
        targetPos: [-1.5, 2.5, -1.5]
      });
    }

    // Cluster Indicator
    if (detail.cluster?.cluster_id) {
      g.push({
        id: 'cluster',
        type: 'cluster',
        isThreat: detail.cluster.risk_score > 70,
        isWarning: detail.cluster.risk_score >= 40 && detail.cluster.risk_score <= 70,
        isUnknown: false,
        parentIndex: hashParent,
        targetPos: [1.5, 2.5, -1.5]
      });
    }

    // Network Indicators (IPs & Domains)
    const netEvents = detail.dynamic_finding?.network_events || [];
    const uniqueDomains = Array.from(new Set(netEvents.map((e: any) => e.destination_host).filter(Boolean))).slice(0, 3) as string[];
    const uniqueIPs = Array.from(new Set(netEvents.map((e: any) => e.destination_ip).filter(Boolean))).slice(0, 3) as string[];

    uniqueDomains.forEach((_, i) => {
      // If overall threat, we arbitrarily paint the first domain as threat to visually represent the correlation (since we lack domain-specific threat API data)
      const isBad = overallThreat && i === 0;
      g.push({
        id: `dom-${i}`,
        type: 'domain',
        isThreat: isBad,
        isWarning: false,
        isUnknown: false,
        parentIndex: 0,
        targetPos: [-2 + i * 2, -1.5, 1.5 + (i%2)]
      });
    });

    uniqueIPs.forEach((_, i) => {
      const isBad = overallThreat && uniqueDomains.length === 0 && i === 0;
      g.push({
        id: `ip-${i}`,
        type: 'ip',
        isThreat: isBad,
        isWarning: false,
        isUnknown: false,
        parentIndex: 0,
        targetPos: [2 - i * 1.5, -1.8, 1 - (i%2)]
      });
    });

    return g;
  }, [detail, virustotal]);

  const nodeGroupsRef = useRef<THREE.Group[]>([]);
  
  useFrame((state) => {
    const t = state.clock.getElapsedTime();
    
    // Ambient constellation rotation
    if (groupRef.current && !prefersReducedMotion) {
      groupRef.current.rotation.y = Math.sin(t * 0.05) * 0.1;
      groupRef.current.rotation.x = Math.sin(t * 0.02) * 0.05;
    }

    // Expand / Stabilize logic (scale up instead of moving positions to preserve Line geometry)
    if (isActive) {
      nodes.forEach((node, i) => {
        const group = nodeGroupsRef.current[i];
        if (group) {
          // Scale from 0 to 1
          const targetScale = 1;
          group.scale.lerp(new THREE.Vector3(targetScale, targetScale, targetScale), prefersReducedMotion ? 1 : 0.05);

          if (isRunning && !prefersReducedMotion) {
            // Subtle floating in place
            group.position.y = node.targetPos[1] + Math.sin(t * 1.2 + i) * 0.1;
          } else {
            group.position.y = THREE.MathUtils.lerp(group.position.y, node.targetPos[1], 0.05);
          }
        }
      });
    }

    // Signal Pulses along connections
    if (isRunning && !prefersReducedMotion && pulsesRef.current.length > 0) {
      nodes.forEach((node, i) => {
        if (node.parentIndex === -1) return;
        const pulse = pulsesRef.current[i];
        const parentPos = nodes[node.parentIndex].targetPos;
        
        if (pulse && parentPos) {
          // Calculate a traveling offset (0 to 1) based on time and index
          const progress = (t * 0.5 + i * 0.2) % 1;
          
          const pVec = new THREE.Vector3(...parentPos);
          const cVec = new THREE.Vector3(...node.targetPos);
          
          pulse.position.copy(pVec).lerp(cVec, progress);
          pulse.visible = true;
        }
      });
    } else {
      pulsesRef.current.forEach(p => { if (p) p.visible = false; });
    }
  });

  if (!isActive && tiStage?.status !== 'pending') return null;

  return (
    <group ref={groupRef}>
      {nodes.map((node, i) => {
        const c = getNodeColor(node);
        const parentPos = node.parentIndex !== -1 ? nodes[node.parentIndex].targetPos : null;

        return (
          <group key={node.id}>
            {/* The Node Object */}
            <group 
              ref={(el) => (nodeGroupsRef.current[i] = el as THREE.Group)}
              position={new THREE.Vector3(...node.targetPos)} 
              scale={[0.01, 0.01, 0.01]}
            >
              {node.type === 'apk' && (
                <Octahedron args={[0.5, 0]}>
                  <meshStandardMaterial color={c} emissive={c} emissiveIntensity={isRunning ? 0.6 : 0.2} wireframe={isRunning} />
                </Octahedron>
              )}
              {node.type === 'hash' && (
                <Sphere args={[0.15, 16, 16]}>
                  <meshStandardMaterial color={c} emissive={c} emissiveIntensity={0.4} />
                </Sphere>
              )}
              {node.type === 'vt' && (
                <Octahedron args={[0.3, 1]}>
                  <meshStandardMaterial color={c} emissive={c} emissiveIntensity={0.5} />
                </Octahedron>
              )}
              {node.type === 'cluster' && (
                <Octahedron args={[0.3, 1]}>
                  <meshStandardMaterial color={c} emissive={c} emissiveIntensity={0.5} wireframe />
                </Octahedron>
              )}
              {node.type === 'family' && (
                <Sphere args={[0.2, 8, 8]}>
                  <meshStandardMaterial color={c} emissive={c} emissiveIntensity={0.8} wireframe />
                </Sphere>
              )}
              {node.type === 'domain' && (
                <group>
                  <Sphere args={[0.12, 16, 16]}>
                    <meshStandardMaterial color={c} />
                  </Sphere>
                  <Ring args={[0.2, 0.22, 16]} rotation={[Math.PI/2, 0, 0]}>
                    <meshBasicMaterial color={c} side={THREE.DoubleSide} transparent opacity={0.6} />
                  </Ring>
                </group>
              )}
              {node.type === 'ip' && (
                <Sphere args={[0.1, 8, 8]}>
                  <meshStandardMaterial color={c} emissive={c} emissiveIntensity={0.2} />
                </Sphere>
              )}
            </group>

            {/* Connection Line to Parent */}
            {parentPos && (
              <Line
                points={[new THREE.Vector3(...parentPos), new THREE.Vector3(...node.targetPos)]}
                color={c}
                lineWidth={1}
                transparent
                opacity={isRunning ? 0.3 : 0.1}
              />
            )}

            {/* Signal Pulse Mesh */}
            {parentPos && (
              <mesh ref={(el) => (pulsesRef.current[i] = el as THREE.Mesh)} visible={false}>
                <sphereGeometry args={[0.04, 8, 8]} />
                <meshBasicMaterial color={c} />
              </mesh>
            )}
          </group>
        );
      })}
    </group>
  );
}
