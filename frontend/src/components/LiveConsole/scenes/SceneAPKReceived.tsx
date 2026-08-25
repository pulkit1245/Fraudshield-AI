import { useRef } from 'react';
import { useFrame } from '@react-three/fiber';
import { Box, Cylinder, Wireframe } from '@react-three/drei';
import * as THREE from 'three';

export default function SceneAPKReceived() {
  const scanGroup = useRef<THREE.Group>(null);
  const ringRef = useRef<THREE.Mesh>(null);

  useFrame((state) => {
    const t = state.clock.getElapsedTime();
    if (scanGroup.current) {
      scanGroup.current.position.y = Math.sin(t * 2) * 0.2;
    }
    if (ringRef.current) {
      ringRef.current.position.y = (Math.sin(t * 1.5) * 1.5);
      ringRef.current.scale.setScalar(1 + Math.sin(t * 3) * 0.05);
    }
  });

  return (
    <group>
      {/* Containment Chamber */}
      <Cylinder args={[3, 3, 4, 32]} position={[0, 0, 0]}>
        <meshStandardMaterial color="#0D1320" transparent opacity={0.3} wireframe />
      </Cylinder>
      
      {/* APK Object */}
      <group ref={scanGroup} position={[0, 0, 0]}>
        <Box args={[1.5, 2, 0.5]}>
          <meshStandardMaterial color="#5EE7FF" metalness={0.8} roughness={0.2} />
          <Wireframe thickness={0.02} stroke="#CBD5E1" />
        </Box>
        <Box args={[1.6, 2.1, 0.6]} visible={false}>
          <meshBasicMaterial color="#5EE7FF" transparent opacity={0.1} />
        </Box>
      </group>

      {/* Scanning Ring */}
      <Cylinder ref={ringRef} args={[2.5, 2.5, 0.1, 32]} position={[0, -1, 0]}>
        <meshBasicMaterial color="#4ADE80" transparent opacity={0.6} side={THREE.DoubleSide} />
      </Cylinder>
    </group>
  );
}
