import { Suspense, lazy } from 'react';
import { Canvas } from '@react-three/fiber';
import { OrbitControls, Environment, BakeShadows } from '@react-three/drei';

const SceneAPKReceived = lazy(() => import('./scenes/SceneAPKReceived'));
const SceneStaticAnalysis = lazy(() => import('./scenes/SceneStaticAnalysis'));
const SceneDynamicAnalysis = lazy(() => import('./scenes/SceneDynamicAnalysis'));
const SceneThreatIntel = lazy(() => import('./scenes/SceneThreatIntel'));
const SceneMLScoring = lazy(() => import('./scenes/SceneMLScoring'));
const SceneLLMReport = lazy(() => import('./scenes/SceneLLMReport'));
const SceneFinalVerdict = lazy(() => import('./scenes/SceneFinalVerdict'));

interface SceneContainerProps {
  activeStage: string;
  
  statusData?: any;
  detail?: any;
  virustotal?: any;
  mlScore?: any;
  report?: any;
}

export default function SceneContainer({ activeStage, statusData, detail, virustotal, mlScore, report }: SceneContainerProps) {
  // Use a fallback while loading the heavy 3D chunks
  const fallback = (
    <div className="absolute inset-0 flex items-center justify-center bg-background/50 backdrop-blur-sm">
      <div className="w-8 h-8 rounded-full border-2 border-primary-cyan border-t-transparent animate-spin" />
    </div>
  );

  return (
    <div className="relative w-full h-full bg-background-elevated rounded-xl overflow-hidden border border-border">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-background-surface to-background z-0" />
      
      <Suspense fallback={fallback}>
        <Canvas
          shadows
          camera={{ position: [0, 2, 8], fov: 45 }}
          className="z-10"
          gl={{ antialias: true, alpha: true }}
          dpr={[1, 2]} // Support retina
        >
          {/* Global lighting */}
          <ambientLight intensity={0.4} />
          <directionalLight position={[5, 10, 5]} intensity={1} castShadow />
          <pointLight position={[-5, 5, -5]} intensity={0.5} color="#5EE7FF" />
          
          <OrbitControls 
            enablePan={false} 
            enableZoom={false} 
            maxPolarAngle={Math.PI / 2} 
            minPolarAngle={Math.PI / 4}
            autoRotate
            autoRotateSpeed={0.5}
          />
          <Environment preset="city" />
          <BakeShadows />

          {activeStage === 'APK Received' && <SceneAPKReceived />}
          {activeStage === 'Static Analysis' && <SceneStaticAnalysis statusData={statusData} detail={detail} />}
          {activeStage === 'Dynamic Analysis' && <SceneDynamicAnalysis statusData={statusData} detail={detail} />}
          {activeStage === 'Threat Intelligence' && <SceneThreatIntel statusData={statusData} detail={detail} virustotal={virustotal} />}
          {activeStage === 'ML Risk Scoring' && <SceneMLScoring statusData={statusData} detail={detail} mlScore={mlScore} />}
          {activeStage === 'LLM Security Report' && <SceneLLMReport statusData={statusData} detail={detail} report={report} />}
          {activeStage === 'Final Verdict' && <SceneFinalVerdict statusData={statusData} detail={detail} />}
          {/* Fallback to idle if none match or it's queued/done but we want to show verdict */}
          {!['APK Received', 'Static Analysis', 'Dynamic Analysis', 'Threat Intelligence', 'ML Risk Scoring', 'LLM Security Report', 'Final Verdict'].includes(activeStage) && (
            <SceneFinalVerdict statusData={statusData} detail={detail} />
          )}
        </Canvas>
      </Suspense>
      
      <div className="absolute inset-0 pointer-events-none shadow-[inset_0_0_100px_rgba(5,7,11,0.8)] z-20" />
    </div>
  );
}
