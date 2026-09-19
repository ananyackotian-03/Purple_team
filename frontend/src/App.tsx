import { Routes, Route } from 'react-router-dom'
import Layout from '@/components/Layout'
import { EmptyState } from '@/components/Shared'
import Overview from '@/pages/Overview'
import DigitalTwin from '@/pages/DigitalTwin'
import Objectives from '@/pages/Objectives'
import ObjectiveDetail from '@/pages/ObjectiveDetail'
import Experiments from '@/pages/Experiments'
import ExperimentDetail from '@/pages/ExperimentDetail'
import Detection from '@/pages/Detection'
import DetectionGaps from '@/pages/DetectionGaps'
import DefenseRetests from '@/pages/DefenseRetests'
import ImmuneMemoryPage from '@/pages/ImmuneMemory'
import AdaptiveTesting from '@/pages/AdaptiveTesting'
import Telemetry from '@/pages/Telemetry'
import SecurityControls from '@/pages/SecurityControls'
import AuditEvidence from '@/pages/AuditEvidence'
import EvidenceTrace from '@/pages/EvidenceTrace'

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Overview />} />
        <Route path="/digital-twin" element={<DigitalTwin />} />
        <Route path="/objectives" element={<Objectives />} />
        <Route path="/objectives/:id" element={<ObjectiveDetail />} />
        <Route path="/experiments" element={<Experiments />} />
        <Route path="/experiments/:id" element={<ExperimentDetail />} />
        <Route path="/detection" element={<Detection />} />
        <Route path="/detection-gaps" element={<DetectionGaps />} />
        <Route path="/defense-retests" element={<DefenseRetests />} />
        <Route path="/immune-memory" element={<ImmuneMemoryPage />} />
        <Route path="/adaptive-testing" element={<AdaptiveTesting />} />
        <Route path="/telemetry" element={<Telemetry />} />
        <Route path="/security-controls" element={<SecurityControls />} />
        <Route path="/audit" element={<AuditEvidence />} />
        <Route path="/evidence/:id" element={<EvidenceTrace />} />
        <Route path="*" element={<div className="pt-12"><EmptyState title="404 Not Found" description="The requested page does not exist." /></div>} />
      </Route>
    </Routes>
  )
}
