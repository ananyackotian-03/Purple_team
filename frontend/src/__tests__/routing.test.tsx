import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('@/hooks/useApi', () => ({
  useHealth: vi.fn().mockReturnValue({ data: { status: 'healthy', docker: 'available', ollama: 'available' }, isLoading: false, error: null }),
  useDashboard: vi.fn().mockReturnValue({ data: { total_objectives: 0, total_experiments: 0, completed_experiments: 0, total_detections: 0, detection_gaps: 0, coverage_pct: 0, total_retests: 0, retests_improved: 0, system_status: 'ok', recent_activities: [] }, isLoading: false, error: null, refetch: vi.fn() }),
  useOrganizations: vi.fn().mockReturnValue({ data: [], isLoading: false, error: null }),
  useObjectives: vi.fn().mockReturnValue({ data: [], isLoading: false, error: null, refetch: vi.fn() }),
  useCreateObjective: vi.fn().mockReturnValue({ mutate: vi.fn(), isPending: false }),
  useObjective: vi.fn().mockReturnValue({ data: null, isLoading: false, error: null, refetch: vi.fn() }),
  useRunExperiment: vi.fn().mockReturnValue({ mutate: vi.fn(), isPending: false }),
  useExperiments: vi.fn().mockReturnValue({ data: [], isLoading: false, error: null, refetch: vi.fn() }),
  useExperiment: vi.fn().mockReturnValue({ data: null, isLoading: false, error: null, refetch: vi.fn() }),
  useRetest: vi.fn().mockReturnValue({ data: null, isLoading: false }),
  useCoverage: vi.fn().mockReturnValue({ data: { report_id: 'r1', organization_id: 'org-1', total_experiments: 0, detected_experiments: 0, missed_experiments: 0, gap_experiments: 0, coverage_pct: 0, technique_coverage: {}, generated_at: '' }, isLoading: false, error: null, refetch: vi.fn() }),
  useRetests: vi.fn().mockReturnValue({ data: [], isLoading: false, error: null, refetch: vi.fn() }),
  useEvidenceTrace: vi.fn().mockReturnValue({ data: null, isLoading: false, error: null, refetch: vi.fn() }),
  useDetectionGaps: vi.fn().mockReturnValue({ data: [], isLoading: false, error: null, refetch: vi.fn() }),
  useDefensiveProposals: vi.fn().mockReturnValue({ data: [], isLoading: false, error: null }),
  useImmuneMemory: vi.fn().mockReturnValue({ data: { organization_id: 'org-1', previous_experiments: 0, techniques_tested: [], detection_outcomes: {}, detection_gaps: [], retest_results: [], coverage_pct: 0, mitigated_gaps: 0, unresolved_gaps: 0, successful_improvements: 0, failed_improvements: 0, defensive_proposals: [] }, isLoading: false, error: null, refetch: vi.fn() }),
  useNextExperiment: vi.fn().mockReturnValue({ data: null, isLoading: false, error: null, refetch: vi.fn() }),
  useImmuneCycleStatus: vi.fn().mockReturnValue({ data: null, isLoading: false, error: null, refetch: vi.fn() }),
  useTwinSummary: vi.fn().mockReturnValue({ data: { organization_id: 'org-1', organization_name: 'Org', total_assets: 0, assets_by_type: {}, total_services: 0, services_by_type: {}, internet_facing_services: 0, total_controls: 0, enabled_controls: 0, controls_by_type: {}, total_techniques_tested: 0, techniques_detected: 0, detection_coverage_pct: 0, high_risk_assets: 0, critical_risk_assets: 0, unresolved_gaps: 0, last_experiment_at: null, last_posture_snapshot_at: null, computed_at: '' }, isLoading: false, error: null, refetch: vi.fn() }),
  useTwinAssets: vi.fn().mockReturnValue({ data: { assets: [], total: 0 }, isLoading: false, error: null, refetch: vi.fn() }),
  useTwinServices: vi.fn().mockReturnValue({ data: { services: [], total: 0 }, isLoading: false, error: null, refetch: vi.fn() }),
  useTwinControls: vi.fn().mockReturnValue({ data: { controls: [], total: 0 }, isLoading: false, error: null, refetch: vi.fn() }),
  useTwinCoverage: vi.fn().mockReturnValue({ data: null, isLoading: false, error: null, refetch: vi.fn() }),
  useComputeTwinPosture: vi.fn().mockReturnValue({ mutate: vi.fn(), isPending: false }),
  useRunImmuneCycle: vi.fn().mockReturnValue({ mutate: vi.fn(), isPending: false }),
  useCreateDefensiveProposal: vi.fn().mockReturnValue({ mutate: vi.fn(), isPending: false }),
  useValidateDefensiveProposal: vi.fn().mockReturnValue({ mutate: vi.fn(), isPending: false }),
}))

import App from '@/App'

function renderAt(path: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>
  )
}

describe('Routing', () => {
  it('renders Overview at /', () => {
    renderAt('/')
    expect(screen.getByText('OVERVIEW')).toBeInTheDocument()
  })

  it('renders Digital Twin at /digital-twin', () => {
    renderAt('/digital-twin')
    expect(screen.getByText('DIGITAL TWIN')).toBeInTheDocument()
  })

  it('renders Objectives at /objectives', () => {
    renderAt('/objectives')
    expect(screen.getByText('SECURITY OBJECTIVES')).toBeInTheDocument()
  })

  it('renders Experiments at /experiments', () => {
    renderAt('/experiments')
    expect(screen.getByText('EXPERIMENTS')).toBeInTheDocument()
  })

  it('renders Detection at /detection', () => {
    renderAt('/detection')
    expect(screen.getByText('DETECTION')).toBeInTheDocument()
  })

  it('renders Detection Gaps at /detection-gaps', () => {
    renderAt('/detection-gaps')
    expect(screen.getByText('DETECTION GAPS')).toBeInTheDocument()
  })

  it('renders Defense & Retests at /defense-retests', () => {
    renderAt('/defense-retests')
    expect(screen.getByText('DEFENSIVE MITIGATION & VALIDATION')).toBeInTheDocument()
  })

  it('renders Immune Memory at /immune-memory', () => {
    renderAt('/immune-memory')
    expect(screen.getByText('IMMUNE MEMORY')).toBeInTheDocument()
  })

  it('renders Adaptive Testing at /adaptive-testing', () => {
    renderAt('/adaptive-testing')
    expect(screen.getByText('ADAPTIVE TESTING')).toBeInTheDocument()
  })

  it('renders Telemetry at /telemetry', () => {
    renderAt('/telemetry')
    expect(screen.getByText('TELEMETRY')).toBeInTheDocument()
  })

  it('renders Security Controls at /security-controls', () => {
    renderAt('/security-controls')
    expect(screen.getByText('SECURITY CONTROLS')).toBeInTheDocument()
  })

  it('renders Audit & Evidence at /audit', () => {
    renderAt('/audit')
    expect(screen.getByText('AUDIT & EVIDENCE')).toBeInTheDocument()
  })
})
