import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import DigitalTwin from '@/pages/DigitalTwin'

vi.mock('@/hooks/useApi', () => ({
  useTwinSummary: vi.fn(),
  useTwinAssets: vi.fn(),
  useTwinServices: vi.fn(),
  useTwinControls: vi.fn(),
  useTwinCoverage: vi.fn().mockReturnValue({ data: null, isLoading: false, error: null, refetch: vi.fn() }),
  useComputeTwinPosture: vi.fn().mockReturnValue({ mutate: vi.fn(), isPending: false }),
}))

import { useTwinSummary, useTwinAssets, useTwinServices, useTwinControls } from '@/hooks/useApi'
const mockSummary = vi.mocked(useTwinSummary)
const mockAssets = vi.mocked(useTwinAssets)
const mockServices = vi.mocked(useTwinServices)
const mockControls = vi.mocked(useTwinControls)

function renderWithProviders(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('DigitalTwin page', () => {
  it('shows loading', () => {
    mockSummary.mockReturnValue({ data: undefined, isLoading: true, error: null, refetch: vi.fn() } as never)
    mockAssets.mockReturnValue({ data: undefined, isLoading: true, error: null, refetch: vi.fn() } as never)
    mockServices.mockReturnValue({ data: undefined, isLoading: true, error: null, refetch: vi.fn() } as never)
    mockControls.mockReturnValue({ data: undefined, isLoading: true, error: null, refetch: vi.fn() } as never)
    const { container } = renderWithProviders(<DigitalTwin />)
    expect(container.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('renders summary data from backend', () => {
    mockSummary.mockReturnValue({
      data: {
        organization_id: 'org-1',
        organization_name: 'TestOrg',
        total_assets: 5,
        assets_by_type: { server: 3, workstation: 2 },
        total_services: 8,
        services_by_type: { web: 4, db: 4 },
        internet_facing_services: 2,
        total_controls: 4,
        enabled_controls: 3,
        controls_by_type: { sigma: 2, network: 1 },
        total_techniques_tested: 10,
        techniques_detected: 7,
        detection_coverage_pct: 70.0,
        high_risk_assets: 1,
        critical_risk_assets: 0,
        unresolved_gaps: 2,
        last_experiment_at: null,
        last_posture_snapshot_at: null,
        computed_at: '2024-01-01',
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as never)
    mockAssets.mockReturnValue({ data: { assets: [], total: 0 }, isLoading: false, error: null, refetch: vi.fn() } as never)
    mockServices.mockReturnValue({ data: { services: [], total: 0 }, isLoading: false, error: null, refetch: vi.fn() } as never)
    mockControls.mockReturnValue({ data: { controls: [], total: 0 }, isLoading: false, error: null, refetch: vi.fn() } as never)
    renderWithProviders(<DigitalTwin />)
    expect(screen.getByText('DIGITAL TWIN')).toBeInTheDocument()
    expect(screen.getByText('5')).toBeInTheDocument()
    expect(screen.getByText('8')).toBeInTheDocument()
    expect(screen.getByText('70.0%')).toBeInTheDocument()
  })

  it('shows high risk warning', () => {
    mockSummary.mockReturnValue({
      data: {
        organization_id: 'org-1', organization_name: 'Org',
        total_assets: 1, assets_by_type: {}, total_services: 0, services_by_type: {},
        internet_facing_services: 0, total_controls: 0, enabled_controls: 0,
        controls_by_type: {}, total_techniques_tested: 0, techniques_detected: 0,
        detection_coverage_pct: 0, high_risk_assets: 3, critical_risk_assets: 1,
        unresolved_gaps: 0, last_experiment_at: null, last_posture_snapshot_at: null,
        computed_at: '2024-01-01',
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as never)
    mockAssets.mockReturnValue({ data: { assets: [], total: 0 }, isLoading: false, error: null, refetch: vi.fn() } as never)
    mockServices.mockReturnValue({ data: { services: [], total: 0 }, isLoading: false, error: null, refetch: vi.fn() } as never)
    mockControls.mockReturnValue({ data: { controls: [], total: 0 }, isLoading: false, error: null, refetch: vi.fn() } as never)
    renderWithProviders(<DigitalTwin />)
    expect(screen.getByText(/3 high-risk asset/)).toBeInTheDocument()
    expect(screen.getByText(/1 critical/)).toBeInTheDocument()
  })

  it('shows empty state when no data', () => {
    mockSummary.mockReturnValue({
      data: {
        organization_id: 'org-1', organization_name: 'Org',
        total_assets: 0, assets_by_type: {}, total_services: 0, services_by_type: {},
        internet_facing_services: 0, total_controls: 0, enabled_controls: 0,
        controls_by_type: {}, total_techniques_tested: 0, techniques_detected: 0,
        detection_coverage_pct: 0, high_risk_assets: 0, critical_risk_assets: 0,
        unresolved_gaps: 0, last_experiment_at: null, last_posture_snapshot_at: null,
        computed_at: '2024-01-01',
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as never)
    mockAssets.mockReturnValue({ data: { assets: [], total: 0 }, isLoading: false, error: null, refetch: vi.fn() } as never)
    mockServices.mockReturnValue({ data: { services: [], total: 0 }, isLoading: false, error: null, refetch: vi.fn() } as never)
    mockControls.mockReturnValue({ data: { controls: [], total: 0 }, isLoading: false, error: null, refetch: vi.fn() } as never)
    renderWithProviders(<DigitalTwin />)
    expect(screen.getByText('No digital twin data')).toBeInTheDocument()
  })
})
