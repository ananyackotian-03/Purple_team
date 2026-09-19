import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Overview from '@/pages/Overview'

vi.mock('@/hooks/useApi', () => ({
  useDashboard: vi.fn(),
  useOrganizations: vi.fn(),
  useImmuneCycleStatus: vi.fn().mockReturnValue({ data: null, isLoading: false, error: null, refetch: vi.fn() }),
  useRunImmuneCycle: vi.fn().mockReturnValue({ mutate: vi.fn(), isPending: false }),
}))

import { useDashboard, useOrganizations } from '@/hooks/useApi'
const mockUseDashboard = vi.mocked(useDashboard)
const mockUseOrganizations = vi.mocked(useOrganizations)

function renderWithProviders(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('Overview page', () => {
  it('shows loading spinner', () => {
    mockUseDashboard.mockReturnValue({ data: undefined, isLoading: true, error: null, refetch: vi.fn() } as never)
    mockUseOrganizations.mockReturnValue({ data: undefined, isLoading: true, error: null, refetch: vi.fn() } as never)
    const { container } = renderWithProviders(<Overview />)
    expect(container.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows error state', () => {
    mockUseDashboard.mockReturnValue({ data: undefined, isLoading: false, error: new Error('fail'), refetch: vi.fn() } as never)
    mockUseOrganizations.mockReturnValue({ data: undefined, isLoading: false, error: null, refetch: vi.fn() } as never)
    renderWithProviders(<Overview />)
    expect(screen.getByText(/fail/)).toBeInTheDocument()
  })

  it('renders dashboard metrics', () => {
    mockUseDashboard.mockReturnValue({
      data: {
        total_objectives: 5,
        total_experiments: 12,
        completed_experiments: 10,
        total_detections: 8,
        detection_gaps: 2,
        coverage_pct: 72.5,
        total_retests: 3,
        retests_improved: 2,
        system_status: 'ok',
        recent_activities: [],
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as never)
    mockUseOrganizations.mockReturnValue({ data: undefined, isLoading: false, error: null, refetch: vi.fn() } as never)
    renderWithProviders(<Overview />)
    expect(screen.getByText('OVERVIEW')).toBeInTheDocument()
    expect(screen.getByText('5')).toBeInTheDocument()
    expect(screen.getByText('12')).toBeInTheDocument()
  })

  it('renders activity feed', () => {
    mockUseDashboard.mockReturnValue({
      data: {
        total_objectives: 1,
        total_experiments: 1,
        completed_experiments: 1,
        total_detections: 1,
        detection_gaps: 0,
        coverage_pct: 100,
        total_retests: 0,
        retests_improved: 0,
        system_status: 'ok',
        recent_activities: [
          { type: 'experiment', title: 'Test Exp', objective: 'Obj 1', risk_level: 'HIGH', created_by: 'red', timestamp: '2024-01-01' },
        ],
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as never)
    mockUseOrganizations.mockReturnValue({ data: undefined, isLoading: false, error: null, refetch: vi.fn() } as never)
    renderWithProviders(<Overview />)
    expect(screen.getByText('Test Exp')).toBeInTheDocument()
    expect(screen.getByText('HIGH')).toBeInTheDocument()
  })

  it('shows empty state when no activities', () => {
    mockUseDashboard.mockReturnValue({
      data: {
        total_objectives: 0, total_experiments: 0, completed_experiments: 0,
        total_detections: 0, detection_gaps: 0, coverage_pct: 0,
        total_retests: 0, retests_improved: 0, system_status: 'ok', recent_activities: [],
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as never)
    mockUseOrganizations.mockReturnValue({ data: undefined, isLoading: false, error: null, refetch: vi.fn() } as never)
    renderWithProviders(<Overview />)
    expect(screen.getByText('No activity yet')).toBeInTheDocument()
  })
})
