import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ImmuneMemoryPage from '@/pages/ImmuneMemory'

vi.mock('@/hooks/useApi', () => ({
  useImmuneMemory: vi.fn(),
}))

import { useImmuneMemory } from '@/hooks/useApi'
const mockUse = vi.mocked(useImmuneMemory)

function renderWithProviders(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('ImmuneMemory page', () => {
  it('shows loading', () => {
    mockUse.mockReturnValue({ data: undefined, isLoading: true, error: null, refetch: vi.fn() } as never)
    const { container } = renderWithProviders(<ImmuneMemoryPage />)
    expect(container.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows error state', () => {
    mockUse.mockReturnValue({ data: undefined, isLoading: false, error: new Error('fail'), refetch: vi.fn() } as never)
    renderWithProviders(<ImmuneMemoryPage />)
    expect(screen.getByText(/fail/)).toBeInTheDocument()
  })

  it('shows empty state when no data', () => {
    mockUse.mockReturnValue({ data: null, isLoading: false, error: null, refetch: vi.fn() } as never)
    renderWithProviders(<ImmuneMemoryPage />)
    expect(screen.getByText('No immune memory')).toBeInTheDocument()
  })

  it('renders immune memory data from backend', () => {
    mockUse.mockReturnValue({
      data: {
        organization_id: 'org-1',
        previous_experiments: 15,
        techniques_tested: ['T1059', 'T1053', 'T1190'],
        detection_outcomes: { DETECTED: 10, NOT_DETECTED: 5 },
        detection_gaps: [],
        retest_results: [],
        coverage_pct: 66.7,
        mitigated_gaps: 3,
        unresolved_gaps: 2,
        successful_improvements: 4,
        failed_improvements: 1,
        defensive_proposals: [],
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as never)
    renderWithProviders(<ImmuneMemoryPage />)
    expect(screen.getByText('IMMUNE MEMORY')).toBeInTheDocument()
    expect(screen.getByText('15')).toBeInTheDocument()
    expect(screen.getAllByText('3').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('2')).toBeInTheDocument()
    expect(screen.getByText('66.7%')).toBeInTheDocument()
    expect(screen.getByText('T1059')).toBeInTheDocument()
    expect(screen.getByText('T1053')).toBeInTheDocument()
    expect(screen.getByText('T1190')).toBeInTheDocument()
    expect(screen.getByText('DETECTED')).toBeInTheDocument()
    expect(screen.getByText('10')).toBeInTheDocument()
    expect(screen.getByText('5')).toBeInTheDocument()
  })

  it('displays backend mitigated/unresolved counts', () => {
    mockUse.mockReturnValue({
      data: {
        organization_id: 'org-1',
        previous_experiments: 5,
        techniques_tested: [],
        detection_outcomes: {},
        detection_gaps: [],
        retest_results: [],
        coverage_pct: 0,
        mitigated_gaps: 7,
        unresolved_gaps: 3,
        successful_improvements: 2,
        failed_improvements: 0,
        defensive_proposals: [],
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as never)
    renderWithProviders(<ImmuneMemoryPage />)
    expect(screen.getByText('7')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
  })
})
