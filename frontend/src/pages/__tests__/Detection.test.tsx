import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Detection from '@/pages/Detection'

vi.mock('@/hooks/useApi', () => ({
  useCoverage: vi.fn(),
}))

import { useCoverage } from '@/hooks/useApi'
const mockUse = vi.mocked(useCoverage)

function renderWithProviders(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('Detection page', () => {
  it('shows loading', () => {
    mockUse.mockReturnValue({ data: undefined, isLoading: true, error: null, refetch: vi.fn() } as never)
    const { container } = renderWithProviders(<Detection />)
    expect(container.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows error state', () => {
    mockUse.mockReturnValue({ data: undefined, isLoading: false, error: new Error('fail'), refetch: vi.fn() } as never)
    renderWithProviders(<Detection />)
    expect(screen.getByText(/fail/)).toBeInTheDocument()
  })

  it('shows empty state when no data', () => {
    mockUse.mockReturnValue({ data: null, isLoading: false, error: null, refetch: vi.fn() } as never)
    renderWithProviders(<Detection />)
    expect(screen.getByText('No detection data')).toBeInTheDocument()
  })

  it('renders coverage data from backend', () => {
    mockUse.mockReturnValue({
      data: {
        report_id: 'r1',
        organization_id: 'org-1',
        total_experiments: 10,
        detected_experiments: 7,
        missed_experiments: 2,
        gap_experiments: 1,
        coverage_pct: 70.0,
        technique_coverage: { T1059: true, T1053: false },
        generated_at: '2024-01-01',
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as never)
    renderWithProviders(<Detection />)
    expect(screen.getByText('DETECTION')).toBeInTheDocument()
    expect(screen.getByText('10')).toBeInTheDocument()
    expect(screen.getByText('7')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
    expect(screen.getByText('1')).toBeInTheDocument()
    expect(screen.getByText('70.0%')).toBeInTheDocument()
    expect(screen.getByText('T1059')).toBeInTheDocument()
    expect(screen.getByText('T1053')).toBeInTheDocument()
    expect(screen.getAllByText('DETECTED').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('NOT DETECTED')).toBeInTheDocument()
  })
})
