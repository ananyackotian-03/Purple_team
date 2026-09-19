import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import AuditEvidence from '@/pages/AuditEvidence'

vi.mock('@/hooks/useApi', () => ({
  useExperiments: vi.fn(),
  useRetests: vi.fn(),
}))

import { useExperiments, useRetests } from '@/hooks/useApi'
const mockExperiments = vi.mocked(useExperiments)
const mockRetests = vi.mocked(useRetests)

function renderWithProviders(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('AuditEvidence page', () => {
  it('shows loading', () => {
    mockExperiments.mockReturnValue({ data: undefined, isLoading: true, error: null, refetch: vi.fn() } as never)
    mockRetests.mockReturnValue({ data: undefined, isLoading: true, error: null, refetch: vi.fn() } as never)
    const { container } = renderWithProviders(<AuditEvidence />)
    expect(container.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows error state', () => {
    mockExperiments.mockReturnValue({ data: undefined, isLoading: false, error: new Error('fail'), refetch: vi.fn() } as never)
    mockRetests.mockReturnValue({ data: undefined, isLoading: false, error: null, refetch: vi.fn() } as never)
    renderWithProviders(<AuditEvidence />)
    expect(screen.getByText(/fail/)).toBeInTheDocument()
  })

  it('shows empty state when no completed experiments', () => {
    mockExperiments.mockReturnValue({ data: [], isLoading: false, error: null, refetch: vi.fn() } as never)
    mockRetests.mockReturnValue({ data: [], isLoading: false, error: null, refetch: vi.fn() } as never)
    renderWithProviders(<AuditEvidence />)
    expect(screen.getByText('No evidence records')).toBeInTheDocument()
  })

  it('renders evidence chain', () => {
    mockExperiments.mockReturnValue({ data: [], isLoading: false, error: null, refetch: vi.fn() } as never)
    mockRetests.mockReturnValue({ data: [], isLoading: false, error: null, refetch: vi.fn() } as never)
    renderWithProviders(<AuditEvidence />)
    expect(screen.getByText('EVIDENCE CHAIN')).toBeInTheDocument()
    expect(screen.getByText('OBJECTIVE')).toBeInTheDocument()
    expect(screen.getByText('DETECTION')).toBeInTheDocument()
    expect(screen.getByText('RETEST')).toBeInTheDocument()
  })

  it('renders completed experiments as evidence', () => {
    mockExperiments.mockReturnValue({
      data: [
        {
          id: 'exp-1',
          organization_id: 'org-1',
          objective_id: 'obj-1',
          title: 'SQLi Evidence',
          strategy_description: null,
          risk_level: 'HIGH',
          status: 'DETECTED',
          created_by: null,
          created_at: '2024-01-15',
        },
      ],
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as never)
    mockRetests.mockReturnValue({ data: [], isLoading: false, error: null, refetch: vi.fn() } as never)
    renderWithProviders(<AuditEvidence />)
    expect(screen.getByText('SQLi Evidence')).toBeInTheDocument()
    expect(screen.getByText('DETECTED')).toBeInTheDocument()
    expect(screen.getByText('HIGH')).toBeInTheDocument()
    expect(screen.getByText('VIEW')).toBeInTheDocument()
  })

  it('links to evidence trace', () => {
    mockExperiments.mockReturnValue({
      data: [
        {
          id: 'exp-1',
          organization_id: 'org-1',
          objective_id: 'obj-1',
          title: 'Test',
          strategy_description: null,
          risk_level: null,
          status: 'NOT_DETECTED',
          created_by: null,
          created_at: null,
        },
      ],
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as never)
    mockRetests.mockReturnValue({ data: [], isLoading: false, error: null, refetch: vi.fn() } as never)
    renderWithProviders(<AuditEvidence />)
    const viewLinks = screen.getAllByText('VIEW')
    expect(viewLinks.length).toBeGreaterThan(0)
  })
})
