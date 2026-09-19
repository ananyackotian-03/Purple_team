import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import AdaptiveTesting from '@/pages/AdaptiveTesting'

vi.mock('@/hooks/useApi', () => ({
  useNextExperiment: vi.fn(),
  useImmuneCycleStatus: vi.fn(),
}))

import { useNextExperiment, useImmuneCycleStatus } from '@/hooks/useApi'
const mockNext = vi.mocked(useNextExperiment)
const mockCycle = vi.mocked(useImmuneCycleStatus)

function renderWithProviders(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('AdaptiveTesting page', () => {
  it('shows loading', () => {
    mockNext.mockReturnValue({ data: undefined, isLoading: true, error: null, refetch: vi.fn() } as never)
    mockCycle.mockReturnValue({ data: undefined, isLoading: true, error: null, refetch: vi.fn() } as never)
    const { container } = renderWithProviders(<AdaptiveTesting />)
    expect(container.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('renders next experiment from backend', () => {
    mockNext.mockReturnValue({
      data: {
        organization_id: 'org-1',
        selected_strategy: 'sqli_based',
        selected_techniques: ['T1190'],
        selection_method: 'deterministic_scoring',
        score: 85.5,
        reason: 'High unresolved gap',
        validation_passed: true,
        validation_rejection: null,
        used_llm: false,
        used_fallback: true,
        candidates_count: 4,
        evidence_references: [],
        selected_at: '2024-01-01',
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as never)
    mockCycle.mockReturnValue({ data: undefined, isLoading: false, error: null, refetch: vi.fn() } as never)
    renderWithProviders(<AdaptiveTesting />)
    expect(screen.getByText('sqli_based')).toBeInTheDocument()
    expect(screen.getByText('85.50')).toBeInTheDocument()
    expect(screen.getByText('High unresolved gap')).toBeInTheDocument()
    expect(screen.getByText('VALIDATION PASSED')).toBeInTheDocument()
    expect(screen.getByText('T1190')).toBeInTheDocument()
  })

  it('shows MITIGATED/UNRESOLVED from backend state', () => {
    mockNext.mockReturnValue({ data: undefined, isLoading: false, error: null, refetch: vi.fn() } as never)
    mockCycle.mockReturnValue({
      data: {
        organization_id: 'org-1',
        current_state: 'MITIGATED',
        last_cycle_at: '2024-01-01',
        total_cycles: 3,
        mitigated_count: 2,
        unresolved_count: 1,
        next_experiment: null,
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as never)
    renderWithProviders(<AdaptiveTesting />)
    expect(screen.getAllByText('MITIGATED').length).toBeGreaterThan(0)
    expect(screen.getByText('2')).toBeInTheDocument()
    expect(screen.getByText('1')).toBeInTheDocument()
  })

  it('does NOT make security decisions', () => {
    mockNext.mockReturnValue({ data: undefined, isLoading: false, error: null, refetch: vi.fn() } as never)
    mockCycle.mockReturnValue({ data: undefined, isLoading: false, error: null, refetch: vi.fn() } as never)
    renderWithProviders(<AdaptiveTesting />)
    expect(screen.getByText('LLM (Reasoning — No Authority)')).toBeInTheDocument()
    expect(screen.getByText('Deterministic Scoring')).toBeInTheDocument()
    expect(screen.getByText('Safety Boundary Validation')).toBeInTheDocument()
  })
})
