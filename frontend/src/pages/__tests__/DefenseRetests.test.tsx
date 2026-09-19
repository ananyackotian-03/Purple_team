import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import DefenseRetests from '@/pages/DefenseRetests'

vi.mock('@/hooks/useApi', () => ({
  useRetests: vi.fn(),
  useDefensiveProposals: vi.fn(),
  useValidateDefensiveProposal: vi.fn().mockReturnValue({ mutate: vi.fn(), isPending: false }),
}))

import { useRetests, useDefensiveProposals } from '@/hooks/useApi'
const mockRetests = vi.mocked(useRetests)
const mockProposals = vi.mocked(useDefensiveProposals)

function renderWithProviders(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('DefenseRetests page', () => {
  it('shows loading', () => {
    mockRetests.mockReturnValue({ data: undefined, isLoading: true, error: null, refetch: vi.fn() } as never)
    mockProposals.mockReturnValue({ data: undefined, isLoading: true, error: null } as never)
    const { container } = renderWithProviders(<DefenseRetests />)
    expect(container.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows error state', () => {
    mockRetests.mockReturnValue({ data: undefined, isLoading: false, error: new Error('fail'), refetch: vi.fn() } as never)
    mockProposals.mockReturnValue({ data: undefined, isLoading: false, error: null } as never)
    renderWithProviders(<DefenseRetests />)
    expect(screen.getByText(/fail/)).toBeInTheDocument()
  })

  it('renders mitigation lifecycle', () => {
    mockRetests.mockReturnValue({ data: [], isLoading: false, error: null, refetch: vi.fn() } as never)
    mockProposals.mockReturnValue({ data: [], isLoading: false, error: null } as never)
    renderWithProviders(<DefenseRetests />)
    expect(screen.getByText('MITIGATION LIFECYCLE')).toBeInTheDocument()
    expect(screen.getByText('TOTAL RETESTS')).toBeInTheDocument()
    expect(screen.getByText('IMPROVED')).toBeInTheDocument()
  })

  it('shows empty state when no retests', () => {
    mockRetests.mockReturnValue({ data: [], isLoading: false, error: null, refetch: vi.fn() } as never)
    mockProposals.mockReturnValue({ data: [], isLoading: false, error: null } as never)
    renderWithProviders(<DefenseRetests />)
    expect(screen.getByText('No retests')).toBeInTheDocument()
  })

  it('renders retests with before/after from backend', () => {
    mockRetests.mockReturnValue({
      data: [
        {
          id: 'retest-1',
          organization_id: 'org-1',
          exercise_id: null,
          scenario_id: 'exp-1',
          before_outcome: 'NOT_DETECTED',
          after_outcome: 'DETECTED',
          detection_improved: true,
          validated_rule_ids: ['rule-1'],
          evaluated_at: '2024-01-20',
        },
      ],
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as never)
    mockProposals.mockReturnValue({ data: [], isLoading: false, error: null } as never)
    renderWithProviders(<DefenseRetests />)
    expect(screen.getAllByText('NOT DETECTED').length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText('DETECTED').length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText('IMPROVED').length).toBeGreaterThanOrEqual(1)
  })

  it('renders defensive proposals', () => {
    mockRetests.mockReturnValue({ data: [], isLoading: false, error: null, refetch: vi.fn() } as never)
    mockProposals.mockReturnValue({
      data: [
        {
          id: 'p1',
          organization_id: 'org-1',
          finding_id: null,
          scenario_id: null,
          root_cause: 'Missing WAF rule',
          proposed_remediation: 'Add OWASP CRS rules',
          expected_security_effect: 'Block SQLi',
          status: 'VALIDATED',
          created_at: '2024-01-01',
        },
      ],
      isLoading: false,
      error: null,
    } as never)
    renderWithProviders(<DefenseRetests />)
    expect(screen.getByText('Missing WAF rule')).toBeInTheDocument()
    expect(screen.getByText('Add OWASP CRS rules')).toBeInTheDocument()
    expect(screen.getByText('VALIDATED')).toBeInTheDocument()
  })
})
