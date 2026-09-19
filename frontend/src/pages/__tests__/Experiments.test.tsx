import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Experiments from '@/pages/Experiments'

vi.mock('@/hooks/useApi', () => ({
  useExperiments: vi.fn(),
}))

import { useExperiments } from '@/hooks/useApi'
const mockUse = vi.mocked(useExperiments)

function renderWithProviders(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('Experiments page', () => {
  it('shows loading', () => {
    mockUse.mockReturnValue({ data: undefined, isLoading: true, error: null, refetch: vi.fn() } as never)
    const { container } = renderWithProviders(<Experiments />)
    expect(container.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows error state', () => {
    mockUse.mockReturnValue({ data: undefined, isLoading: false, error: new Error('fail'), refetch: vi.fn() } as never)
    renderWithProviders(<Experiments />)
    expect(screen.getByText(/fail/)).toBeInTheDocument()
  })

  it('shows empty state', () => {
    mockUse.mockReturnValue({ data: [], isLoading: false, error: null, refetch: vi.fn() } as never)
    renderWithProviders(<Experiments />)
    expect(screen.getByText('No experiments')).toBeInTheDocument()
  })

  it('renders experiments from backend', () => {
    mockUse.mockReturnValue({
      data: [
        {
          id: 'exp-1',
          organization_id: 'org-1',
          objective_id: 'obj-1',
          title: 'SQL Injection Test',
          strategy_description: 'Test SQLi via login form',
          risk_level: 'HIGH',
          status: 'COMPLETED',
          created_by: 'red_agent',
          created_at: '2024-01-15',
        },
      ],
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as never)
    renderWithProviders(<Experiments />)
    expect(screen.getByText('SQL Injection Test')).toBeInTheDocument()
    expect(screen.getByText('Test SQLi via login form')).toBeInTheDocument()
    expect(screen.getByText('COMPLETED')).toBeInTheDocument()
    expect(screen.getByText('HIGH')).toBeInTheDocument()
    expect(screen.getByText('red_agent')).toBeInTheDocument()
  })

  it('displays backend status only', () => {
    mockUse.mockReturnValue({
      data: [
        {
          id: 'exp-2',
          organization_id: 'org-1',
          objective_id: 'obj-1',
          title: 'XSS Test',
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
    renderWithProviders(<Experiments />)
    expect(screen.getByText('NOT DETECTED')).toBeInTheDocument()
    expect(screen.getByText('MEDIUM')).toBeInTheDocument()
  })
})
