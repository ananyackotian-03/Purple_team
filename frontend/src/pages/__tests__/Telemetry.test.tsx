import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Telemetry from '@/pages/Telemetry'

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

describe('Telemetry page', () => {
  it('shows loading', () => {
    mockUse.mockReturnValue({ data: undefined, isLoading: true, error: null, refetch: vi.fn() } as never)
    const { container } = renderWithProviders(<Telemetry />)
    expect(container.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows error state', () => {
    mockUse.mockReturnValue({ data: undefined, isLoading: false, error: new Error('fail'), refetch: vi.fn() } as never)
    renderWithProviders(<Telemetry />)
    expect(screen.getByText(/fail/)).toBeInTheDocument()
  })

  it('shows empty state when no telemetry', () => {
    mockUse.mockReturnValue({ data: [], isLoading: false, error: null, refetch: vi.fn() } as never)
    renderWithProviders(<Telemetry />)
    expect(screen.getByText('No telemetry data')).toBeInTheDocument()
  })

  it('renders telemetry events from backend experiments', () => {
    mockUse.mockReturnValue({
      data: [
        {
          id: 'exp-1',
          organization_id: 'org-1',
          objective_id: 'obj-1',
          title: 'SQL Injection Test',
          strategy_description: 'Test SQLi',
          risk_level: 'HIGH',
          status: 'COMPLETED',
          created_by: 'red_agent',
          created_at: '2024-01-15',
        },
        {
          id: 'exp-2',
          organization_id: 'org-1',
          objective_id: 'obj-1',
          title: 'XSS Test',
          strategy_description: 'Test XSS',
          risk_level: 'MEDIUM',
          status: 'DETECTED',
          created_by: 'red_agent',
          created_at: '2024-01-16',
        },
      ],
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as never)
    renderWithProviders(<Telemetry />)
    expect(screen.getByText('TELEMETRY')).toBeInTheDocument()
    expect(screen.getByText('SQL Injection Test')).toBeInTheDocument()
    expect(screen.getByText('XSS Test')).toBeInTheDocument()
  })

  it('does not show pending experiments as telemetry', () => {
    mockUse.mockReturnValue({
      data: [
        {
          id: 'exp-3',
          organization_id: 'org-1',
          objective_id: 'obj-1',
          title: 'Pending Test',
          strategy_description: null,
          risk_level: null,
          status: 'PENDING',
          created_by: null,
          created_at: null,
        },
      ],
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as never)
    renderWithProviders(<Telemetry />)
    expect(screen.getByText('No telemetry data')).toBeInTheDocument()
  })
})
