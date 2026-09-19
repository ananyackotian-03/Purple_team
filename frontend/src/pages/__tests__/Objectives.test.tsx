import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Objectives from '@/pages/Objectives'

vi.mock('@/hooks/useApi', () => ({
  useObjectives: vi.fn(),
  useCreateObjective: vi.fn(),
}))

import { useObjectives, useCreateObjective } from '@/hooks/useApi'
const mockUse = vi.mocked(useObjectives)
const mockCreate = vi.mocked(useCreateObjective)

function renderWithProviders(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('Objectives page', () => {
  it('shows loading', () => {
    mockUse.mockReturnValue({ data: undefined, isLoading: true, error: null, refetch: vi.fn() } as never)
    mockCreate.mockReturnValue({ mutate: vi.fn(), isPending: false } as never)
    const { container } = renderWithProviders(<Objectives />)
    expect(container.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows error state', () => {
    mockUse.mockReturnValue({ data: undefined, isLoading: false, error: new Error('fail'), refetch: vi.fn() } as never)
    mockCreate.mockReturnValue({ mutate: vi.fn(), isPending: false } as never)
    renderWithProviders(<Objectives />)
    expect(screen.getByText(/fail/)).toBeInTheDocument()
  })

  it('shows empty state when no objectives', () => {
    mockUse.mockReturnValue({ data: [], isLoading: false, error: null, refetch: vi.fn() } as never)
    mockCreate.mockReturnValue({ mutate: vi.fn(), isPending: false } as never)
    renderWithProviders(<Objectives />)
    expect(screen.getByText('No objectives')).toBeInTheDocument()
  })

  it('renders objectives list from backend', () => {
    mockUse.mockReturnValue({
      data: [
        {
          id: 'obj-1',
          organization_id: 'org-1',
          title: 'Test SQL Injection',
          description: 'Test for SQLi',
          target_category: 'web',
          default_risk_level: 'HIGH',
          created_at: '2024-01-01',
          experiment_count: 3,
        },
      ],
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as never)
    mockCreate.mockReturnValue({ mutate: vi.fn(), isPending: false } as never)
    renderWithProviders(<Objectives />)
    expect(screen.getByText('Test SQL Injection')).toBeInTheDocument()
    expect(screen.getByText('Test for SQLi')).toBeInTheDocument()
    expect(screen.getByText('HIGH')).toBeInTheDocument()
    expect(screen.getByText('3 experiments')).toBeInTheDocument()
  })

  it('renders NEW OBJECTIVE button', () => {
    mockUse.mockReturnValue({ data: [], isLoading: false, error: null, refetch: vi.fn() } as never)
    mockCreate.mockReturnValue({ mutate: vi.fn(), isPending: false } as never)
    renderWithProviders(<Objectives />)
    expect(screen.getByText('NEW OBJECTIVE')).toBeInTheDocument()
  })
})
