import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import DetectionGaps from '@/pages/DetectionGaps'

vi.mock('@/hooks/useApi', () => ({
  useDetectionGaps: vi.fn(),
  useCreateDefensiveProposal: vi.fn().mockReturnValue({ mutate: vi.fn(), isPending: false }),
}))

import { useDetectionGaps } from '@/hooks/useApi'
const mockUse = vi.mocked(useDetectionGaps)

function renderWithProviders(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('DetectionGaps page', () => {
  it('shows loading', () => {
    mockUse.mockReturnValue({ data: undefined, isLoading: true, error: null, refetch: vi.fn() } as never)
    const { container } = renderWithProviders(<DetectionGaps />)
    expect(container.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows empty state', () => {
    mockUse.mockReturnValue({ data: [], isLoading: false, error: null, refetch: vi.fn() } as never)
    renderWithProviders(<DetectionGaps />)
    expect(screen.getByText('No detection gaps')).toBeInTheDocument()
  })

  it('renders gap table', () => {
    mockUse.mockReturnValue({
      data: [
        { id: '1', organization_id: 'o1', scenario_id: null, technique_id: 'T1059', original_outcome: 'NOT_DETECTED', remediation_status: 'OPEN', reason: 'No rule', created_at: '2024-01-01' },
      ],
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as never)
    renderWithProviders(<DetectionGaps />)
    expect(screen.getByText('T1059')).toBeInTheDocument()
    expect(screen.getByText('NOT DETECTED')).toBeInTheDocument()
    expect(screen.getByText('OPEN')).toBeInTheDocument()
  })

  it('displays backend status only', () => {
    mockUse.mockReturnValue({
      data: [
        { id: '2', organization_id: 'o1', scenario_id: null, technique_id: 'T1053', original_outcome: 'DETECTION_GAP', remediation_status: 'IN_PROGRESS', reason: 'Weak rule', created_at: '2024-06-01' },
      ],
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as never)
    renderWithProviders(<DetectionGaps />)
    expect(screen.getByText('DETECTION GAP')).toBeInTheDocument()
    expect(screen.getByText('IN PROGRESS')).toBeInTheDocument()
    expect(screen.getByText('Weak rule')).toBeInTheDocument()
  })
})
