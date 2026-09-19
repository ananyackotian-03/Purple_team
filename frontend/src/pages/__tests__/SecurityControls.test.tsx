import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import SecurityControls from '@/pages/SecurityControls'

vi.mock('@/hooks/useApi', () => ({
  useTwinControls: vi.fn(),
}))

import { useTwinControls } from '@/hooks/useApi'
const mockUse = vi.mocked(useTwinControls)

function renderWithProviders(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('SecurityControls page', () => {
  it('shows loading', () => {
    mockUse.mockReturnValue({ data: undefined, isLoading: true, error: null, refetch: vi.fn() } as never)
    const { container } = renderWithProviders(<SecurityControls />)
    expect(container.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows error state', () => {
    mockUse.mockReturnValue({ data: undefined, isLoading: false, error: new Error('fail'), refetch: vi.fn() } as never)
    renderWithProviders(<SecurityControls />)
    expect(screen.getByText(/fail/)).toBeInTheDocument()
  })

  it('renders security architecture diagram', () => {
    mockUse.mockReturnValue({ data: { controls: [], total: 0 }, isLoading: false, error: null, refetch: vi.fn() } as never)
    renderWithProviders(<SecurityControls />)
    expect(screen.getByText('SECURITY ARCHITECTURE')).toBeInTheDocument()
    expect(screen.getByText('LLM')).toBeInTheDocument()
    expect(screen.getByText('PROPOSAL')).toBeInTheDocument()
    expect(screen.getByText('SAFETY BOUNDARY')).toBeInTheDocument()
    expect(screen.getByText('POLICY ENGINE')).toBeInTheDocument()
    expect(screen.getByText('TOOL AUTHORIZATION')).toBeInTheDocument()
    expect(screen.getByText('SANDBOX')).toBeInTheDocument()
    expect(screen.getByText('TELEMETRY')).toBeInTheDocument()
    expect(screen.getByText('DETECTION')).toBeInTheDocument()
  })

  it('shows empty state when no controls', () => {
    mockUse.mockReturnValue({ data: { controls: [], total: 0 }, isLoading: false, error: null, refetch: vi.fn() } as never)
    renderWithProviders(<SecurityControls />)
    expect(screen.getByText('No security controls registered')).toBeInTheDocument()
  })

  it('renders controls table from backend', () => {
    mockUse.mockReturnValue({
      data: {
        controls: [
          {
            id: 'c1',
            organization_id: 'org-1',
            name: 'Sigma Rules',
            control_type: 'detection',
            description: 'Detection rules',
            enabled: true,
            version: '1.0',
            vendor: 'Splunk',
            technique_ids: ['T1059', 'T1053'],
            coverage_description: 'Covers execution techniques',
            last_validated_at: null,
            validation_status: 'SCHEMA_VALIDATED',
            metadata_json: {},
            created_at: '2024-01-01',
            updated_at: '2024-01-01',
          },
        ],
        total: 1,
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as never)
    renderWithProviders(<SecurityControls />)
    expect(screen.getAllByText('Sigma Rules').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('detection')).toBeInTheDocument()
    expect(screen.getByText('Splunk')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
    expect(screen.getByText('ACTIVE')).toBeInTheDocument()
    expect(screen.getByText('SCHEMA VALIDATED')).toBeInTheDocument()
  })

  it('shows DRAFT status for disabled controls', () => {
    mockUse.mockReturnValue({
      data: {
        controls: [
          {
            id: 'c2',
            organization_id: 'org-1',
            name: 'Firewall',
            control_type: 'network',
            description: 'Network firewall',
            enabled: false,
            version: null,
            vendor: null,
            technique_ids: [],
            coverage_description: '',
            last_validated_at: null,
            validation_status: null,
            metadata_json: {},
            created_at: '2024-01-01',
            updated_at: '2024-01-01',
          },
        ],
        total: 1,
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as never)
    renderWithProviders(<SecurityControls />)
    expect(screen.getByText('DRAFT')).toBeInTheDocument()
    expect(screen.getByText('—')).toBeInTheDocument()
    expect(screen.getByText('PENDING')).toBeInTheDocument()
  })
})
