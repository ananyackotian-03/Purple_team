import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { StatusBadge, RiskBadge, MetricCard, LoadingSpinner, EmptyState } from '@/components/Shared'

describe('StatusBadge', () => {
  it('renders status text', () => {
    render(<StatusBadge status="DETECTED" />)
    expect(screen.getByText('DETECTED')).toBeInTheDocument()
  })

  it('replaces underscores with spaces', () => {
    render(<StatusBadge status="DETECTION_GAP" />)
    expect(screen.getByText('DETECTION GAP')).toBeInTheDocument()
  })

  it('applies correct color for DETECTED', () => {
    render(<StatusBadge status="DETECTED" />)
    const el = screen.getByText('DETECTED')
    expect(el.className).toContain('secondary')
  })

  it('applies correct color for NOT_DETECTED', () => {
    render(<StatusBadge status="NOT_DETECTED" />)
    const el = screen.getByText('NOT DETECTED')
    expect(el.className).toContain('error')
  })

  it('applies correct color for GAP', () => {
    render(<StatusBadge status="GAP" />)
    const el = screen.getByText('GAP')
    expect(el.className).toContain('on-error')
  })

  it('applies correct color for MITIGATED', () => {
    render(<StatusBadge status="MITIGATED" />)
    const el = screen.getByText('MITIGATED')
    expect(el.className).toContain('secondary')
  })

  it('applies correct color for UNRESOLVED', () => {
    render(<StatusBadge status="UNRESOLVED" />)
    const el = screen.getByText('UNRESOLVED')
    expect(el.className).toContain('tertiary')
  })

  it('falls back for unknown status', () => {
    render(<StatusBadge status="CUSTOM_STATUS" />)
    const el = screen.getByText('CUSTOM STATUS')
    expect(el.className).toContain('on-surface-variant')
  })
})

describe('RiskBadge', () => {
  it('renders risk level', () => {
    render(<RiskBadge level="HIGH" />)
    expect(screen.getByText('HIGH')).toBeInTheDocument()
  })

  it('applies correct color for CRITICAL', () => {
    render(<RiskBadge level="CRITICAL" />)
    const el = screen.getByText('CRITICAL')
    expect(el.className).toContain('on-error')
  })

  it('applies correct color for LOW', () => {
    render(<RiskBadge level="LOW" />)
    const el = screen.getByText('LOW')
    expect(el.className).toContain('secondary')
  })
})

describe('MetricCard', () => {
  it('renders label and value', () => {
    render(<MetricCard label="TOTAL" value={42} />)
    expect(screen.getByText('TOTAL')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
  })

  it('renders optional subtitle', () => {
    render(<MetricCard label="TEST" value={10} subtitle="details" />)
    expect(screen.getByText('details')).toBeInTheDocument()
  })

  it('renders string value', () => {
    render(<MetricCard label="STATUS" value="OK" />)
    expect(screen.getByText('OK')).toBeInTheDocument()
  })
})

describe('LoadingSpinner', () => {
  it('renders a spinner', () => {
    const { container } = render(<LoadingSpinner />)
    expect(container.querySelector('.animate-spin')).toBeInTheDocument()
  })
})

describe('EmptyState', () => {
  it('renders title', () => {
    render(<EmptyState title="No data" />)
    expect(screen.getByText('No data')).toBeInTheDocument()
  })

  it('renders optional description', () => {
    render(<EmptyState title="Empty" description="Nothing here" />)
    expect(screen.getByText('Nothing here')).toBeInTheDocument()
  })
})
