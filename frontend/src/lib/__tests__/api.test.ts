import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from '@/lib/api'

const mockFetch = vi.fn()
globalThis.fetch = mockFetch as never

beforeEach(() => {
  mockFetch.mockReset()
})

function mockJsonResponse(data: unknown, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(data),
    statusText: status === 200 ? 'OK' : 'Error',
  })
}

describe('API client', () => {
  it('getHealth calls /api/health', async () => {
    const healthData = { status: 'healthy', version: '1.0', database: 'ok', ollama: 'ok', docker: 'ok' }
    mockFetch.mockReturnValue(mockJsonResponse(healthData))
    const result = await api.getHealth()
    expect(mockFetch).toHaveBeenCalledWith('/api/health', expect.objectContaining({
      headers: { 'Content-Type': 'application/json' },
    }))
    expect(result).toEqual(healthData)
  })

  it('getDashboard calls /api/dashboard', async () => {
    const dashData = { total_objectives: 5, total_experiments: 10, coverage_pct: 75.0 }
    mockFetch.mockReturnValue(mockJsonResponse(dashData))
    const result = await api.getDashboard()
    expect(mockFetch).toHaveBeenCalledWith('/api/dashboard', expect.anything())
    expect(result.total_objectives).toBe(5)
  })

  it('getObjectives calls /api/objectives', async () => {
    mockFetch.mockReturnValue(mockJsonResponse([]))
    await api.getObjectives()
    expect(mockFetch).toHaveBeenCalledWith('/api/objectives', expect.anything())
  })

  it('getObjective calls /api/objectives/:id', async () => {
    mockFetch.mockReturnValue(mockJsonResponse({ objective: {}, experiments: [] }))
    await api.getObjective('test-id')
    expect(mockFetch).toHaveBeenCalledWith('/api/objectives/test-id', expect.anything())
  })

  it('createObjective sends POST', async () => {
    mockFetch.mockReturnValue(mockJsonResponse({ id: '1', title: 'Test' }))
    await api.createObjective({ title: 'Test', description: 'desc' })
    expect(mockFetch).toHaveBeenCalledWith('/api/objectives', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ title: 'Test', description: 'desc' }),
    }))
  })

  it('runExperiment sends POST to /run', async () => {
    mockFetch.mockReturnValue(mockJsonResponse({ status: 'accepted' }))
    await api.runExperiment('obj-1')
    expect(mockFetch).toHaveBeenCalledWith('/api/objectives/obj-1/run', expect.objectContaining({
      method: 'POST',
    }))
  })

  it('getExperiment calls /api/experiments/:id', async () => {
    mockFetch.mockReturnValue(mockJsonResponse({ experiment: {}, lifecycle: [] }))
    await api.getExperiment('exp-1')
    expect(mockFetch).toHaveBeenCalledWith('/api/experiments/exp-1', expect.anything())
  })

  it('getCoverage calls /api/coverage', async () => {
    mockFetch.mockReturnValue(mockJsonResponse({ coverage_pct: 80 }))
    await api.getCoverage()
    expect(mockFetch).toHaveBeenCalledWith('/api/coverage', expect.anything())
  })

  it('getRetests calls /api/retests', async () => {
    mockFetch.mockReturnValue(mockJsonResponse([]))
    await api.getRetests()
    expect(mockFetch).toHaveBeenCalledWith('/api/retests', expect.anything())
  })

  it('getImmuneMemory calls org immune-memory', async () => {
    mockFetch.mockReturnValue(mockJsonResponse({ previous_experiments: 5 }))
    await api.getImmuneMemory('org-1')
    expect(mockFetch).toHaveBeenCalledWith('/api/organizations/org-1/immune-memory', expect.anything())
  })

  it('getNextExperiment calls org next-experiment', async () => {
    mockFetch.mockReturnValue(mockJsonResponse({ selected_strategy: 'sqli' }))
    await api.getNextExperiment('org-1')
    expect(mockFetch).toHaveBeenCalledWith('/api/organizations/org-1/next-experiment', expect.anything())
  })

  it('getTwinSummary calls org twin/summary', async () => {
    mockFetch.mockReturnValue(mockJsonResponse({ total_assets: 3 }))
    await api.getTwinSummary('org-1')
    expect(mockFetch).toHaveBeenCalledWith('/api/organizations/org-1/twin/summary', expect.anything())
  })

  it('throws on non-OK response', async () => {
    mockFetch.mockReturnValue(mockJsonResponse({ detail: 'Not found' }, 404))
    await expect(api.getExperiment('bad')).rejects.toThrow('Not found')
  })

  it('throws on network error with statusText', async () => {
    mockFetch.mockReturnValue(mockJsonResponse(null, 500))
    await expect(api.getHealth()).rejects.toThrow()
  })
})
