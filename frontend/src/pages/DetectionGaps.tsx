import { useState } from 'react'
import { useDetectionGaps, useCreateDefensiveProposal } from '@/hooks/useApi'
import { LoadingSpinner, ErrorMessage, PageHeader, StatusBadge, EmptyState } from '@/components/Shared'

export default function DetectionGaps() {
  const { data, isLoading, error, refetch } = useDetectionGaps()
  const createProposalMut = useCreateDefensiveProposal()
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({ finding_id: '', root_cause: '', proposed_remediation: '', expected_security_effect: '' })

  if (isLoading) return <LoadingSpinner />
  if (error) return <ErrorMessage message={String(error)} onRetry={refetch} />

  return (
    <div>
      <div className="flex justify-between items-start mb-stack-lg">
        <div>
          <PageHeader
            title="DETECTION GAPS"
            subtitle="Techniques where detection failed or was absent"
          />
        </div>
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="px-4 py-2 bg-primary text-on-primary hover:bg-primary/90 transition-colors rounded flex items-center text-label-caps font-label-caps"
        >
          <span className="material-symbols-outlined mr-1 text-[18px]">add</span>
          NEW PROPOSAL
        </button>
      </div>

      {showCreate && (
        <div className="soc-card rounded-lg p-stack-md mb-stack-lg border-primary/30 border">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
            CREATE DEFENSIVE PROPOSAL
          </p>
          <div className="space-y-3">
            <input
              type="text"
              placeholder="Finding ID (gap scenario ID)"
              value={form.finding_id}
              onChange={(e) => setForm({ ...form, finding_id: e.target.value })}
              className="w-full px-3 py-2 bg-black/30 border border-white/10 rounded text-on-surface placeholder-outline focus:border-primary focus:shadow-active-glow outline-none transition-all text-body-base"
            />
            <input
              type="text"
              placeholder="Root cause"
              value={form.root_cause}
              onChange={(e) => setForm({ ...form, root_cause: e.target.value })}
              className="w-full px-3 py-2 bg-black/30 border border-white/10 rounded text-on-surface placeholder-outline focus:border-primary focus:shadow-active-glow outline-none transition-all text-body-base"
            />
            <textarea
              placeholder="Proposed remediation"
              value={form.proposed_remediation}
              onChange={(e) => setForm({ ...form, proposed_remediation: e.target.value })}
              className="w-full px-3 py-2 bg-black/30 border border-white/10 rounded text-on-surface placeholder-outline focus:border-primary focus:shadow-active-glow outline-none transition-all text-body-base h-20 resize-none"
            />
            <input
              type="text"
              placeholder="Expected security effect (optional)"
              value={form.expected_security_effect}
              onChange={(e) => setForm({ ...form, expected_security_effect: e.target.value })}
              className="w-full px-3 py-2 bg-black/30 border border-white/10 rounded text-on-surface placeholder-outline focus:border-primary focus:shadow-active-glow outline-none transition-all text-body-base"
            />
            <div className="flex items-center gap-3">
              <button
                onClick={() => {
                  if (!form.root_cause.trim() || !form.proposed_remediation.trim()) return
                  createProposalMut.mutate(
                    {
                      finding_id: form.finding_id || 'manual',
                      root_cause: form.root_cause,
                      proposed_remediation: form.proposed_remediation,
                      expected_security_effect: form.expected_security_effect || undefined,
                    },
                    {
                      onSuccess: () => {
                        setShowCreate(false)
                        setForm({ finding_id: '', root_cause: '', proposed_remediation: '', expected_security_effect: '' })
                      },
                    }
                  )
                }}
                disabled={!form.root_cause.trim() || !form.proposed_remediation.trim() || createProposalMut.isPending}
                className="px-4 py-2 bg-primary text-on-primary hover:bg-primary/90 transition-colors rounded text-label-caps font-label-caps disabled:opacity-50"
              >
                {createProposalMut.isPending ? 'CREATING...' : 'CREATE PROPOSAL'}
              </button>
              <button
                onClick={() => setShowCreate(false)}
                className="px-4 py-2 border border-white/10 text-on-surface-variant hover:bg-surface-container-high transition-colors rounded text-label-caps font-label-caps"
              >
                CANCEL
              </button>
            </div>
          </div>
        </div>
      )}

      {!data?.length ? (
        <EmptyState
          title="No detection gaps"
          description="All techniques are being detected"
        />
      ) : (
        <div className="soc-card rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/10">
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">
                    TECHNIQUE
                  </th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">
                    OUTCOME
                  </th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">
                    REMEDIATION
                  </th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">
                    REASON
                  </th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">
                    DATE
                  </th>
                </tr>
              </thead>
              <tbody>
                {data.map((gap) => (
                  <tr key={gap.id} className="border-b border-white/5 hover:bg-white/[0.02]">
                    <td className="py-3 px-stack-md text-data-mono font-data-mono text-primary">
                      {gap.technique_id}
                    </td>
                    <td className="py-3 px-stack-md">
                      <StatusBadge status={gap.original_outcome} />
                    </td>
                    <td className="py-3 px-stack-md">
                      <StatusBadge status={gap.remediation_status} />
                    </td>
                    <td className="py-3 px-stack-md text-on-surface-variant text-body-base max-w-xs truncate">
                      {gap.reason || '—'}
                    </td>
                    <td className="py-3 px-stack-md text-data-mono-sm font-data-mono-sm text-outline">
                      {gap.created_at ? new Date(gap.created_at).toLocaleDateString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
