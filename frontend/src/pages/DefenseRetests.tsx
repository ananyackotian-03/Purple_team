import { useState } from 'react'
import { useRetests, useDefensiveProposals, useValidateDefensiveProposal } from '@/hooks/useApi'
import { LoadingSpinner, ErrorMessage, PageHeader, StatusBadge, EmptyState } from '@/components/Shared'

const LIFECYCLE_STEPS = [
  { icon: 'warning', label: 'GAP', colorClass: 'bg-error-container border-error', textClass: 'text-error' },
  { icon: 'edit_document', label: 'PROPOSAL', colorClass: '', textClass: '' },
  { icon: 'health_and_safety', label: 'VALIDATION', colorClass: '', textClass: '' },
  { icon: 'science', label: 'TEST', colorClass: '', textClass: '' },
  { icon: 'refresh', label: 'RETEST', colorClass: 'bg-primary-container/20 border-primary', textClass: 'text-primary', active: true },
  { icon: 'compare', label: 'COMPARE', colorClass: '', textClass: '' },
  { icon: 'task_alt', label: 'MITIGATED', colorClass: 'bg-secondary-container/20 border-secondary', textClass: 'text-secondary' },
]

export default function DefenseRetests() {
  const { data: retests, isLoading: rLoad, error: rErr, refetch: rRef } = useRetests()
  const { data: proposals, isLoading: pLoad } = useDefensiveProposals()
  const validateMut = useValidateDefensiveProposal()
  const [validatingId, setValidatingId] = useState<string | null>(null)

  if (rLoad || pLoad) return <LoadingSpinner />
  if (rErr) return <ErrorMessage message={String(rErr)} onRetry={rRef} />

  const latestRetest = retests?.[0]
  const hasMitigated = retests?.some((r) => r.after_outcome === 'DETECTED' || r.after_outcome === 'VERIFIED')

  const handleValidate = (proposalId: string) => {
    setValidatingId(proposalId)
    validateMut.mutate(proposalId, {
      onSettled: () => setValidatingId(null),
    })
  }

  return (
    <div>
      <PageHeader
        title="DEFENSIVE MITIGATION & VALIDATION"
        subtitle={
          latestRetest
            ? `Evaluation of applied countermeasures — Retest ${latestRetest.id.slice(0, 8)}`
            : 'Defensive mitigation validation and before/after comparison'
        }
      />

      {/* Mitigation Lifecycle Visualization — Stitch style */}
      <div className="soc-card rounded-lg p-stack-md mb-stack-lg">
        <div className="flex justify-between items-center mb-stack-md">
          <span className="text-label-caps font-label-caps text-on-surface-variant">
            MITIGATION LIFECYCLE
          </span>
          {hasMitigated && (
            <span className="status-pill bg-secondary-container/20 border border-secondary text-secondary">
              <span className="material-symbols-outlined text-[14px] mr-1">check_circle</span>
              MITIGATED
            </span>
          )}
        </div>
        <div className="relative pt-2 pb-8">
          <div className="absolute top-4 left-0 w-full progress-line z-0" />
          <div className="flex justify-between relative z-10 w-full">
            {LIFECYCLE_STEPS.map((step, i) => (
              <div key={i} className="flex flex-col items-center">
                <div
                  className={`w-10 h-10 rounded-full ${
                    step.colorClass || 'bg-surface-variant border-outline'
                  } border flex items-center justify-center mb-2 ${
                    step.active ? 'shadow-active-glow' : ''
                  }`}
                >
                  <span
                    className={`material-symbols-outlined text-[18px] ${
                      step.textClass || 'text-on-surface'
                    }`}
                  >
                    {step.icon}
                  </span>
                </div>
                <span className="text-label-caps font-label-caps text-outline text-center w-16">
                  {step.label}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Before / After Comparison — Stitch style side-by-side cards */}
      {latestRetest && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-stack-md mb-stack-lg">
          {/* BEFORE card */}
          <div className="soc-card rounded-lg overflow-hidden">
            <div className="border-l-4 border-error/50">
              <div className="bg-error/5 px-stack-md py-stack-sm">
                <div className="flex justify-between items-center">
                  <span className="text-label-caps font-label-caps text-error">
                    BEFORE MITIGATION
                  </span>
                  <span className="text-data-mono-sm font-data-mono-sm text-outline">
                    {latestRetest.evaluated_at
                      ? new Date(latestRetest.evaluated_at).toLocaleDateString()
                      : '—'}
                  </span>
                </div>
              </div>
              <div className="p-stack-md space-y-3">
                <div className="flex justify-between items-center border-b border-white/5 pb-2">
                  <span className="text-label-caps font-label-caps text-outline">Detection</span>
                  <span className="flex items-center gap-1 text-error text-data-mono font-data-mono">
                    <span className="material-symbols-outlined text-[16px]">close</span>
                    {latestRetest.before_outcome === 'NOT_DETECTED' ? 'NOT DETECTED' : latestRetest.before_outcome}
                  </span>
                </div>
                <div className="flex justify-between items-center border-b border-white/5 pb-2">
                  <span className="text-label-caps font-label-caps text-outline">Status</span>
                  <span className="status-pill bg-error-container text-on-error">
                    GAP
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* AFTER card */}
          <div className="soc-card rounded-lg overflow-hidden shadow-success-glow">
            <div className="border-l-4 border-secondary">
              <div className="bg-secondary/5 px-stack-md py-stack-sm">
                <div className="flex justify-between items-center">
                  <span className="text-label-caps font-label-caps text-secondary">
                    AFTER MITIGATION
                  </span>
                  <span className="text-data-mono-sm font-data-mono-sm text-secondary">
                    CURRENT STATE
                  </span>
                </div>
              </div>
              <div className="p-stack-md space-y-3">
                <div className="flex justify-between items-center border-b border-white/5 pb-2">
                  <span className="text-label-caps font-label-caps text-outline">Detection</span>
                  <span className="flex items-center gap-1 text-secondary text-data-mono font-data-mono">
                    <span className="material-symbols-outlined text-[16px]">check</span>
                    {latestRetest.after_outcome === 'DETECTED' ? 'DETECTED' : latestRetest.after_outcome}
                  </span>
                </div>
                <div className="flex justify-between items-center border-b border-white/5 pb-2">
                  <span className="text-label-caps font-label-caps text-outline">Status</span>
                  <span className="status-pill bg-secondary-container/20 border border-secondary text-secondary">
                    {latestRetest.detection_improved ? 'VERIFIED' : latestRetest.after_outcome}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Remediation Details + Technical Evidence — Stitch bento grid */}
      {proposals && proposals.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-stack-md mb-stack-lg">
          {/* Remediation Details — left 1/3 */}
          <div className="soc-card rounded-lg">
            <div className="soc-card-header p-stack-sm px-stack-md">
              <span className="text-label-caps font-label-caps text-on-surface-variant">
                REMEDIATION DETAILS
              </span>
            </div>
            <div className="p-stack-md space-y-3">
              <div className="border-b border-white/5 pb-2">
                <span className="text-label-caps font-label-caps text-outline block mb-1">PROPOSAL</span>
                <span className="text-on-surface text-body-base">
                  {proposals[0].root_cause}
                </span>
              </div>
              <div className="border-b border-white/5 pb-2">
                <span className="text-label-caps font-label-caps text-outline block mb-1">REMEDIATION</span>
                <span className="text-on-surface-variant text-body-base">
                  {proposals[0].proposed_remediation}
                </span>
              </div>
              <div className="border-b border-white/5 pb-2">
                <span className="text-label-caps font-label-caps text-outline block mb-1">EXPECTED EFFECT</span>
                <span className="text-on-surface-variant text-body-base">
                  {proposals[0].expected_security_effect || '—'}
                </span>
              </div>
              <div className="border-b border-white/5 pb-2">
                <span className="text-label-caps font-label-caps text-outline block mb-1">STATUS</span>
                <StatusBadge status={proposals[0].status} />
              </div>
              <div>
                <span className="text-label-caps font-label-caps text-outline block mb-1">TARGET</span>
                <span className="px-2 py-1 bg-primary/10 border border-primary/30 text-primary rounded text-data-mono-sm font-data-mono-sm">
                  {proposals[0].scenario_id || '—'}
                </span>
              </div>
              {proposals[0].status === 'CREATED' && (
                <button
                  onClick={() => handleValidate(proposals[0].id)}
                  disabled={validatingId === proposals[0].id}
                  className="w-full px-4 py-2 bg-primary/10 border border-primary/30 text-primary hover:bg-primary/20 transition-colors rounded text-label-caps font-label-caps disabled:opacity-50"
                >
                  {validatingId === proposals[0].id ? 'VALIDATING...' : 'VALIDATE PROPOSAL'}
                </button>
              )}
            </div>
          </div>

          {/* Technical Evidence — right 2/3 */}
          <div className="soc-card rounded-lg lg:col-span-2">
            <div className="soc-card-header p-stack-sm px-stack-md flex justify-between items-center">
              <span className="text-label-caps font-label-caps text-on-surface-variant">
                TECHNICAL EVIDENCE: DEFENSIVE PROPOSAL
              </span>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(proposals[0].proposed_remediation)
                }}
                className="p-1 text-on-surface-variant hover:text-on-surface transition-colors rounded"
                title="Copy to clipboard"
              >
                <span className="material-symbols-outlined text-[18px]">content_copy</span>
              </button>
            </div>
            <div className="p-stack-md">
              <div className="code-block rounded p-stack-md overflow-x-auto">
                <pre className="text-data-mono font-data-mono text-on-surface-variant text-[13px] whitespace-pre-wrap">
                  <span className="text-primary">title:</span> {proposals[0].root_cause}
{'\n'}
                  <span className="text-primary">id:</span> {proposals[0].id}
{'\n'}
                  <span className="text-primary">status:</span> {proposals[0].status.toLowerCase()}
{'\n'}
                  <span className="text-primary">description:</span> {proposals[0].expected_security_effect || 'Defensive remediation proposal'}
{'\n'}
                  <span className="text-primary">remediation:</span>
{'\n'}    {proposals[0].proposed_remediation}
{'\n'}
                  <span className="text-primary">organization_id:</span> {proposals[0].organization_id}
{'\n'}
                  <span className="text-primary">created_at:</span> {proposals[0].created_at || '—'}
{'\n'}
                  <span className="text-primary">finding_id:</span> {proposals[0].finding_id || '—'}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Summary Stats */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-stack-md mb-stack-lg">
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
            TOTAL RETESTS
          </p>
          <p className="text-headline-md font-headline-md text-on-surface">
            {retests?.length || 0}
          </p>
        </div>
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
            IMPROVED
          </p>
          <p className="text-headline-md font-headline-md text-secondary">
            {retests?.filter((r) => r.detection_improved).length || 0}
          </p>
        </div>
      </div>

      {/* All Retests */}
      {!retests?.length ? (
        <EmptyState
          title="No retests"
          description="Complete an immune cycle to generate before/after comparisons"
        />
      ) : (
        <div className="space-y-3">
          <p className="text-label-caps font-label-caps text-on-surface-variant">
            ALL RETESTS
          </p>
          {retests.map((r) => (
            <div key={r.id} className="soc-card rounded-lg p-stack-md">
              <div className="flex justify-between items-start mb-stack-sm">
                <span className="text-data-mono-sm font-data-mono-sm text-outline">
                  {r.id.slice(0, 8)}
                </span>
                <span className="text-data-mono-sm font-data-mono-sm text-outline">
                  {r.evaluated_at ? new Date(r.evaluated_at).toLocaleDateString() : '—'}
                </span>
              </div>
              <div className="grid grid-cols-2 gap-stack-md">
                <div className="bg-error/5 border-l-4 border-error/50 rounded-r p-stack-sm">
                  <p className="text-label-caps font-label-caps text-error mb-1">BEFORE</p>
                  <StatusBadge status={r.before_outcome} />
                </div>
                <div className="bg-secondary/5 border-l-4 border-secondary rounded-r p-stack-sm">
                  <p className="text-label-caps font-label-caps text-secondary mb-1">AFTER</p>
                  <StatusBadge status={r.after_outcome} />
                </div>
              </div>
              <div className="mt-2 flex items-center gap-2">
                <span className="material-symbols-outlined text-[16px]">
                  {r.detection_improved ? 'check_circle' : 'cancel'}
                </span>
                <span
                  className={`text-data-mono-sm font-data-mono-sm ${
                    r.detection_improved ? 'text-secondary' : 'text-error'
                  }`}
                >
                  {r.detection_improved ? 'IMPROVED' : 'NOT IMPROVED'}
                </span>
                {r.validated_rule_ids.length > 0 && (
                  <span className="text-data-mono-sm font-data-mono-sm text-outline ml-2">
                    {r.validated_rule_ids.length} rule{r.validated_rule_ids.length !== 1 ? 's' : ''} validated
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* All Defensive Proposals */}
      {proposals && proposals.length > 1 && (
        <div className="mt-stack-lg">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-md">
            ALL DEFENSIVE PROPOSALS
          </p>
          <div className="space-y-3">
            {proposals.map((p) => (
              <div key={p.id} className="soc-card rounded-lg p-stack-md">
                <div className="flex justify-between items-start mb-2">
                  <span className="text-on-surface font-medium text-body-base">
                    {p.root_cause}
                  </span>
                  <StatusBadge status={p.status} />
                </div>
                <p className="text-on-surface-variant text-body-base text-sm mb-2">
                  {p.proposed_remediation}
                </p>
                {p.expected_security_effect && (
                  <p className="text-outline text-data-mono-sm font-data-mono-sm">
                    Expected: {p.expected_security_effect}
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
