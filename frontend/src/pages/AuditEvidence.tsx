import { useExperiments, useRetests } from '@/hooks/useApi'
import { Link } from 'react-router-dom'
import { LoadingSpinner, ErrorMessage, PageHeader, EmptyState, StatusBadge } from '@/components/Shared'

export default function AuditEvidence() {
  const { data: experiments, isLoading: eLoad, error: eErr, refetch: eRef } = useExperiments()
  const { data: retests, isLoading: rLoad } = useRetests()

  if (eLoad || rLoad) return <LoadingSpinner />
  if (eErr) return <ErrorMessage message={String(eErr)} onRetry={eRef} />

  const completed = experiments?.filter(
    (e) =>
      e.status === 'COMPLETED' ||
      e.status === 'DETECTED' ||
      e.status === 'NOT_DETECTED' ||
      e.status === 'DETECTION_GAP'
  ) || []

  return (
    <div>
      <PageHeader
        title="AUDIT & EVIDENCE"
        subtitle="Full evidence chain traceability from objective to detection"
      />

      {/* Evidence Chain Visualization */}
      <div className="soc-card rounded-lg p-stack-md mb-stack-lg">
        <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
          EVIDENCE CHAIN
        </p>
        <div className="flex items-center gap-2 flex-wrap text-data-mono font-data-mono text-on-surface-variant">
          {[
            { label: 'OBJECTIVE', icon: 'target' },
            { label: 'EXPERIMENT', icon: 'science' },
            { label: 'EXECUTION', icon: 'play_arrow' },
            { label: 'TELEMETRY', icon: 'biotech' },
            { label: 'DETECTION', icon: 'radar' },
            { label: 'EVALUATION', icon: 'fact_check' },
            { label: 'RETEST', icon: 'refresh' },
          ].map((step, i) => (
            <span key={i} className="flex items-center gap-2">
              <span className="px-2 py-1 bg-primary/10 border border-primary/30 text-primary rounded text-data-mono-sm font-data-mono-sm flex items-center gap-1">
                <span className="material-symbols-outlined text-[14px]">{step.icon}</span>
                {step.label}
              </span>
              {i < 6 && (
                <span className="material-symbols-outlined text-outline text-[16px]">
                  arrow_forward
                </span>
              )}
            </span>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-stack-md mb-stack-lg">
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">TOTAL</p>
          <p className="text-headline-md font-headline-md text-on-surface">
            {experiments?.length || 0}
          </p>
        </div>
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">WITH EVIDENCE</p>
          <p className="text-headline-md font-headline-md text-secondary">
            {completed.length}
          </p>
        </div>
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">RETESTS</p>
          <p className="text-headline-md font-headline-md text-primary">
            {retests?.length || 0}
          </p>
        </div>
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">IMPROVED</p>
          <p className="text-headline-md font-headline-md text-secondary">
            {retests?.filter((r) => r.detection_improved).length || 0}
          </p>
        </div>
      </div>

      {!completed.length ? (
        <EmptyState
          title="No evidence records"
          description="Complete experiments to generate audit evidence"
        />
      ) : (
        <div className="soc-card rounded-lg overflow-hidden">
          <div className="soc-card-header p-stack-sm px-stack-md">
            <span className="text-label-caps font-label-caps text-on-surface-variant">
              EVIDENCE RECORDS
            </span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/10">
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">
                    EXPERIMENT
                  </th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">
                    STATUS
                  </th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">
                    RISK LEVEL
                  </th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">
                    CREATED BY
                  </th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">
                    EVIDENCE
                  </th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">
                    RETEST
                  </th>
                </tr>
              </thead>
              <tbody>
                {completed.map((e) => {
                  const retest = retests?.find((r) => r.scenario_id === e.id)
                  return (
                    <tr key={e.id} className="border-b border-white/5 hover:bg-white/[0.02]">
                      <td className="py-3 px-stack-md">
                        <Link
                          to={`/experiments/${e.id}`}
                          className="text-on-surface hover:text-primary transition-colors"
                        >
                          {e.title || e.id.slice(0, 8)}
                        </Link>
                      </td>
                      <td className="py-3 px-stack-md">
                        <StatusBadge status={e.status || 'PENDING'} />
                      </td>
                      <td className="py-3 px-stack-md text-data-mono font-data-mono text-primary">
                        {e.risk_level || '—'}
                      </td>
                      <td className="py-3 px-stack-md text-data-mono-sm font-data-mono-sm text-on-surface-variant">
                        {e.created_by || '—'}
                      </td>
                      <td className="py-3 px-stack-md">
                        <Link
                          to={`/evidence/${e.id}`}
                          className="text-primary hover:text-primary/80 transition-colors text-data-mono-sm font-data-mono-sm flex items-center gap-1"
                        >
                          <span className="material-symbols-outlined text-[14px]">visibility</span>
                          VIEW
                        </Link>
                      </td>
                      <td className="py-3 px-stack-md text-data-mono-sm font-data-mono-sm">
                        {retest ? (
                          <span className={retest.detection_improved ? 'text-secondary' : 'text-error'}>
                            {retest.detection_improved ? 'IMPROVED' : 'NOT IMPROVED'}
                          </span>
                        ) : (
                          <span className="text-outline">—</span>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
