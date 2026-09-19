import { useImmuneMemory } from '@/hooks/useApi'
import { LoadingSpinner, ErrorMessage, PageHeader, EmptyState, StatusBadge } from '@/components/Shared'

export default function ImmuneMemoryPage() {
  const { data, isLoading, error, refetch } = useImmuneMemory()

  if (isLoading) return <LoadingSpinner />
  if (error) return <ErrorMessage message={String(error)} onRetry={refetch} />
  if (!data) return <EmptyState title="No immune memory" />

  return (
    <div>
      <PageHeader
        title="IMMUNE MEMORY"
        subtitle="Accumulated security experience and learning history"
      />

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-stack-md mb-stack-lg">
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">EXPERIMENTS</p>
          <p className="text-headline-md font-headline-md text-on-surface">
            {data.previous_experiments}
          </p>
        </div>
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">TECHNIQUES</p>
          <p className="text-headline-md font-headline-md text-primary">
            {data.techniques_tested.length}
          </p>
        </div>
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">MITIGATED</p>
          <p className="text-headline-md font-headline-md text-secondary">
            {data.mitigated_gaps}
          </p>
        </div>
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">UNRESOLVED</p>
          <p className="text-headline-md font-headline-md text-tertiary">
            {data.unresolved_gaps}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-stack-md mb-stack-lg">
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
            COVERAGE
          </p>
          <div className="w-full bg-surface-container-high rounded-full h-3 mb-2">
            <div
              className="bg-secondary h-3 rounded-full transition-all duration-500"
              style={{ width: `${data.coverage_pct}%` }}
            />
          </div>
          <p className="text-data-mono font-data-mono text-secondary">
            {data.coverage_pct.toFixed(1)}%
          </p>
        </div>
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
            DEFENSIVE IMPROVEMENTS
          </p>
          <div className="flex items-center gap-4">
            <div>
              <p className="text-headline-md font-headline-md text-secondary">
                {data.successful_improvements}
              </p>
              <p className="text-data-mono-sm font-data-mono-sm text-outline">successful</p>
            </div>
            <div>
              <p className="text-headline-md font-headline-md text-error">
                {data.failed_improvements}
              </p>
              <p className="text-data-mono-sm font-data-mono-sm text-outline">failed</p>
            </div>
          </div>
        </div>
      </div>

      {data.techniques_tested.length > 0 && (
        <div className="soc-card rounded-lg p-stack-md mb-stack-lg">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
            TECHNIQUES TESTED
          </p>
          <div className="flex flex-wrap gap-2">
            {data.techniques_tested.map((t) => (
              <span
                key={t}
                className="px-2 py-1 bg-primary/10 border border-primary/30 text-primary rounded text-data-mono-sm font-data-mono-sm"
              >
                {t}
              </span>
            ))}
          </div>
        </div>
      )}

      {Object.keys(data.detection_outcomes).length > 0 && (
        <div className="soc-card rounded-lg p-stack-md mb-stack-lg">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
            DETECTION OUTCOMES
          </p>
          <div className="space-y-2">
            {Object.entries(data.detection_outcomes).map(([outcome, count]) => (
              <div key={outcome} className="flex justify-between items-center">
                <span className="text-on-surface-variant text-body-base">{outcome}</span>
                <span className="text-data-mono font-data-mono text-on-surface">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Detection Gaps */}
      {data.detection_gaps.length > 0 && (
        <div className="soc-card rounded-lg p-stack-md mb-stack-lg">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
            DETECTION GAPS
          </p>
          <div className="space-y-2">
            {data.detection_gaps.map((gap, i) => (
              <div key={i} className="flex items-center justify-between py-2 border-b border-white/5 last:border-0">
                <div className="flex items-center gap-2">
                  <span className="text-data-mono-sm font-data-mono-sm text-primary">
                    {String(gap.technique_id || '—')}
                  </span>
                  <span className="text-on-surface-variant text-body-base text-sm">
                    {String(gap.reason || '')}
                  </span>
                </div>
                <StatusBadge status={String(gap.remediation_status || 'OPEN')} />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Retest Results */}
      {data.retest_results.length > 0 && (
        <div className="soc-card rounded-lg p-stack-md mb-stack-lg">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
            RETEST RESULTS
          </p>
          <div className="space-y-2">
            {data.retest_results.map((rt, i) => (
              <div key={i} className="flex items-center justify-between py-2 border-b border-white/5 last:border-0">
                <div className="flex items-center gap-3">
                  <span className="text-data-mono-sm font-data-mono-sm text-outline">
                    {String(rt.id || '').slice(0, 8)}
                  </span>
                  <StatusBadge status={String(rt.before_outcome || '—')} />
                  <span className="material-symbols-outlined text-outline text-[16px]">arrow_forward</span>
                  <StatusBadge status={String(rt.after_outcome || '—')} />
                </div>
                <span className={`text-data-mono-sm font-data-mono-sm ${rt.detection_improved ? 'text-secondary' : 'text-error'}`}>
                  {rt.detection_improved ? 'IMPROVED' : 'NOT IMPROVED'}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Defensive Proposals */}
      {data.defensive_proposals.length > 0 && (
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
            DEFENSIVE PROPOSALS
          </p>
          <div className="space-y-2">
            {data.defensive_proposals.map((dp, i) => (
              <div key={i} className="flex items-center justify-between py-2 border-b border-white/5 last:border-0">
                <div className="flex-1 min-w-0">
                  <span className="text-on-surface text-body-base">
                    {String(dp.root_cause || '—')}
                  </span>
                  <p className="text-on-surface-variant text-data-mono-sm font-data-mono-sm mt-1 truncate">
                    {String(dp.proposed_remediation || '')}
                  </p>
                </div>
                <StatusBadge status={String(dp.status || 'CREATED')} />
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
