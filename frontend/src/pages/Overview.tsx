import { useState } from 'react'
import { useDashboard, useImmuneCycleStatus, useRunImmuneCycle } from '@/hooks/useApi'
import { LoadingSpinner, ErrorMessage, PageHeader, StatusBadge, ConfirmationDialog } from '@/components/Shared'

export default function Overview() {
  const { data, isLoading, error, refetch } = useDashboard()
  const { data: cycle } = useImmuneCycleStatus()
  const runCycleMut = useRunImmuneCycle()
  const [isConfirmOpen, setIsConfirmOpen] = useState(false)

  if (isLoading) return <LoadingSpinner />
  if (error) return <ErrorMessage message={String(error)} onRetry={refetch} />

  const m = data!

  return (
    <div>
      <PageHeader
        title="OVERVIEW"
        subtitle="SentinelForge Cyber Immune System — Real-time security posture"
      />

      <div className="soc-card rounded-lg p-stack-md mb-stack-lg">
        <div className="flex items-center mb-stack-sm">
          <span className="material-symbols-outlined text-primary mr-2">security</span>
          <span className="text-label-caps font-label-caps text-on-surface-variant">
            SECURITY MODEL
          </span>
        </div>
        <div className="flex items-center gap-2 flex-wrap text-data-mono font-data-mono text-on-surface-variant">
          <span className="px-2 py-1 bg-tertiary/10 border border-tertiary/30 text-tertiary rounded">
            LLM (Untrusted)
          </span>
          <span className="material-symbols-outlined text-outline text-[16px]">arrow_forward</span>
          <span className="px-2 py-1 bg-primary/10 border border-primary/30 text-primary rounded">
            Safety Boundary
          </span>
          <span className="material-symbols-outlined text-outline text-[16px]">arrow_forward</span>
          <span className="px-2 py-1 bg-primary/10 border border-primary/30 text-primary rounded">
            Policy Engine
          </span>
          <span className="material-symbols-outlined text-outline text-[16px]">arrow_forward</span>
          <span className="px-2 py-1 bg-primary/10 border border-primary/30 text-primary rounded">
            Authorization
          </span>
          <span className="material-symbols-outlined text-outline text-[16px]">arrow_forward</span>
          <span className="px-2 py-1 bg-secondary/10 border border-secondary/30 text-secondary rounded">
            Execution
          </span>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-stack-md mb-stack-lg">
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">OBJECTIVES</p>
          <p className="text-headline-md font-headline-md text-on-surface">{m.total_objectives}</p>
        </div>
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">EXPERIMENTS</p>
          <p className="text-headline-md font-headline-md text-on-surface">{m.total_experiments}</p>
          <p className="text-data-mono-sm font-data-mono-sm text-outline mt-1">
            {m.completed_experiments} completed
          </p>
        </div>
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">DETECTIONS</p>
          <p className="text-headline-md font-headline-md text-on-surface">{m.total_detections}</p>
          <p className="text-data-mono-sm font-data-mono-sm text-error mt-1">
            {m.detection_gaps} gaps
          </p>
        </div>
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">COVERAGE</p>
          <p className="text-headline-md font-headline-md text-secondary">
            {m.coverage_pct.toFixed(1)}%
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-stack-md mb-stack-lg">
        <div className="soc-card rounded-lg lg:col-span-2 p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
            DETECTION COVERAGE
          </p>
          <div className="w-full bg-surface-container-high rounded-full h-3 mb-2">
            <div
              className="bg-secondary h-3 rounded-full transition-all duration-500"
              style={{ width: `${m.coverage_pct}%` }}
            />
          </div>
          <div className="flex justify-between text-data-mono-sm font-data-mono-sm text-outline">
            <span>{m.total_detections} detected</span>
            <span>{m.detection_gaps} gaps</span>
          </div>
        </div>
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
            RETESTS
          </p>
          <p className="text-headline-md font-headline-md text-on-surface">{m.total_retests}</p>
          <p className="text-data-mono-sm font-data-mono-sm text-secondary mt-1">
            {m.retests_improved} improved
          </p>
        </div>
      </div>

      {/* Immune Cycle Status */}
      {cycle && (
        <div className="soc-card rounded-lg p-stack-md mb-stack-lg">
          <div className="flex items-center justify-between mb-stack-sm">
            <span className="text-label-caps font-label-caps text-on-surface-variant">
              IMMUNE CYCLE
            </span>
            <div className="flex items-center gap-3">
              <StatusBadge status={cycle.current_state} />
              <button
                onClick={() => setIsConfirmOpen(true)}
                disabled={runCycleMut.isPending}
                className="px-4 py-2 bg-primary/10 border border-primary/30 text-primary hover:bg-primary/20 transition-colors rounded flex items-center text-label-caps font-label-caps disabled:opacity-50"
              >
                <span className="material-symbols-outlined mr-1 text-[18px]">play_arrow</span>
                {runCycleMut.isPending ? 'RUNNING...' : 'RUN IMMUNE CYCLE'}
              </button>
            </div>
          </div>
          
          <ConfirmationDialog
            isOpen={isConfirmOpen}
            title="Run Cyber Immune Cycle"
            message="Are you sure you want to trigger the SentinelForge cyber immune cycle? This will automatically identify gaps, propose defensive mitigations, and run validation retests in the sandbox."
            confirmText="RUN CYCLE"
            onConfirm={() => {
              setIsConfirmOpen(false)
              runCycleMut.mutate(undefined)
            }}
            onCancel={() => setIsConfirmOpen(false)}
          />
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-stack-md">
            <div>
              <p className="text-label-caps font-label-caps text-outline mb-1">CYCLES</p>
              <p className="text-data-mono font-data-mono text-on-surface">{cycle.total_cycles}</p>
            </div>
            <div>
              <p className="text-label-caps font-label-caps text-outline mb-1">MITIGATED</p>
              <p className="text-data-mono font-data-mono text-secondary">{cycle.mitigated_count}</p>
            </div>
            <div>
              <p className="text-label-caps font-label-caps text-outline mb-1">UNRESOLVED</p>
              <p className="text-data-mono font-data-mono text-tertiary">{cycle.unresolved_count}</p>
            </div>
            <div>
              <p className="text-label-caps font-label-caps text-outline mb-1">LAST CYCLE</p>
              <p className="text-data-mono-sm font-data-mono-sm text-on-surface-variant">
                {cycle.last_cycle_at
                  ? new Date(cycle.last_cycle_at).toLocaleDateString()
                  : '—'}
              </p>
            </div>
          </div>
        </div>
      )}

      {m.recent_activities.length > 0 && (
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-md">
            RECENT ACTIVITY
          </p>
          <div className="space-y-3">
            {m.recent_activities.map((a, i) => (
              <div
                key={i}
                className="flex items-center justify-between py-2 border-b border-white/5 last:border-0"
              >
                <div className="flex-1 min-w-0">
                  <p className="text-on-surface text-body-base truncate">{a.title}</p>
                  <p className="text-on-surface-variant text-data-mono-sm font-data-mono-sm">
                    {a.objective}
                  </p>
                </div>
                <span
                  className={`status-pill ml-3 ${
                    a.risk_level === 'CRITICAL'
                      ? 'bg-error-container text-on-error'
                      : a.risk_level === 'HIGH'
                      ? 'bg-error/10 text-error border border-error/30'
                      : a.risk_level === 'MEDIUM'
                      ? 'bg-tertiary/10 text-tertiary border border-tertiary/30'
                      : 'bg-secondary/10 text-secondary border border-secondary/30'
                  }`}
                >
                  {a.risk_level}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {!m.recent_activities.length && (
        <div className="soc-card rounded-lg p-stack-md text-center">
          <span className="material-symbols-outlined text-outline text-[48px] mb-3">inbox</span>
          <p className="text-on-surface font-medium">No activity yet</p>
          <p className="text-on-surface-variant text-body-base mt-1">
            Run a security experiment to get started
          </p>
        </div>
      )}
    </div>
  )
}
