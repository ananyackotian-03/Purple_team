import { useNextExperiment, useImmuneCycleStatus } from '@/hooks/useApi'
import { LoadingSpinner, ErrorMessage, PageHeader, StatusBadge, EmptyState } from '@/components/Shared'

export default function AdaptiveTesting() {
  const { data: next, isLoading: nLoad, error: nErr, refetch: nRef } = useNextExperiment()
  const { data: cycle } = useImmuneCycleStatus()

  if (nLoad) return <LoadingSpinner />
  if (nErr) return <ErrorMessage message={String(nErr)} onRetry={nRef} />

  return (
    <div>
      <PageHeader
        title="ADAPTIVE TESTING"
        subtitle="AI-driven experiment selection with deterministic safety validation"
      />

      {/* LLM vs Deterministic Authority Banner */}
      <div className="soc-card rounded-lg p-stack-md mb-stack-lg">
        <div className="flex items-center mb-stack-sm">
          <span className="material-symbols-outlined text-tertiary mr-2">psychology</span>
          <span className="text-label-caps font-label-caps text-on-surface-variant">
            SECURITY ARCHITECTURE PRINCIPLE
          </span>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-stack-md">
          <div className="bg-tertiary/5 border border-tertiary/20 rounded p-stack-md">
            <div className="flex items-center gap-2 mb-2">
              <span className="material-symbols-outlined text-tertiary text-[20px]">psychology</span>
              <span className="text-label-caps font-label-caps text-tertiary">LLM = REASONING</span>
            </div>
            <p className="text-on-surface-variant text-body-base">
              The LLM generates strategies, proposes experiments, and provides reasoning.
              It has NO execution authority. All outputs are treated as untrusted proposals.
            </p>
          </div>
          <div className="bg-primary/5 border border-primary/20 rounded p-stack-md">
            <div className="flex items-center gap-2 mb-2">
              <span className="material-symbols-outlined text-primary text-[20px]">shield</span>
              <span className="text-label-caps font-label-caps text-primary">DETERMINISTIC = AUTHORITY</span>
            </div>
            <p className="text-on-surface-variant text-body-base">
              Safety boundaries, policy engine, tool authorization, and scoring are all
              deterministic. The system decides what runs, not the LLM.
            </p>
          </div>
        </div>
      </div>

      <div className="soc-card rounded-lg p-stack-md mb-stack-lg border-primary/30 border">
        <div className="flex items-center mb-stack-sm">
          <span className="material-symbols-outlined text-primary mr-2">psychology</span>
          <span className="text-label-caps font-label-caps text-on-surface-variant">
            NEXT EXPERIMENT
          </span>
        </div>
        {next ? (
          <div className="space-y-4">
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-stack-md">
              <div>
                <p className="text-label-caps font-label-caps text-outline mb-1">STRATEGY</p>
                <p className="text-data-mono font-data-mono text-primary">
                  {next.selected_strategy || '—'}
                </p>
              </div>
              <div>
                <p className="text-label-caps font-label-caps text-outline mb-1">SCORE</p>
                <p className="text-data-mono font-data-mono text-on-surface">
                  {next.score.toFixed(2)}
                </p>
              </div>
              <div>
                <p className="text-label-caps font-label-caps text-outline mb-1">METHOD</p>
                <p className="text-data-mono font-data-mono text-on-surface-variant">
                  {next.selection_method}
                </p>
              </div>
              <div>
                <p className="text-label-caps font-label-caps text-outline mb-1">CANDIDATES</p>
                <p className="text-data-mono font-data-mono text-on-surface-variant">
                  {next.candidates_count}
                </p>
              </div>
            </div>
            <div className="border-t border-white/5 pt-3">
              <p className="text-label-caps font-label-caps text-outline mb-1">REASONING</p>
              <p className="text-on-surface-variant text-body-base">{next.reason}</p>
            </div>
            <div className="flex items-center gap-4 flex-wrap">
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-[16px]">
                  {next.validation_passed ? 'check_circle' : 'cancel'}
                </span>
                <span
                  className={`text-data-mono-sm font-data-mono-sm ${
                    next.validation_passed ? 'text-secondary' : 'text-error'
                  }`}
                >
                  {next.validation_passed ? 'VALIDATION PASSED' : 'VALIDATION FAILED'}
                </span>
              </div>
              {next.used_llm && (
                <span className="text-data-mono-sm font-data-mono-sm text-tertiary">
                  LLM REASONING
                </span>
              )}
              {next.used_fallback && (
                <span className="text-data-mono-sm font-data-mono-sm text-outline">
                  FALLBACK
                </span>
              )}
              {next.selected_at && (
                <span className="text-data-mono-sm font-data-mono-sm text-outline">
                  {new Date(next.selected_at).toLocaleString()}
                </span>
              )}
            </div>
            {next.validation_rejection && (
              <div className="bg-error/5 border border-error/20 rounded p-stack-sm">
                <p className="text-label-caps font-label-caps text-error mb-1">REJECTION REASON</p>
                <p className="text-on-surface-variant text-body-base text-sm">
                  {next.validation_rejection}
                </p>
              </div>
            )}
            {next.selected_techniques.length > 0 && (
              <div>
                <p className="text-label-caps font-label-caps text-outline mb-1">TECHNIQUES</p>
                <div className="flex flex-wrap gap-2">
                  {next.selected_techniques.map((t) => (
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
            {next.evidence_references.length > 0 && (
              <div>
                <p className="text-label-caps font-label-caps text-outline mb-1">EVIDENCE REFERENCES</p>
                <div className="flex flex-wrap gap-2">
                  {next.evidence_references.map((ref) => (
                    <span
                      key={ref}
                      className="px-2 py-1 bg-surface-variant border border-outline-variant text-on-surface-variant rounded text-data-mono-sm font-data-mono-sm"
                    >
                      {ref}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <EmptyState title="No next experiment" description="Run experiments to build adaptive context" />
        )}
      </div>

      {cycle && (
        <div className="soc-card rounded-lg p-stack-md mb-stack-lg">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
            IMMUNE CYCLE STATUS
          </p>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-stack-md">
            <div>
              <p className="text-label-caps font-label-caps text-outline mb-1">STATE</p>
              <StatusBadge status={cycle.current_state} />
            </div>
            <div>
              <p className="text-label-caps font-label-caps text-outline mb-1">TOTAL CYCLES</p>
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
          </div>
        </div>
      )}

      <div className="soc-card rounded-lg p-stack-md">
        <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
          SECURITY ARCHITECTURE
        </p>
        <div className="flex flex-col gap-2 text-data-mono font-data-mono text-on-surface-variant">
          <div className="px-3 py-2 bg-tertiary/10 border border-tertiary/30 text-tertiary rounded text-center">
            LLM (Reasoning — No Authority)
          </div>
          <div className="text-center text-outline">
            <span className="material-symbols-outlined text-[16px]">arrow_downward</span>
          </div>
          <div className="px-3 py-2 bg-primary/10 border border-primary/30 text-primary rounded text-center">
            Deterministic Scoring
          </div>
          <div className="text-center text-outline">
            <span className="material-symbols-outlined text-[16px]">arrow_downward</span>
          </div>
          <div className="px-3 py-2 bg-primary/10 border border-primary/30 text-primary rounded text-center">
            Safety Boundary Validation
          </div>
          <div className="text-center text-outline">
            <span className="material-symbols-outlined text-[16px]">arrow_downward</span>
          </div>
          <div className="px-3 py-2 bg-secondary/10 border border-secondary/30 text-secondary rounded text-center">
            Authorized Experiment Execution
          </div>
        </div>
      </div>
    </div>
  )
}
