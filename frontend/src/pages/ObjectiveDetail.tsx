import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useObjective, useRunExperiment } from '@/hooks/useApi'
import { LoadingSpinner, ErrorMessage, RiskBadge, ConfirmationDialog } from '@/components/Shared'

export default function ObjectiveDetail() {
  const { id } = useParams<{ id: string }>()
  const { data, isLoading, error, refetch } = useObjective(id)
  const runMut = useRunExperiment()
  const [isConfirmOpen, setIsConfirmOpen] = useState(false)

  if (isLoading) return <LoadingSpinner />
  if (error) return <ErrorMessage message={String(error)} onRetry={refetch} />
  if (!data) return null

  const { objective, experiments } = data

  return (
    <div>
      <div className="mb-stack-lg">
        <div className="flex items-center gap-2 text-on-surface-variant text-body-base mb-2">
          <Link to="/objectives" className="hover:text-on-surface transition-colors">
            Objectives
          </Link>
          <span className="material-symbols-outlined text-[16px]">chevron_right</span>
          <span className="text-on-surface">{objective.title}</span>
        </div>
      </div>

      <div className="soc-card rounded-lg p-stack-md mb-stack-lg">
        <div className="flex justify-between items-start">
          <div>
            <h2 className="text-headline-md font-headline-md text-on-surface">
              {objective.title}
            </h2>
            {objective.description && (
              <p className="text-on-surface-variant text-body-base mt-2">
                {objective.description}
              </p>
            )}
            <div className="flex items-center gap-3 mt-3">
              <span className="text-data-mono-sm font-data-mono-sm text-outline">
                {objective.target_category}
              </span>
              <RiskBadge level={objective.default_risk_level} />
              <span className="text-data-mono-sm font-data-mono-sm text-outline">
                {objective.experiment_count} experiments
              </span>
            </div>
          </div>
          <button
            onClick={() => setIsConfirmOpen(true)}
            disabled={runMut.isPending}
            className="px-4 py-2 bg-primary text-on-primary hover:bg-primary/90 transition-colors rounded flex items-center text-label-caps font-label-caps disabled:opacity-50"
          >
            <span className="material-symbols-outlined mr-1 text-[18px]">play_arrow</span>
            {runMut.isPending ? 'STARTING...' : 'RUN EXPERIMENT'}
          </button>
        </div>
      </div>

      <ConfirmationDialog
        isOpen={isConfirmOpen}
        title="Run Security Experiment"
        message={`Are you sure you want to execute a new experiment for objective "${objective.title}"? This will trigger live execution in the sandbox.`}
        confirmText="RUN EXPERIMENT"
        onConfirm={() => {
          setIsConfirmOpen(false)
          runMut.mutate(objective.id)
        }}
        onCancel={() => setIsConfirmOpen(false)}
      />

      <div className="mb-stack-md">
        <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
          EXPERIMENTS
        </p>
      </div>

      {!experiments.length ? (
        <div className="soc-card rounded-lg p-stack-lg text-center">
          <span className="material-symbols-outlined text-outline text-[48px] mb-3">science</span>
          <p className="text-on-surface font-medium">No experiments yet</p>
          <p className="text-on-surface-variant text-body-base mt-1">
            Click "RUN EXPERIMENT" to start the first security validation
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {experiments.map((e) => (
            <Link
              key={e.id}
              to={`/experiments/${e.id}`}
              className="soc-card rounded-lg p-stack-md block hover:bg-surface-container-high transition-all"
            >
              <div className="flex justify-between items-start">
                <div className="flex-1 min-w-0">
                  <h3 className="text-on-surface font-medium text-body-base">
                    {e.title || e.id.slice(0, 8)}
                  </h3>
                  {e.strategy_description && (
                    <p className="text-on-surface-variant text-body-base mt-1 line-clamp-2">
                      {e.strategy_description}
                    </p>
                  )}
                  <div className="flex items-center gap-3 mt-2">
                    <span className="text-data-mono-sm font-data-mono-sm text-outline">
                      {e.created_by}
                    </span>
                    <span className="text-data-mono-sm font-data-mono-sm text-outline">
                      {new Date(e.created_at).toLocaleDateString()}
                    </span>
                  </div>
                </div>
                <RiskBadge level={e.proposed_risk_level} />
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  )
}
