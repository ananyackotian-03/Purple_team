import { useExperiments } from '@/hooks/useApi'
import { Link } from 'react-router-dom'
import { LoadingSpinner, ErrorMessage, PageHeader, EmptyState } from '@/components/Shared'

export default function Telemetry() {
  const { data: experiments, isLoading, error, refetch } = useExperiments()

  if (isLoading) return <LoadingSpinner />
  if (error) return <ErrorMessage message={String(error)} onRetry={refetch} />

  const completedExps = experiments?.filter(
    (e) =>
      e.status === 'COMPLETED' ||
      e.status === 'DETECTED' ||
      e.status === 'NOT_DETECTED' ||
      e.status === 'DETECTION_GAP'
  ) || []

  return (
    <div>
      <PageHeader
        title="TELEMETRY"
        subtitle="Normalized security events from experiment execution"
      />

      <div className="soc-card rounded-lg p-stack-md mb-stack-lg">
        <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
          TELEMETRY STATUS
        </p>
        <p className="text-on-surface-variant text-body-base">
          Telemetry events are collected during experiment execution via the TelemetryCollector
          and TelemetryNormalizer pipeline. Events are normalized into a standard format including
          event type, source, technique, process, command line, and detection status.
        </p>
        <p className="text-on-surface-variant text-body-base mt-2">
          Individual telemetry events are accessible through the Experiment Detail page for each
          completed experiment. The table below shows experiments that have generated telemetry data.
        </p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-stack-md mb-stack-lg">
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">EXPERIMENTS</p>
          <p className="text-headline-md font-headline-md text-on-surface">
            {experiments?.length || 0}
          </p>
        </div>
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">COMPLETED</p>
          <p className="text-headline-md font-headline-md text-secondary">
            {completedExps.length}
          </p>
        </div>
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">DETECTED</p>
          <p className="text-headline-md font-headline-md text-secondary">
            {completedExps.filter((e) => e.status === 'DETECTED').length}
          </p>
        </div>
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">MISSED</p>
          <p className="text-headline-md font-headline-md text-error">
            {completedExps.filter((e) => e.status === 'NOT_DETECTED' || e.status === 'DETECTION_GAP').length}
          </p>
        </div>
      </div>

      {!completedExps.length ? (
        <EmptyState
          title="No telemetry data"
          description="Execute experiments to generate telemetry events. View experiment details for individual telemetry records."
        />
      ) : (
        <div className="soc-card rounded-lg overflow-hidden">
          <div className="soc-card-header p-stack-sm px-stack-md">
            <span className="text-label-caps font-label-caps text-on-surface-variant">
              EXPERIMENT TELEMETRY RECORDS
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
                    STRATEGY
                  </th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">
                    CREATED BY
                  </th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">
                    DATE
                  </th>
                </tr>
              </thead>
              <tbody>
                {completedExps.map((e) => (
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
                      <span
                        className={`status-pill ${
                          e.status === 'DETECTED'
                            ? 'bg-secondary-container/20 border border-secondary text-secondary'
                            : e.status === 'NOT_DETECTED' || e.status === 'DETECTION_GAP'
                            ? 'bg-error-container/20 border border-error text-error'
                            : 'bg-surface-variant text-on-surface-variant'
                        }`}
                      >
                        {e.status}
                      </span>
                    </td>
                    <td className="py-3 px-stack-md text-on-surface-variant text-body-base max-w-xs truncate">
                      {e.strategy_description || '—'}
                    </td>
                    <td className="py-3 px-stack-md text-data-mono font-data-mono text-on-surface-variant">
                      {e.created_by || '—'}
                    </td>
                    <td className="py-3 px-stack-md text-data-mono-sm font-data-mono-sm text-outline">
                      {e.created_at ? new Date(e.created_at).toLocaleDateString() : '—'}
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
