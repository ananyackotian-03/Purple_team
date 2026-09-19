import { useParams, Link } from 'react-router-dom'
import { useEvidenceTrace } from '@/hooks/useApi'
import { LoadingSpinner, ErrorMessage, PageHeader } from '@/components/Shared'

function TraceSection({
  title,
  data,
  color = 'text-on-surface-variant',
}: {
  title: string
  data: Record<string, unknown> | null | undefined
  color?: string
}) {
  if (!data) {
    return (
      <div className="soc-card rounded-lg p-stack-md opacity-50">
        <p className={`text-label-caps font-label-caps ${color} mb-2`}>{title}</p>
        <p className="text-on-surface-variant text-body-base">No data</p>
      </div>
    )
  }
  return (
    <div className="soc-card rounded-lg p-stack-md">
      <p className={`text-label-caps font-label-caps ${color} mb-stack-sm`}>{title}</p>
      <div className="space-y-2">
        {Object.entries(data)
          .filter(([k]) => !k.startsWith('_'))
          .slice(0, 10)
          .map(([key, val]) => (
            <div key={key} className="flex justify-between items-center border-b border-white/5 pb-2 last:border-0 last:pb-0">
              <span className="text-label-caps font-label-caps text-outline">{key}</span>
              <span className="text-data-mono-sm font-data-mono-sm text-on-surface max-w-xs truncate">
                {val === null || val === undefined ? '—' : typeof val === 'object' ? JSON.stringify(val) : String(val)}
              </span>
            </div>
          ))}
      </div>
    </div>
  )
}

export default function EvidenceTrace() {
  const { id } = useParams<{ id: string }>()
  const { data, isLoading, error, refetch } = useEvidenceTrace(id)

  if (isLoading) return <LoadingSpinner />
  if (error) return <ErrorMessage message={String(error)} onRetry={refetch} />
  if (!data) return null

  return (
    <div>
      <div className="mb-stack-lg">
        <div className="flex items-center gap-2 text-on-surface-variant text-body-base mb-2">
          <Link to="/audit" className="hover:text-on-surface transition-colors">
            Audit & Evidence
          </Link>
          <span className="material-symbols-outlined text-[16px]">chevron_right</span>
          <span className="text-on-surface">Evidence Trace</span>
        </div>
      </div>

      <PageHeader
        title="EVIDENCE TRACE"
        subtitle="Full traceability chain from objective to detection"
      />

      <div className="soc-card rounded-lg p-stack-md mb-stack-lg">
        <div className="flex items-center gap-2 flex-wrap text-data-mono font-data-mono text-on-surface-variant">
          {['OBJECTIVE', 'EXPERIMENT', 'EXECUTION', 'TELEMETRY', 'DETECTION', 'EVALUATION', 'RETEST'].map(
            (step, i) => (
              <span key={i} className="flex items-center gap-2">
                <span className="px-2 py-1 bg-primary/10 border border-primary/30 text-primary rounded text-data-mono-sm font-data-mono-sm">
                  {step}
                </span>
                {i < 6 && (
                  <span className="material-symbols-outlined text-outline text-[16px]">arrow_forward</span>
                )}
              </span>
            )
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-stack-md">
        <TraceSection title="SECURITY OBJECTIVE" data={data.objective} />
        <TraceSection title="EXPERIMENT" data={data.experiment} />
        <TraceSection title="EXECUTION" data={data.execution} />
        <TraceSection title="DETECTION" data={data.detection} />
        <TraceSection title="PURPLE EVALUATION" data={data.purple_evaluation} />
        <TraceSection title="RETEST" data={data.retest} />
      </div>

      {data.telemetry && data.telemetry.length > 0 && (
        <div className="mt-stack-md">
          <TraceSection
            title={`TELEMETRY (${data.telemetry.length} events)`}
            data={data.telemetry[0]}
          />
        </div>
      )}
    </div>
  )
}
