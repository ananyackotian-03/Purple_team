import { useCoverage } from '@/hooks/useApi'
import { LoadingSpinner, ErrorMessage, PageHeader, EmptyState } from '@/components/Shared'

export default function Detection() {
  const { data, isLoading, error, refetch } = useCoverage()

  if (isLoading) return <LoadingSpinner />
  if (error) return <ErrorMessage message={String(error)} onRetry={refetch} />

  if (!data) return <EmptyState title="No detection data" />

  const entries = Object.entries(data.technique_coverage)

  return (
    <div>
      <PageHeader
        title="DETECTION"
        subtitle="Detection coverage analytics across all techniques"
      />

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-stack-md mb-stack-lg">
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">TOTAL</p>
          <p className="text-headline-md font-headline-md text-on-surface">
            {data.total_experiments}
          </p>
        </div>
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">DETECTED</p>
          <p className="text-headline-md font-headline-md text-secondary">
            {data.detected_experiments}
          </p>
        </div>
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">MISSED</p>
          <p className="text-headline-md font-headline-md text-error">
            {data.missed_experiments}
          </p>
        </div>
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">GAPS</p>
          <p className="text-headline-md font-headline-md text-tertiary">
            {data.gap_experiments}
          </p>
        </div>
      </div>

      <div className="soc-card rounded-lg p-stack-md mb-stack-lg">
        <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
          OVERALL COVERAGE
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

      {entries.length > 0 && (
        <div className="soc-card rounded-lg overflow-hidden">
          <div className="soc-card-header p-stack-sm px-stack-md">
            <span className="text-label-caps font-label-caps text-on-surface-variant">
              TECHNIQUE COVERAGE
            </span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/10">
                  <th className="text-left text-label-caps font-label-caps text-outline py-2 px-stack-md">
                    TECHNIQUE
                  </th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-2 px-stack-md">
                    STATUS
                  </th>
                </tr>
              </thead>
              <tbody>
                {entries.map(([tech, detected]) => (
                  <tr key={tech} className="border-b border-white/5 hover:bg-white/[0.02]">
                    <td className="py-2 px-stack-md text-data-mono font-data-mono text-on-surface">
                      {tech}
                    </td>
                    <td className="py-2 px-stack-md">
                      <span
                        className={`status-pill ${
                          detected
                            ? 'bg-secondary-container/20 border border-secondary text-secondary'
                            : 'bg-error-container/20 border border-error text-error'
                        }`}
                      >
                        {detected ? 'DETECTED' : 'NOT DETECTED'}
                      </span>
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
