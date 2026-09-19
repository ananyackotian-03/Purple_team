import { Link } from 'react-router-dom'
import { useExperiments } from '@/hooks/useApi'
import { LoadingSpinner, ErrorMessage, PageHeader, StatusBadge, RiskBadge, EmptyState } from '@/components/Shared'

export default function Experiments() {
  const { data, isLoading, error, refetch } = useExperiments()

  if (isLoading) return <LoadingSpinner />
  if (error) return <ErrorMessage message={String(error)} onRetry={refetch} />

  return (
    <div>
      <PageHeader
        title="EXPERIMENTS"
        subtitle="All adversarial security experiments"
      />

      {!data?.length ? (
        <EmptyState
          title="No experiments"
          description="Run a security experiment from an objective to get started"
        />
      ) : (
        <div className="soc-card rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/10">
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">TITLE</th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">STATUS</th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">RISK</th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">CREATED BY</th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">DATE</th>
                </tr>
              </thead>
              <tbody>
                {data.map((e) => (
                  <tr key={e.id} className="border-b border-white/5 hover:bg-white/[0.02]">
                    <td className="py-3 px-stack-md">
                      <Link
                        to={`/experiments/${e.id}`}
                        className="text-on-surface hover:text-primary transition-colors"
                      >
                        {e.title || e.id.slice(0, 8)}
                      </Link>
                      {e.strategy_description && (
                        <p className="text-on-surface-variant text-data-mono-sm font-data-mono-sm mt-1 line-clamp-1">
                          {e.strategy_description}
                        </p>
                      )}
                    </td>
                    <td className="py-3 px-stack-md">
                      <StatusBadge status={e.status || 'PENDING'} />
                    </td>
                    <td className="py-3 px-stack-md">
                      <RiskBadge level={e.risk_level || 'MEDIUM'} />
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
