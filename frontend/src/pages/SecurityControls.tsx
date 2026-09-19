import { useTwinControls } from '@/hooks/useApi'
import { LoadingSpinner, ErrorMessage, PageHeader, StatusBadge, EmptyState } from '@/components/Shared'

export default function SecurityControls() {
  const { data, isLoading, error, refetch } = useTwinControls()

  if (isLoading) return <LoadingSpinner />
  if (error) return <ErrorMessage message={String(error)} onRetry={refetch} />

  return (
    <div>
      <PageHeader
        title="SECURITY CONTROLS"
        subtitle="Security architecture and defense-in-depth layers"
      />

      <div className="soc-card rounded-lg p-stack-md mb-stack-lg">
        <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
          SECURITY ARCHITECTURE
        </p>
        <div className="flex flex-col gap-2 text-data-mono font-data-mono text-on-surface-variant">
          {[
            { label: 'LLM', sub: 'Reasoning Only', cls: 'bg-tertiary/10 border-tertiary/30 text-tertiary', icon: 'psychology' },
            { label: 'PROPOSAL', sub: 'LLM Generates', cls: 'bg-tertiary/10 border-tertiary/30 text-tertiary', icon: 'edit_document' },
            { label: 'SAFETY BOUNDARY', sub: 'Deterministic Gate', cls: 'bg-primary/10 border-primary/30 text-primary', icon: 'health_and_safety' },
            { label: 'POLICY ENGINE', sub: 'Deterministic Gate', cls: 'bg-primary/10 border-primary/30 text-primary', icon: 'policy' },
            { label: 'TOOL AUTHORIZATION', sub: 'HMAC Signed', cls: 'bg-primary/10 border-primary/30 text-primary', icon: 'key' },
            { label: 'SANDBOX', sub: 'Container Isolation', cls: 'bg-primary/10 border-primary/30 text-primary', icon: 'developer_board' },
            { label: 'TELEMETRY', sub: 'Normalized Events', cls: 'bg-primary/10 border-primary/30 text-primary', icon: 'biotech' },
            { label: 'DETECTION', sub: 'Sigma Rules', cls: 'bg-secondary/10 border-secondary/30 text-secondary', icon: 'radar' },
          ].map((layer, i) => (
            <div key={i}>
              <div
                className={`px-3 py-2 border rounded flex items-center justify-between ${layer.cls}`}
              >
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-[16px]">{layer.icon}</span>
                  <span>{layer.label}</span>
                </div>
                <span className="text-data-mono-sm font-data-mono-sm opacity-70">{layer.sub}</span>
              </div>
              {i < 7 && (
                <div className="text-center text-outline py-1">
                  <span className="material-symbols-outlined text-[16px]">arrow_downward</span>
                </div>
              )}
            </div>
          ))}
        </div>
        <div className="mt-stack-md text-data-mono-sm font-data-mono-sm text-outline border-t border-white/5 pt-stack-sm">
          "LLM proposes, deterministic infrastructure disposes."
        </div>
      </div>

      {!data?.controls.length ? (
        <EmptyState
          title="No security controls registered"
          description="Add controls to your digital twin to track coverage"
        />
      ) : (
        <div className="soc-card rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/10">
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">NAME</th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">TYPE</th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">STATUS</th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">VENDOR</th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">TECHNIQUES</th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-3 px-stack-md">VALIDATION</th>
                </tr>
              </thead>
              <tbody>
                {data.controls.map((c) => (
                  <tr key={c.id} className="border-b border-white/5 hover:bg-white/[0.02]">
                    <td className="py-3 px-stack-md text-on-surface text-body-base">{c.name}</td>
                    <td className="py-3 px-stack-md text-data-mono font-data-mono text-on-surface-variant">
                      {c.control_type}
                    </td>
                    <td className="py-3 px-stack-md">
                      <StatusBadge status={c.enabled ? 'ACTIVE' : 'DRAFT'} />
                    </td>
                    <td className="py-3 px-stack-md text-on-surface-variant text-body-base">
                      {c.vendor || '—'}
                    </td>
                    <td className="py-3 px-stack-md text-data-mono font-data-mono text-primary">
                      {c.technique_ids.length}
                    </td>
                    <td className="py-3 px-stack-md">
                      <StatusBadge status={c.validation_status || 'PENDING'} />
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
