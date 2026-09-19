import { useTwinSummary, useTwinAssets, useTwinServices, useTwinControls, useTwinCoverage, useComputeTwinPosture } from '@/hooks/useApi'
import { LoadingSpinner, ErrorMessage, PageHeader, StatusBadge } from '@/components/Shared'

export default function DigitalTwin() {
  const { data: summary, isLoading: sLoad, error: sErr, refetch: sRef } = useTwinSummary()
  const { data: assets } = useTwinAssets()
  const { data: services } = useTwinServices()
  const { data: controls } = useTwinControls()
  const { data: coverage } = useTwinCoverage()
  const postureMut = useComputeTwinPosture()

  if (sLoad) return <LoadingSpinner />
  if (sErr) return <ErrorMessage message={String(sErr)} onRetry={sRef} />

  const s = summary!

  return (
    <div>
      <div className="flex justify-between items-start mb-stack-lg">
        <div>
          <PageHeader
            title="DIGITAL TWIN"
            subtitle={`Security model for ${s.organization_name}`}
          />
        </div>
        <button
          onClick={() => postureMut.mutate()}
          disabled={postureMut.isPending}
          className="px-4 py-2 bg-primary/10 border border-primary/30 text-primary hover:bg-primary/20 transition-colors rounded flex items-center text-label-caps font-label-caps disabled:opacity-50"
        >
          <span className="material-symbols-outlined mr-1 text-[18px]">assessment</span>
          {postureMut.isPending ? 'COMPUTING...' : 'COMPUTE POSTURE'}
        </button>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-stack-md mb-stack-lg">
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">ASSETS</p>
          <p className="text-headline-md font-headline-md text-on-surface">{s.total_assets}</p>
        </div>
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">SERVICES</p>
          <p className="text-headline-md font-headline-md text-on-surface">{s.total_services}</p>
          <p className="text-data-mono-sm font-data-mono-sm text-tertiary mt-1">
            {s.internet_facing_services} internet-facing
          </p>
        </div>
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">CONTROLS</p>
          <p className="text-headline-md font-headline-md text-on-surface">{s.total_controls}</p>
          <p className="text-data-mono-sm font-data-mono-sm text-secondary mt-1">
            {s.enabled_controls} enabled
          </p>
        </div>
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">COVERAGE</p>
          <p className="text-headline-md font-headline-md text-secondary">
            {s.detection_coverage_pct.toFixed(1)}%
          </p>
          <p className="text-data-mono-sm font-data-mono-sm text-outline mt-1">
            {s.techniques_detected}/{s.total_techniques_tested} techniques
          </p>
        </div>
      </div>

      {s.high_risk_assets > 0 && (
        <div className="soc-card rounded-lg p-stack-md mb-stack-lg border-error/30 border">
          <div className="flex items-center">
            <span className="material-symbols-outlined text-error mr-2">warning</span>
            <span className="text-on-surface font-medium">
              {s.high_risk_assets} high-risk asset{s.high_risk_assets !== 1 ? 's' : ''}
              {s.critical_risk_assets > 0 &&
                ` (${s.critical_risk_assets} critical)`}
            </span>
          </div>
        </div>
      )}

      {/* Detection Coverage Visualization */}
      {coverage && coverage.total > 0 && (
        <div className="soc-card rounded-lg p-stack-md mb-stack-lg">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
            DETECTION COVERAGE
          </p>
          <div className="w-full bg-surface-container-high rounded-full h-3 mb-2">
            <div
              className="bg-secondary h-3 rounded-full transition-all duration-500"
              style={{ width: `${coverage.overall_coverage_pct}%` }}
            />
          </div>
          <div className="flex justify-between text-data-mono-sm font-data-mono-sm text-outline">
            <span>{coverage.detected_count} detected</span>
            <span>{coverage.not_detected_count} not detected</span>
            <span>{coverage.overall_coverage_pct.toFixed(1)}%</span>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-stack-md mb-stack-lg">
        {Object.keys(s.assets_by_type).length > 0 && (
          <div className="soc-card rounded-lg p-stack-md">
            <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
              ASSETS BY TYPE
            </p>
            <div className="space-y-2">
              {Object.entries(s.assets_by_type).map(([type, count]) => (
                <div key={type} className="flex justify-between items-center">
                  <span className="text-on-surface-variant text-body-base">{type}</span>
                  <span className="text-data-mono font-data-mono text-on-surface">{count}</span>
                </div>
              ))}
            </div>
          </div>
        )}
        {Object.keys(s.services_by_type).length > 0 && (
          <div className="soc-card rounded-lg p-stack-md">
            <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
              SERVICES BY TYPE
            </p>
            <div className="space-y-2">
              {Object.entries(s.services_by_type).map(([type, count]) => (
                <div key={type} className="flex justify-between items-center">
                  <span className="text-on-surface-variant text-body-base">{type}</span>
                  <span className="text-data-mono font-data-mono text-on-surface">{count}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {controls && controls.controls.length > 0 && (
        <div className="soc-card rounded-lg p-stack-md mb-stack-lg">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-md">
            SECURITY CONTROLS
          </p>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/10">
                  <th className="text-left text-label-caps font-label-caps text-outline py-2 px-3">NAME</th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-2 px-3">TYPE</th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-2 px-3">STATUS</th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-2 px-3">TECHNIQUES</th>
                </tr>
              </thead>
              <tbody>
                {controls.controls.map((c) => (
                  <tr key={c.id} className="border-b border-white/5 hover:bg-white/[0.02]">
                    <td className="py-2 px-3 text-on-surface text-body-base">{c.name}</td>
                    <td className="py-2 px-3 text-on-surface-variant text-data-mono font-data-mono">{c.control_type}</td>
                    <td className="py-2 px-3">
                      <StatusBadge status={c.enabled ? 'ACTIVE' : 'DRAFT'} />
                    </td>
                    <td className="py-2 px-3 text-data-mono font-data-mono text-on-surface-variant">
                      {c.technique_ids.length}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {assets && assets.assets.length > 0 && (
        <div className="soc-card rounded-lg p-stack-md mb-stack-lg">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-md">ASSETS</p>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/10">
                  <th className="text-left text-label-caps font-label-caps text-outline py-2 px-3">NAME</th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-2 px-3">TYPE</th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-2 px-3">RISK</th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-2 px-3">OS</th>
                </tr>
              </thead>
              <tbody>
                {assets.assets.map((a) => (
                  <tr key={a.id} className="border-b border-white/5 hover:bg-white/[0.02]">
                    <td className="py-2 px-3 text-on-surface text-body-base">{a.name}</td>
                    <td className="py-2 px-3 text-on-surface-variant text-data-mono font-data-mono">{a.asset_type}</td>
                    <td className="py-2 px-3">
                      <StatusBadge status={a.risk_level} />
                    </td>
                    <td className="py-2 px-3 text-on-surface-variant text-data-mono font-data-mono">
                      {a.operating_system || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {services && services.services.length > 0 && (
        <div className="soc-card rounded-lg p-stack-md">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-md">SERVICES</p>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/10">
                  <th className="text-left text-label-caps font-label-caps text-outline py-2 px-3">NAME</th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-2 px-3">TYPE</th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-2 px-3">PORT</th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-2 px-3">RISK</th>
                  <th className="text-left text-label-caps font-label-caps text-outline py-2 px-3">INTERNET</th>
                </tr>
              </thead>
              <tbody>
                {services.services.map((sv) => (
                  <tr key={sv.id} className="border-b border-white/5 hover:bg-white/[0.02]">
                    <td className="py-2 px-3 text-on-surface text-body-base">{sv.name}</td>
                    <td className="py-2 px-3 text-on-surface-variant text-data-mono font-data-mono">{sv.service_type}</td>
                    <td className="py-2 px-3 text-on-surface-variant text-data-mono font-data-mono">{sv.port || '—'}</td>
                    <td className="py-2 px-3">
                      <StatusBadge status={sv.risk_level} />
                    </td>
                    <td className="py-2 px-3">
                      {sv.is_internet_facing ? (
                        <span className="text-tertiary">Yes</span>
                      ) : (
                        <span className="text-outline">No</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {(!assets?.assets.length && !services?.services.length && !controls?.controls.length) && (
        <div className="soc-card rounded-lg p-stack-lg text-center">
          <span className="material-symbols-outlined text-outline text-[48px] mb-3">memory</span>
          <p className="text-on-surface font-medium">No digital twin data</p>
          <p className="text-on-surface-variant text-body-base mt-1">
            Register assets, services, and controls to build your digital twin
          </p>
        </div>
      )}
    </div>
  )
}
