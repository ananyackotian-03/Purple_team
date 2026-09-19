import { useParams, Link } from 'react-router-dom'
import { useExperiment, useHealth } from '@/hooks/useApi'
import { LoadingSpinner, ErrorMessage, StatusBadge, RiskBadge } from '@/components/Shared'

function Panel({
  title,
  color = 'text-on-surface-variant',
  children,
}: {
  title: string
  color?: string
  children: React.ReactNode
}) {
  return (
    <div className="soc-card rounded-lg">
      <div className="soc-card-header p-stack-sm px-stack-md">
        <span className={`text-label-caps font-label-caps ${color}`}>{title}</span>
      </div>
      <div className="p-stack-md space-y-3">{children}</div>
    </div>
  )
}

function Row({
  label,
  value,
  mono = false,
  color,
}: {
  label: string
  value: React.ReactNode
  mono?: boolean
  color?: string
}) {
  return (
    <div className="flex justify-between items-center border-b border-white/5 pb-2 last:border-0 last:pb-0">
      <span className="text-label-caps font-label-caps text-outline">{label}</span>
      <span
        className={`${
          mono ? 'text-data-mono font-data-mono' : 'text-body-base'
        } ${color || 'text-on-surface'}`}
      >
        {value}
      </span>
    </div>
  )
}

export default function ExperimentDetail() {
  const { id } = useParams<{ id: string }>()
  const { data, isLoading, error, refetch } = useExperiment(id)
  const { data: health } = useHealth()

  if (isLoading) return <LoadingSpinner />
  if (error) return <ErrorMessage message={String(error)} onRetry={refetch} />
  if (!data) return null

  const { experiment: exp, lifecycle, red_agent, telemetry, detection, purple_evaluation } = data

  const stageIcons: Record<string, string> = {
    red_agent: 'psychology',
    safety_boundary: 'health_and_safety',
    policy_engine: 'policy',
    tool_authorization: 'key',
    sandbox: 'developer_board',
    execution: 'play_arrow',
    telemetry: 'biotech',
    detection: 'radar',
    purple_evaluation: 'fact_check',
    gap_identification: 'search_off',
    defense_proposal: 'edit_document',
    defense_test: 'science',
    retest: 'refresh',
  }

  return (
    <div>
      <div className="mb-stack-lg">
        <div className="flex items-center gap-2 text-on-surface-variant text-body-base mb-2">
          <Link to="/experiments" className="hover:text-on-surface transition-colors">
            Experiments
          </Link>
          <span className="material-symbols-outlined text-[16px]">chevron_right</span>
          <span className="text-on-surface">{exp.title || exp.id.slice(0, 8)}</span>
        </div>
      </div>

      <div className="soc-card rounded-lg p-stack-md mb-stack-lg">
        <div className="flex justify-between items-start">
          <div>
            <h2 className="text-headline-md font-headline-md text-on-surface">
              {exp.title || 'Experiment'}
            </h2>
            {exp.strategy_description && (
              <p className="text-on-surface-variant text-body-base mt-2">
                {exp.strategy_description}
              </p>
            )}
            <div className="flex items-center gap-3 mt-3">
              <StatusBadge status={exp.status} />
              {exp.risk_level && <RiskBadge level={exp.risk_level} />}
              <span className="text-data-mono-sm font-data-mono-sm text-outline">
                {exp.technique_ids?.join(', ') || 'No techniques'}
              </span>
            </div>
          </div>
          <div className="text-right text-data-mono-sm font-data-mono-sm text-outline">
            <div>{exp.id.slice(0, 8)}</div>
            {exp.created_at && <div>{new Date(exp.created_at).toLocaleDateString()}</div>}
          </div>
        </div>
      </div>

      {/* Lifecycle Visualization — horizontal pipeline */}
      {lifecycle.length > 0 && (
        <div className="soc-card rounded-lg p-stack-md mb-stack-lg">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
            EXPERIMENT LIFECYCLE
          </p>
          <div className="relative pt-2 pb-8">
            <div className="absolute top-4 left-0 w-full progress-line z-0" />
            <div className="flex justify-between relative z-10 w-full overflow-x-auto">
              {lifecycle.map((stage, i) => {
                const isCompleted = stage.status === 'completed'
                const isFailed = stage.status === 'failed'
                const isRunning = stage.status === 'running'
                return (
                  <div key={i} className="flex flex-col items-center min-w-[70px]">
                    <div
                      className={`w-10 h-10 rounded-full border flex items-center justify-center mb-2 ${
                        isCompleted
                          ? 'bg-secondary-container/20 border-secondary shadow-success-glow'
                          : isFailed
                          ? 'bg-error-container border-error'
                          : isRunning
                          ? 'bg-primary-container/20 border-primary shadow-active-glow'
                          : 'bg-surface-variant border-outline'
                      }`}
                    >
                      <span
                        className={`material-symbols-outlined text-[18px] ${
                          isCompleted
                            ? 'text-secondary'
                            : isFailed
                            ? 'text-error'
                            : isRunning
                            ? 'text-primary'
                            : 'text-outline'
                        }`}
                      >
                        {stageIcons[stage.stage] || (isCompleted ? 'check' : isFailed ? 'close' : isRunning ? 'hourglass_top' : 'circle')}
                      </span>
                    </div>
                    <span className="text-label-caps font-label-caps text-outline text-center w-16 text-[10px]">
                      {stage.label}
                    </span>
                    {stage.is_security_decision && (
                      <span className="text-primary text-[9px] font-data-mono-sm bg-primary/10 px-1 py-0.5 rounded mt-1">
                        DETERMINISTIC
                      </span>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-stack-md">
        <div className="lg:col-span-2 space-y-3">
          {/* Detailed Lifecycle Stages */}
          <Panel title="LIFECYCLE DETAILS">
            <div className="space-y-4">
              {lifecycle.map((stage, i) => (
                <div key={i} className="flex items-start gap-3">
                  <div className="flex flex-col items-center">
                    <div
                      className={`w-8 h-8 rounded-full border flex items-center justify-center ${
                        stage.status === 'completed'
                          ? 'bg-secondary-container/20 border-secondary'
                          : stage.status === 'failed'
                          ? 'bg-error-container border-error'
                          : stage.status === 'running'
                          ? 'bg-primary-container/20 border-primary'
                          : 'bg-surface-variant border-outline'
                      }`}
                    >
                      <span
                        className={`material-symbols-outlined text-[16px] ${
                          stage.status === 'completed'
                            ? 'text-secondary'
                            : stage.status === 'failed'
                            ? 'text-error'
                            : stage.status === 'running'
                            ? 'text-primary'
                            : 'text-outline'
                        }`}
                      >
                        {stage.status === 'completed'
                          ? 'check'
                          : stage.status === 'failed'
                          ? 'close'
                          : stage.status === 'running'
                          ? 'hourglass_top'
                          : 'circle'}
                      </span>
                    </div>
                    {i < lifecycle.length - 1 && (
                      <div className="w-px h-8 bg-outline-variant mt-1" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-on-surface font-medium text-body-base">
                        {stage.label}
                      </span>
                      {stage.is_security_decision && (
                        <span className="text-primary text-data-mono-sm font-data-mono-sm bg-primary/10 px-2 py-0.5 rounded">
                          DETERMINISTIC
                        </span>
                      )}
                    </div>
                    {stage.result && (
                      <span className="text-on-surface-variant text-data-mono-sm font-data-mono-sm">
                        {stage.result}
                      </span>
                    )}
                    {stage.detail && (
                      <p className="text-outline text-data-mono-sm font-data-mono-sm mt-1 line-clamp-2">
                        {stage.detail}
                      </p>
                    )}
                    {stage.timestamp && (
                      <span className="text-outline text-data-mono-sm font-data-mono-sm">
                        {new Date(stage.timestamp).toLocaleString()}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </Panel>

          {telemetry && telemetry.length > 0 && (
            <Panel title="TELEMETRY">
              <div className="space-y-2">
                {telemetry.slice(0, 10).map((t, i) => (
                  <div key={i} className="flex items-center gap-3 py-2 border-b border-white/5 last:border-0">
                    <span className="text-data-mono-sm font-data-mono-sm text-outline">
                      {String(t.timestamp || t.event_type || t.source || 'event')}
                    </span>
                    <span className="text-data-mono-sm font-data-mono-sm text-primary">
                      {String(t.technique_id || '')}
                    </span>
                    <span className="text-data-mono-sm font-data-mono-sm text-on-surface-variant">
                      {String(t.process_name || t.source || '')}
                    </span>
                    <span className="text-data-mono-sm font-data-mono-sm text-outline truncate max-w-xs">
                      {String(t.command_line || '')}
                    </span>
                  </div>
                ))}
              </div>
            </Panel>
          )}

          {telemetry && telemetry.length === 0 && (
            <Panel title="TELEMETRY">
              <p className="text-on-surface-variant text-body-base text-sm">
                No telemetry events recorded for this experiment. Telemetry is collected during
                experiment execution by the TelemetryCollector pipeline.
              </p>
            </Panel>
          )}
        </div>

        <div className="space-y-3">
          <Panel title="ENVIRONMENT">
            <Row
              label="Docker"
              value={
                health?.docker === 'available' ? (
                  <span className="text-secondary">Online</span>
                ) : (
                  <span className="text-error">Offline</span>
                )
              }
            />
            <Row
              label="LLM"
              value={
                health?.ollama === 'available' ? (
                  <span className="text-secondary">Online</span>
                ) : (
                  <span className="text-outline">Offline</span>
                )
              }
            />
            <Row label="Iterations" value={exp.iterations} mono />
            <Row label="Experiments" value={exp.experiments_count} mono />
            <Row label="LLM Calls" value={exp.llm_calls} mono />
          </Panel>

          {red_agent && (
            <Panel title="LLM PROPOSAL" color="text-tertiary">
              <Row label="State" value={red_agent.state} mono />
              <Row label="Strategy" value={red_agent.proposed_strategy || '—'} />
              <Row label="Risk" value={red_agent.risk_level} mono />
              <Row label="LLM Calls" value={red_agent.llm_calls} mono />
              <div className="text-data-mono-sm font-data-mono-sm text-outline mt-2 border-t border-white/5 pt-2">
                LLM does not have execution authority
              </div>
            </Panel>
          )}

          {detection && (
            <Panel title="DETECTION">
              <Row label="Outcome" value={<StatusBadge status={detection.outcome} />} />
              <Row label="Technique" value={detection.technique_id} mono />
              <Row label="Rule" value={detection.rule_id?.slice(0, 8) || '—'} mono />
              <Row label="Source" value={detection.source || '—'} />
            </Panel>
          )}

          {purple_evaluation && (
            <Panel title="PURPLE EVALUATION">
              <Row
                label="Status"
                value={<StatusBadge status={purple_evaluation.detection_status} />}
              />
              <Row label="Technique" value={purple_evaluation.technique_id} mono />
              <Row
                label="Expected"
                value={purple_evaluation.expected_detection ? 'Yes' : 'No'}
              />
              {purple_evaluation.gap_reason && (
                <Row
                  label="Gap"
                  value={purple_evaluation.gap_reason}
                  color="text-tertiary"
                />
              )}
              {purple_evaluation.matched_rule_ids.length > 0 && (
                <Row
                  label="Rules"
                  value={purple_evaluation.matched_rule_ids.length}
                  mono
                />
              )}
            </Panel>
          )}

          {data.retest && (
            <Panel title="RETEST">
              <Row label="Before" value={<StatusBadge status={data.retest.before_outcome} />} />
              <Row label="After" value={<StatusBadge status={data.retest.after_outcome} />} />
              <Row
                label="Improved"
                value={
                  data.retest.detection_improved ? (
                    <span className="text-secondary">Yes</span>
                  ) : (
                    <span className="text-error">No</span>
                  )
                }
              />
            </Panel>
          )}
        </div>
      </div>
    </div>
  )
}
