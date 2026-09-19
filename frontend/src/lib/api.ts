const API_BASE = '/api'

async function fetchJSON<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(error.detail || `API error ${res.status}`)
  }
  return res.json()
}

// ─── Health ────────────────────────────────────────────────
export interface HealthResponse {
  status: string
  version: string
  database: string
  ollama: string
  docker: string
}

// ─── Dashboard ─────────────────────────────────────────────
export interface DashboardMetrics {
  total_objectives: number
  total_experiments: number
  active_experiments: number
  completed_experiments: number
  total_detections: number
  detection_gaps: number
  coverage_pct: number
  total_retests: number
  retests_improved: number
  system_status: string
  recent_activities: Array<{
    type: string
    title: string
    objective: string
    risk_level: string
    created_by: string
    timestamp: string
  }>
}

// ─── Objectives ────────────────────────────────────────────
export interface ObjectiveResponse {
  id: string
  organization_id: string
  title: string
  description: string | null
  target_category: string
  default_risk_level: string
  created_at: string
  experiment_count: number
}

export interface ObjectiveDetail {
  objective: ObjectiveResponse
  experiments: Array<{
    id: string
    title: string
    strategy_description: string
    proposed_risk_level: string
    created_by: string
    created_at: string
  }>
}

// ─── Experiments ───────────────────────────────────────────
export interface LifecycleStage {
  stage: string
  status: string
  label: string
  timestamp: string | null
  result: string | null
  detail: string | null
  is_security_decision: boolean
}

export interface ExperimentDetail {
  experiment: {
    id: string
    objective_id: string
    scenario_id: string | null
    status: string
    title: string | null
    strategy_description: string | null
    technique_ids: string[]
    risk_level: string | null
    created_by: string | null
    created_at: string | null
    iterations: number
    experiments_count: number
    llm_calls: number
    terminated_reason: string | null
  }
  lifecycle: LifecycleStage[]
  red_agent: {
    state: string
    iterations: number
    experiments_count: number
    llm_calls: number
    proposed_strategy: string
    risk_level: string
  } | null
  telemetry: Array<Record<string, unknown>>
  detection: {
    detection_id: string
    technique_id: string
    rule_id: string
    matched: boolean
    outcome: string
    timestamp: string
    source: string
  } | null
  purple_evaluation: {
    evaluation_id: string
    experiment_id: string
    execution_id: string | null
    organization_id: string
    technique_id: string
    detection_status: string
    matched_rule_ids: string[]
    evidence_event_ids: string[]
    expected_detection: boolean
    gap_reason: string | null
    detection_latency_ms: number | null
    evaluated_at: string
  } | null
  retest: {
    id: string
    before_outcome: string
    after_outcome: string
    detection_improved: boolean
    validated_rule_ids: string[]
    evaluated_at: string
  } | null
}

export interface ExperimentListResponse {
  id: string
  organization_id: string
  objective_id: string | null
  title: string | null
  strategy_description: string | null
  risk_level: string | null
  status: string | null
  created_by: string | null
  created_at: string | null
}

// ─── Coverage ──────────────────────────────────────────────
export interface CoverageReport {
  report_id: string
  organization_id: string
  total_experiments: number
  detected_experiments: number
  missed_experiments: number
  gap_experiments: number
  coverage_pct: number
  technique_coverage: Record<string, boolean>
  generated_at: string
}

// ─── Retests ───────────────────────────────────────────────
export interface RetestResponse {
  id: string
  organization_id: string | null
  exercise_id: string | null
  scenario_id: string | null
  before_outcome: string
  after_outcome: string
  detection_improved: boolean
  validated_rule_ids: string[]
  evaluated_at: string
}

// ─── Evidence ──────────────────────────────────────────────
export interface EvidenceTrace {
  objective: Record<string, unknown> | null
  experiment: Record<string, unknown> | null
  execution: Record<string, unknown> | null
  telemetry: Array<Record<string, unknown>>
  detection: Record<string, unknown> | null
  purple_evaluation: Record<string, unknown> | null
  retest: Record<string, unknown> | null
}

// ─── Organizations ─────────────────────────────────────────
export interface OrganizationResponse {
  id: string
  name: string
  description: string | null
  defensive_state: string
  created_at: string | null
}

export interface OrganizationStateResponse {
  organization_id: string
  name: string
  experiments_performed: number
  techniques_tested: string[]
  detected_experiments: number
  missed_experiments: number
  detection_gap_experiments: number
  mitigated_gaps: number
  unresolved_gaps: number
  coverage_pct: number
  defensive_improvements_attempted: number
  successful_improvements: number
  computed_at: string
}

// ─── Detection Gaps ────────────────────────────────────────
export interface DetectionGapResponse {
  id: string
  organization_id: string
  scenario_id: string | null
  technique_id: string
  original_outcome: string
  remediation_status: string
  reason: string
  created_at: string | null
}

// ─── Defensive Proposals ───────────────────────────────────
export interface DefensiveProposalResponse {
  id: string
  organization_id: string
  finding_id: string | null
  scenario_id: string | null
  root_cause: string
  proposed_remediation: string
  expected_security_effect: string
  status: string
  created_at: string | null
}

// ─── Immune Memory ─────────────────────────────────────────
export interface ImmuneMemoryResponse {
  organization_id: string
  previous_experiments: number
  techniques_tested: string[]
  detection_outcomes: Record<string, number>
  detection_gaps: Array<Record<string, unknown>>
  retest_results: Array<Record<string, unknown>>
  coverage_pct: number
  mitigated_gaps: number
  unresolved_gaps: number
  successful_improvements: number
  failed_improvements: number
  defensive_proposals: Array<Record<string, unknown>>
}

// ─── Next Experiment (Adaptive) ────────────────────────────
export interface NextExperimentResponse {
  organization_id: string
  selected_strategy: string | null
  selected_techniques: string[]
  selection_method: string
  score: number
  reason: string
  validation_passed: boolean
  validation_rejection: string | null
  used_llm: boolean
  used_fallback: boolean
  candidates_count: number
  evidence_references: string[]
  selected_at: string | null
}

// ─── Immune Cycle ──────────────────────────────────────────
export interface ImmuneCycleStatusResponse {
  organization_id: string
  current_state: string
  last_cycle_at: string | null
  total_cycles: number
  mitigated_count: number
  unresolved_count: number
  next_experiment: Record<string, unknown> | null
}

// ─── Digital Twin ──────────────────────────────────────────
export interface AssetResponse {
  id: string
  organization_id: string
  name: string
  asset_type: string
  description: string
  operating_system: string | null
  software_version: string | null
  network_segment: string | null
  ip_address: string | null
  risk_level: string
  is_active: boolean
  last_scanned_at: string | null
  tags: string[]
  metadata_json: Record<string, unknown>
  created_at: string
  updated_at: string
}

export interface ServiceResponse {
  id: string
  organization_id: string
  asset_id: string
  name: string
  service_type: string
  description: string
  port: number | null
  protocol: string | null
  version: string | null
  technology_stack: string[]
  risk_level: string
  is_internet_facing: boolean
  has_authentication: boolean
  has_encryption: boolean
  last_tested_at: string | null
  detection_rules_count: number
  coverage_pct: number
  metadata_json: Record<string, unknown>
  created_at: string
  updated_at: string
}

export interface SecurityControlResponse {
  id: string
  organization_id: string
  name: string
  control_type: string
  description: string
  enabled: boolean
  version: string | null
  vendor: string | null
  technique_ids: string[]
  coverage_description: string
  last_validated_at: string | null
  validation_status: string | null
  metadata_json: Record<string, unknown>
  created_at: string
  updated_at: string
}

export interface DetectionCoverageResponse {
  id: string
  organization_id: string
  asset_id: string | null
  service_id: string | null
  technique_id: string
  is_detected: boolean
  detection_method: string | null
  rule_ids: string[]
  last_experiment_id: string | null
  last_detected_at: string | null
  confidence_score: number
  metadata_json: Record<string, unknown>
  created_at: string
  updated_at: string
}

export interface DetectionCoverageListResponse {
  coverage: DetectionCoverageResponse[]
  total: number
  detected_count: number
  not_detected_count: number
  overall_coverage_pct: number
}

export interface SecurityPostureResponse {
  id: string
  organization_id: string
  total_assets: number
  active_assets: number
  total_services: number
  internet_facing_services: number
  total_security_controls: number
  enabled_controls: number
  total_techniques_tested: number
  techniques_detected: number
  detection_coverage_pct: number
  high_risk_assets: number
  critical_risk_assets: number
  unresolved_gaps: number
  total_experiments: number
  successful_experiments: number
  failed_experiments: number
  snapshot_date: string
  computed_from_evidence: boolean
}

export interface DigitalTwinSummaryResponse {
  organization_id: string
  organization_name: string
  total_assets: number
  assets_by_type: Record<string, number>
  total_services: number
  services_by_type: Record<string, number>
  internet_facing_services: number
  total_controls: number
  enabled_controls: number
  controls_by_type: Record<string, number>
  total_techniques_tested: number
  techniques_detected: number
  detection_coverage_pct: number
  high_risk_assets: number
  critical_risk_assets: number
  unresolved_gaps: number
  last_experiment_at: string | null
  last_posture_snapshot_at: string | null
  computed_at: string
}

export interface AssetWithRelationsResponse {
  asset: AssetResponse
  services: ServiceResponse[]
  controls: SecurityControlResponse[]
}

// ─── API Client ────────────────────────────────────────────
export const api = {
  getHealth: () => fetchJSON<HealthResponse>('/health'),
  getDashboard: () => fetchJSON<DashboardMetrics>('/dashboard'),

  getObjectives: () => fetchJSON<ObjectiveResponse[]>('/objectives'),
  getObjective: (id: string) => fetchJSON<ObjectiveDetail>(`/objectives/${id}`),
  createObjective: (data: {
    title: string
    description: string
    target_category?: string
    default_risk_level?: string
  }) =>
    fetchJSON<ObjectiveResponse>('/objectives', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  runExperiment: (objectiveId: string) =>
    fetchJSON<{ status: string; objective_id: string }>(
      `/objectives/${objectiveId}/run`,
      { method: 'POST' }
    ),

  getExperiments: (orgId: string) =>
    fetchJSON<ExperimentListResponse[]>(
      `/organizations/${orgId}/experiments`
    ),
  getExperiment: (id: string) =>
    fetchJSON<ExperimentDetail>(`/experiments/${id}`),

  getCoverage: () => fetchJSON<CoverageReport>('/coverage'),

  getRetests: () => fetchJSON<RetestResponse[]>('/retests'),
  getRetest: (experimentId: string) =>
    fetchJSON<RetestResponse>(`/retests/${experimentId}`),

  getEvidenceTrace: (id: string) =>
    fetchJSON<EvidenceTrace>(`/evidence/${id}`),

  getOrganizations: () => fetchJSON<OrganizationResponse[]>('/organizations'),
  createOrganization: (data: { name: string; description?: string }) =>
    fetchJSON<OrganizationResponse>('/organizations', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  getOrganizationState: (orgId: string) =>
    fetchJSON<OrganizationStateResponse>(
      `/organizations/${orgId}/state`
    ),

  getDetectionGaps: (orgId: string) =>
    fetchJSON<DetectionGapResponse[]>(
      `/organizations/${orgId}/detection-gaps`
    ),

  getDefensiveProposals: (orgId: string) =>
    fetchJSON<DefensiveProposalResponse[]>(
      `/organizations/${orgId}/defensive-proposals`
    ),
  createDefensiveProposal: (
    orgId: string,
    data: {
      finding_id: string
      root_cause: string
      proposed_remediation: string
      expected_security_effect?: string
    }
  ) =>
    fetchJSON<DefensiveProposalResponse>(`/organizations/${orgId}/defensive-proposals`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  validateDefensiveProposal: (proposalId: string) =>
    fetchJSON<{
      proposal_id: string
      validation_passed: boolean
      rejection_reason: string | null
      status: string
    }>(`/defensive-proposals/${proposalId}/validate`, { method: 'POST' }),

  getImmuneMemory: (orgId: string) =>
    fetchJSON<ImmuneMemoryResponse>(
      `/organizations/${orgId}/immune-memory`
    ),

  getNextExperiment: (orgId: string) =>
    fetchJSON<NextExperimentResponse>(
      `/organizations/${orgId}/next-experiment`
    ),

  getImmuneCycleStatus: (orgId: string) =>
    fetchJSON<ImmuneCycleStatusResponse>(
      `/organizations/${orgId}/immune-cycle/status`
    ),

  runImmuneCycle: (orgId: string, objectiveId?: string) =>
    fetchJSON<{
      cycle_id: string
      organization_id: string
      final_state: string
      path: string
      evidence: Record<string, unknown>
      next_experiment: Record<string, unknown> | null
    }>(
      `/organizations/${orgId}/immune-cycle/run${objectiveId ? `?objective_id=${objectiveId}` : ''}`,
      { method: 'POST' }
    ),

  getTwinSummary: (orgId: string) =>
    fetchJSON<DigitalTwinSummaryResponse>(
      `/organizations/${orgId}/twin/summary`
    ),
  getTwinAssets: (orgId: string) =>
    fetchJSON<{ assets: AssetResponse[]; total: number }>(
      `/organizations/${orgId}/twin/assets`
    ),
  getTwinServices: (orgId: string) =>
    fetchJSON<{ services: ServiceResponse[]; total: number }>(
      `/organizations/${orgId}/twin/services`
    ),
  getTwinControls: (orgId: string) =>
    fetchJSON<{
      controls: SecurityControlResponse[]
      total: number
    }>(`/organizations/${orgId}/twin/controls`),
  getTwinCoverage: (orgId: string) =>
    fetchJSON<DetectionCoverageListResponse>(
      `/organizations/${orgId}/twin/coverage`
    ),
  computeTwinPosture: (orgId: string) =>
    fetchJSON<SecurityPostureResponse>(
      `/organizations/${orgId}/twin/posture`,
      { method: 'POST' }
    ),
}
