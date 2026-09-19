import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'

const DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000001'

export function useHealth() {
  return useQuery({
    queryKey: ['health'],
    queryFn: api.getHealth,
    refetchInterval: 30_000,
  })
}

export function useDashboard() {
  return useQuery({ queryKey: ['dashboard'], queryFn: api.getDashboard })
}

export function useObjectives() {
  return useQuery({ queryKey: ['objectives'], queryFn: api.getObjectives })
}

export function useObjective(id: string | undefined, opts?: object) {
  return useQuery({
    queryKey: ['objective', id],
    queryFn: () => api.getObjective(id!),
    enabled: !!id,
    ...opts,
  })
}

export function useCreateObjective() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: api.createObjective,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['objectives'] }),
  })
}

export function useRunExperiment() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: api.runExperiment,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['objectives'] })
      qc.invalidateQueries({ queryKey: ['experiments'] })
      qc.invalidateQueries({ queryKey: ['dashboard'] })
      qc.invalidateQueries({ queryKey: ['coverage'] })
    },
  })
}

export function useExperiments(orgId: string = DEFAULT_ORG_ID) {
  return useQuery({
    queryKey: ['experiments', orgId],
    queryFn: () => api.getExperiments(orgId),
  })
}

export function useExperiment(id: string | undefined, opts?: object) {
  return useQuery({
    queryKey: ['experiments', id],
    queryFn: () => api.getExperiment(id!),
    enabled: !!id,
    ...opts,
  })
}

export function useCoverage() {
  return useQuery({ queryKey: ['coverage'], queryFn: api.getCoverage })
}

export function useRetests() {
  return useQuery({ queryKey: ['retests'], queryFn: api.getRetests })
}

export function useRetest(experimentId: string | undefined) {
  return useQuery({
    queryKey: ['retest', experimentId],
    queryFn: () => api.getRetest(experimentId!),
    enabled: !!experimentId,
    retry: false,
  })
}

export function useEvidenceTrace(id: string | undefined) {
  return useQuery({
    queryKey: ['evidence', id],
    queryFn: () => api.getEvidenceTrace(id!),
    enabled: !!id,
  })
}

export function useOrganizations() {
  return useQuery({ queryKey: ['organizations'], queryFn: api.getOrganizations })
}

export function useOrganizationState(orgId: string = DEFAULT_ORG_ID) {
  return useQuery({
    queryKey: ['org-state', orgId],
    queryFn: () => api.getOrganizationState(orgId),
  })
}

export function useDetectionGaps(orgId: string = DEFAULT_ORG_ID) {
  return useQuery({
    queryKey: ['detection-gaps', orgId],
    queryFn: () => api.getDetectionGaps(orgId),
  })
}

export function useDefensiveProposals(orgId: string = DEFAULT_ORG_ID) {
  return useQuery({
    queryKey: ['defensive-proposals', orgId],
    queryFn: () => api.getDefensiveProposals(orgId),
  })
}

export function useImmuneMemory(orgId: string = DEFAULT_ORG_ID) {
  return useQuery({
    queryKey: ['immune-memory', orgId],
    queryFn: () => api.getImmuneMemory(orgId),
  })
}

export function useNextExperiment(orgId: string = DEFAULT_ORG_ID) {
  return useQuery({
    queryKey: ['next-experiment', orgId],
    queryFn: () => api.getNextExperiment(orgId),
  })
}

export function useImmuneCycleStatus(orgId: string = DEFAULT_ORG_ID) {
  return useQuery({
    queryKey: ['immune-cycle', orgId],
    queryFn: () => api.getImmuneCycleStatus(orgId),
  })
}

export function useTwinSummary(orgId: string = DEFAULT_ORG_ID) {
  return useQuery({
    queryKey: ['twin-summary', orgId],
    queryFn: () => api.getTwinSummary(orgId),
  })
}

export function useTwinAssets(orgId: string = DEFAULT_ORG_ID) {
  return useQuery({
    queryKey: ['twin-assets', orgId],
    queryFn: () => api.getTwinAssets(orgId),
  })
}

export function useTwinServices(orgId: string = DEFAULT_ORG_ID) {
  return useQuery({
    queryKey: ['twin-services', orgId],
    queryFn: () => api.getTwinServices(orgId),
  })
}

export function useTwinControls(orgId: string = DEFAULT_ORG_ID) {
  return useQuery({
    queryKey: ['twin-controls', orgId],
    queryFn: () => api.getTwinControls(orgId),
  })
}

export function useTwinCoverage(orgId: string = DEFAULT_ORG_ID) {
  return useQuery({
    queryKey: ['twin-coverage', orgId],
    queryFn: () => api.getTwinCoverage(orgId),
  })
}

export function useComputeTwinPosture(orgId: string = DEFAULT_ORG_ID) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => api.computeTwinPosture(orgId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['twin-summary', orgId] }),
  })
}

export function useRunImmuneCycle(orgId: string = DEFAULT_ORG_ID) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (objectiveId?: string) => api.runImmuneCycle(orgId, objectiveId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['immune-cycle', orgId] })
      qc.invalidateQueries({ queryKey: ['next-experiment', orgId] })
      qc.invalidateQueries({ queryKey: ['immune-memory', orgId] })
      qc.invalidateQueries({ queryKey: ['dashboard'] })
      qc.invalidateQueries({ queryKey: ['objectives'] })
      qc.invalidateQueries({ queryKey: ['experiments'] })
    },
  })
}

export function useCreateDefensiveProposal(orgId: string = DEFAULT_ORG_ID) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { finding_id: string; root_cause: string; proposed_remediation: string; expected_security_effect?: string }) =>
      api.createDefensiveProposal(orgId, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['defensive-proposals', orgId] })
      qc.invalidateQueries({ queryKey: ['immune-memory', orgId] })
      qc.invalidateQueries({ queryKey: ['detection-gaps', orgId] })
    },
  })
}

export function useValidateDefensiveProposal(orgId: string = DEFAULT_ORG_ID) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: api.validateDefensiveProposal,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['defensive-proposals', orgId] })
      qc.invalidateQueries({ queryKey: ['immune-memory', orgId] })
      qc.invalidateQueries({ queryKey: ['retests'] })
    },
  })
}
