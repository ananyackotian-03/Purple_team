import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useObjectives, useCreateObjective } from '@/hooks/useApi'
import { LoadingSpinner, ErrorMessage, RiskBadge, EmptyState } from '@/components/Shared'

export default function Objectives() {
  const { data, isLoading, error, refetch } = useObjectives()
  const createMut = useCreateObjective()
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({ title: '', description: '', risk_level: 'MEDIUM' })

  if (isLoading) return <LoadingSpinner />
  if (error) return <ErrorMessage message={String(error)} onRetry={refetch} />

  return (
    <div>
      <div className="flex justify-between items-start mb-stack-lg">
        <div>
          <h2 className="text-headline-md font-headline-md text-on-surface">
            SECURITY OBJECTIVES
          </h2>
          <p className="text-on-surface-variant text-body-base mt-2">
            Define and manage security validation objectives
          </p>
        </div>
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="px-4 py-2 bg-primary text-on-primary hover:bg-primary/90 transition-colors rounded flex items-center text-label-caps font-label-caps"
        >
          <span className="material-symbols-outlined mr-1 text-[18px]">add</span>
          NEW OBJECTIVE
        </button>
      </div>

      {showCreate && (
        <div className="soc-card rounded-lg p-stack-md mb-stack-lg border-primary/30 border">
          <p className="text-label-caps font-label-caps text-on-surface-variant mb-stack-sm">
            CREATE OBJECTIVE
          </p>
          <div className="space-y-3">
            <input
              type="text"
              placeholder="Title"
              value={form.title}
              onChange={(e) => setForm({ ...form, title: e.target.value })}
              className="w-full px-3 py-2 bg-black/30 border border-white/10 rounded text-on-surface placeholder-outline focus:border-primary focus:shadow-active-glow outline-none transition-all text-body-base"
            />
            <textarea
              placeholder="Description"
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
              className="w-full px-3 py-2 bg-black/30 border border-white/10 rounded text-on-surface placeholder-outline focus:border-primary focus:shadow-active-glow outline-none transition-all text-body-base h-20 resize-none"
            />
            <div className="flex items-center gap-3">
              <select
                value={form.risk_level}
                onChange={(e) => setForm({ ...form, risk_level: e.target.value })}
                className="px-3 py-2 bg-black/30 border border-white/10 rounded text-on-surface focus:border-primary outline-none text-body-base"
              >
                <option value="LOW">LOW</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="HIGH">HIGH</option>
                <option value="CRITICAL">CRITICAL</option>
              </select>
              <button
                onClick={() => {
                  if (!form.title.trim()) return
                  createMut.mutate(
                    { title: form.title, description: form.description, default_risk_level: form.risk_level },
                    { onSuccess: () => { setShowCreate(false); setForm({ title: '', description: '', risk_level: 'MEDIUM' }) } }
                  )
                }}
                disabled={!form.title.trim() || createMut.isPending}
                className="px-4 py-2 bg-primary text-on-primary hover:bg-primary/90 transition-colors rounded text-label-caps font-label-caps disabled:opacity-50"
              >
                {createMut.isPending ? 'CREATING...' : 'CREATE'}
              </button>
              <button
                onClick={() => setShowCreate(false)}
                className="px-4 py-2 border border-white/10 text-on-surface-variant hover:bg-surface-container-high transition-colors rounded text-label-caps font-label-caps"
              >
                CANCEL
              </button>
            </div>
          </div>
        </div>
      )}

      {!data?.length ? (
        <EmptyState title="No objectives" description="Create your first security objective to begin" />
      ) : (
        <div className="space-y-3">
          {data.map((o) => (
            <Link
              key={o.id}
              to={`/objectives/${o.id}`}
              className="soc-card rounded-lg p-stack-md block hover:bg-surface-container-high transition-all"
            >
              <div className="flex justify-between items-start">
                <div className="flex-1 min-w-0">
                  <h3 className="text-on-surface font-medium text-body-base">{o.title}</h3>
                  {o.description && (
                    <p className="text-on-surface-variant text-body-base mt-1 line-clamp-2">
                      {o.description}
                    </p>
                  )}
                  <div className="flex items-center gap-3 mt-2">
                    <span className="text-data-mono-sm font-data-mono-sm text-outline">
                      {o.target_category}
                    </span>
                    <span className="text-data-mono-sm font-data-mono-sm text-outline">
                      {o.experiment_count} experiment{o.experiment_count !== 1 ? 's' : ''}
                    </span>
                  </div>
                </div>
                <RiskBadge level={o.default_risk_level} />
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  )
}
