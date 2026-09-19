import React from 'react'

export function StatusBadge({ status }: { status: string }) {
  const colorMap: Record<string, string> = {
    DETECTED: 'bg-secondary-container/20 border border-secondary text-secondary',
    NOT_DETECTED: 'bg-error-container/20 border border-error text-error',
    DETECTION_GAP: 'bg-tertiary-container/20 border border-tertiary text-tertiary',
    GAP: 'bg-error-container text-on-error',
    VERIFIED: 'bg-secondary-container/20 border border-secondary text-secondary',
    ALLOWED: 'bg-secondary-container/20 border border-secondary text-secondary',
    DENIED: 'bg-error-container/20 border border-error text-error',
    COMPLETED: 'bg-secondary-container/20 border border-secondary text-secondary',
    EXECUTED: 'bg-primary/10 border border-primary/30 text-primary',
    PENDING: 'bg-surface-variant text-on-surface-variant',
    DRAFT: 'bg-surface-variant text-on-surface-variant',
    REJECTED: 'bg-error-container/20 border border-error text-error',
    FAILED: 'bg-error-container/20 border border-error text-error',
    CREATED: 'bg-primary/10 border border-primary/30 text-primary',
    SCHEMA_VALIDATED: 'bg-secondary-container/20 border border-secondary text-secondary',
    MITIGATED: 'bg-secondary-container/20 border border-secondary text-secondary',
    UNRESOLVED: 'bg-tertiary-container/20 border border-tertiary text-tertiary',
    INITIAL: 'bg-surface-variant text-on-surface-variant',
    ACTIVE: 'bg-secondary-container/20 border border-secondary text-secondary',
  }
  const display = status.replace(/_/g, ' ')
  return (
    <span className={`status-pill ${colorMap[status] || 'bg-surface-variant text-on-surface-variant'}`}>
      {display}
    </span>
  )
}

export function RiskBadge({ level }: { level: string }) {
  const colorMap: Record<string, string> = {
    LOW: 'bg-secondary/10 text-secondary border border-secondary/30',
    MEDIUM: 'bg-tertiary/10 text-tertiary border border-tertiary/30',
    HIGH: 'bg-error/10 text-error border border-error/30',
    CRITICAL: 'bg-error-container text-on-error border border-error',
  }
  return (
    <span className={`status-pill ${colorMap[level] || 'bg-surface-variant text-on-surface-variant'}`}>
      {level}
    </span>
  )
}

export function MetricCard({
  label,
  value,
  subtitle,
}: {
  label: string
  value: string | number
  subtitle?: string
}) {
  return (
    <div className="soc-card rounded-lg p-stack-md">
      <p className="text-label-caps font-label-caps text-on-surface-variant mb-1">{label}</p>
      <p className="text-headline-md font-headline-md text-on-surface">{value}</p>
      {subtitle && <p className="text-data-mono-sm font-data-mono-sm text-outline mt-1">{subtitle}</p>}
    </div>
  )
}

export function LoadingSpinner() {
  return (
    <div className="flex items-center justify-center py-12">
      <div className="w-8 h-8 border-2 border-primary-container border-t-transparent rounded-full animate-spin" />
    </div>
  )
}

export function ErrorMessage({
  message,
  onRetry,
}: {
  message: string
  onRetry?: () => void
}) {
  return (
    <div className="soc-card rounded-lg p-stack-md border-error/30 border">
      <div className="flex items-center mb-2">
        <span className="material-symbols-outlined text-error mr-2">error</span>
        <span className="text-on-surface font-medium">Error</span>
      </div>
      <p className="text-on-surface-variant text-body-base mb-3">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="px-4 py-2 bg-primary/10 border border-primary/30 text-primary hover:bg-primary/20 transition-colors rounded text-label-caps font-label-caps"
        >
          RETRY
        </button>
      )}
    </div>
  )
}

export function EmptyState({
  title,
  description,
}: {
  title: string
  description?: string
}) {
  return (
    <div className="soc-card rounded-lg p-stack-lg text-center">
      <span className="material-symbols-outlined text-outline text-[48px] mb-3">inbox</span>
      <p className="text-on-surface font-medium mb-1">{title}</p>
      {description && <p className="text-on-surface-variant text-body-base">{description}</p>}
    </div>
  )
}

export function PageHeader({
  title,
  subtitle,
}: {
  title: string
  subtitle?: string
}) {
  return (
    <div className="mb-stack-lg">
      <h2 className="text-headline-md font-headline-md text-on-surface">{title}</h2>
      {subtitle && <p className="text-on-surface-variant text-body-base mt-2">{subtitle}</p>}
    </div>
  )
}

export function ConfirmationDialog({
  isOpen,
  title,
  message,
  onConfirm,
  onCancel,
  confirmText = 'CONFIRM',
  cancelText = 'CANCEL',
  isDestructive = false,
}: {
  isOpen: boolean
  title: string
  message: string
  onConfirm: () => void
  onCancel: () => void
  confirmText?: string
  cancelText?: string
  isDestructive?: boolean
}) {
  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="soc-card rounded-lg p-stack-lg max-w-md w-full border border-outline-variant shadow-2xl">
        <h3 className="text-headline-md font-headline-md text-on-surface mb-2">{title}</h3>
        <p className="text-on-surface-variant text-body-base mb-6">{message}</p>
        <div className="flex justify-end gap-3">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-on-surface-variant hover:bg-surface-variant/50 transition-colors rounded text-label-caps font-label-caps"
          >
            {cancelText}
          </button>
          <button
            onClick={onConfirm}
            className={`px-4 py-2 transition-colors rounded text-label-caps font-label-caps ${
              isDestructive
                ? 'bg-error text-on-error hover:bg-error/90'
                : 'bg-primary text-on-primary hover:bg-primary/90'
            }`}
          >
            {confirmText}
          </button>
        </div>
      </div>
    </div>
  )
}
