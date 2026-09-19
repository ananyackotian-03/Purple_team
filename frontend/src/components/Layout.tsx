import { useState } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { useHealth } from '@/hooks/useApi'

const NAV_ITEMS = [
  { to: '/', icon: 'dashboard', label: 'Overview' },
  { to: '/digital-twin', icon: 'memory', label: 'Digital Twin' },
  { to: '/objectives', icon: 'target', label: 'Security Objectives' },
  { to: '/experiments', icon: 'science', label: 'Experiments' },
  { to: '/detection', icon: 'radar', label: 'Detection' },
  { to: '/detection-gaps', icon: 'search_off', label: 'Detection Gaps' },
  { to: '/defense-retests', icon: 'security', label: 'Defense & Retests' },
  { to: '/immune-memory', icon: 'history', label: 'Immune Memory' },
  { to: '/adaptive-testing', icon: 'psychology', label: 'Adaptive Testing' },
  { to: '/telemetry', icon: 'biotech', label: 'Telemetry' },
  { to: '/security-controls', icon: 'admin_panel_settings', label: 'Security Controls' },
  { to: '/audit', icon: 'fact_check', label: 'Audit & Evidence' },
]

function HealthDot({ ok }: { ok: boolean }) {
  return (
    <span
      className={`inline-block w-2 h-2 rounded-full mr-2 ${
        ok ? 'bg-secondary' : 'bg-error'
      }`}
    />
  )
}

export default function Layout() {
  const location = useLocation()
  const { data: health } = useHealth()
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  const infraStatus = {
    api: health?.status === 'healthy',
    docker: health?.docker === 'available',
    ollama: health?.ollama === 'available',
  }

  return (
    <>
      {/* Mobile overlay */}
      {mobileMenuOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-30 md:hidden"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      <aside className={`${mobileMenuOpen ? 'translate-x-0' : '-translate-x-full'} md:translate-x-0 fixed md:static inset-y-0 left-0 z-40 flex flex-col h-full py-stack-md overflow-y-auto w-64 border-r border-outline-variant bg-surface-container transition-transform duration-200`}>
        <div className="px-container-padding mb-stack-lg">
          <h1 className="text-headline-md font-headline-md text-primary tracking-tighter">
            SENTINELFORGE
          </h1>
          <p className="text-label-caps font-label-caps text-on-surface-variant mt-1">
            CYBER IMMUNE SYSTEM
          </p>
        </div>
        <nav className="flex-1 px-stack-sm">
          <ul className="space-y-1">
            {NAV_ITEMS.map((item) => {
              const isActive =
                item.to === '/'
                  ? location.pathname === '/'
                  : location.pathname.startsWith(item.to)
              return (
                <li key={item.to}>
                  <NavLink
                    to={item.to}
                    onClick={() => setMobileMenuOpen(false)}
                    className={isActive ? 'nav-link-active' : 'nav-link'}
                  >
                    <span
                      className={`material-symbols-outlined mr-3 ${
                        isActive ? 'text-on-primary-container' : ''
                      }`}
                      style={
                        isActive
                          ? { fontVariationSettings: "'FILL' 1" }
                          : undefined
                      }
                    >
                      {item.icon}
                    </span>
                    <span className="text-label-caps font-label-caps">
                      {item.label}
                    </span>
                  </NavLink>
                </li>
              )
            })}
          </ul>
        </nav>
        <div className="px-container-padding mt-stack-lg border-t border-outline-variant pt-stack-md">
          <p className="text-label-caps font-label-caps text-outline mb-3">
            INFRASTRUCTURE
          </p>
          <ul className="space-y-1">
            <li className="flex items-center px-2 py-2 rounded text-on-surface-variant">
              <span className="material-symbols-outlined mr-2 text-[18px]">
                dns
              </span>
              <span className="text-label-caps font-label-caps">System</span>
              <HealthDot ok={infraStatus.api} />
            </li>
            <li className="flex items-center px-2 py-2 rounded text-on-surface-variant">
              <span className="material-symbols-outlined mr-2 text-[18px]">
                api
              </span>
              <span className="text-label-caps font-label-caps">API</span>
              <HealthDot ok={infraStatus.api} />
            </li>
            <li className="flex items-center px-2 py-2 rounded text-on-surface-variant">
              <span className="material-symbols-outlined mr-2 text-[18px]">
                developer_board
              </span>
              <span className="text-label-caps font-label-caps">Docker</span>
              <HealthDot ok={infraStatus.docker} />
            </li>
            <li className="flex items-center px-2 py-2 rounded text-on-surface-variant">
              <span className="material-symbols-outlined mr-2 text-[18px]">
                smart_toy
              </span>
              <span className="text-label-caps font-label-caps">LLM</span>
              <HealthDot ok={infraStatus.ollama} />
            </li>
          </ul>
        </div>
      </aside>
      <main className="flex-1 flex flex-col h-full overflow-hidden relative">
        <header className="flex justify-between items-center w-full px-container-padding h-16 z-50 bg-surface-container-lowest border-b border-outline-variant docked full-width top-0">
          <div className="flex items-center md:hidden">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-2 text-on-surface-variant hover:bg-surface-variant/50 transition-colors rounded-full mr-2"
            >
              <span className="material-symbols-outlined">menu</span>
            </button>
            <span className="text-headline-md-mobile font-headline-md-mobile tracking-tighter text-on-surface">
              SENTINELFORGE
            </span>
          </div>
          <div className="hidden md:flex flex-1"></div>
          <div className="flex items-center space-x-4">
            <div className="p-2 text-on-surface-variant/50 cursor-default rounded-full" title="Notifications (Demo)">
              <span className="material-symbols-outlined">notifications</span>
            </div>
            <div className="p-2 text-on-surface-variant/50 cursor-default rounded-full" title="Settings (Demo)">
              <span className="material-symbols-outlined">settings</span>
            </div>
            <div className="px-4 py-2 bg-primary/10 border border-primary/20 text-primary/80 rounded flex items-center cursor-default" title="Environment Status">
              <span className="text-label-caps font-label-caps">
                LAB ENVIRONMENT
              </span>
            </div>
            <div className="w-8 h-8 rounded-full bg-surface-variant border border-outline-variant flex items-center justify-center cursor-default">
              <span className="material-symbols-outlined text-on-surface-variant/80 text-[18px]">person</span>
            </div>
          </div>
        </header>
        <div className="flex-1 overflow-y-auto p-container-padding md:p-stack-lg">
          <Outlet />
        </div>
      </main>
    </>
  )
}
