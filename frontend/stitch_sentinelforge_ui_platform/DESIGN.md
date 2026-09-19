---
name: Cyber-Immune Professional
colors:
  surface: '#131315'
  surface-dim: '#131315'
  surface-bright: '#39393b'
  surface-container-lowest: '#0e0e10'
  surface-container-low: '#1b1b1d'
  surface-container: '#201f21'
  surface-container-high: '#2a2a2c'
  surface-container-highest: '#353437'
  on-surface: '#e5e1e4'
  on-surface-variant: '#bec7d4'
  inverse-surface: '#e5e1e4'
  inverse-on-surface: '#303032'
  outline: '#88919d'
  outline-variant: '#3f4852'
  surface-tint: '#98cbff'
  primary: '#98cbff'
  on-primary: '#003354'
  primary-container: '#00a3ff'
  on-primary-container: '#00375a'
  inverse-primary: '#00629d'
  secondary: '#4edea3'
  on-secondary: '#003824'
  secondary-container: '#00a572'
  on-secondary-container: '#00311f'
  tertiary: '#ffb95f'
  on-tertiary: '#472a00'
  tertiary-container: '#da8b00'
  on-tertiary-container: '#4c2d00'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#cfe5ff'
  primary-fixed-dim: '#98cbff'
  on-primary-fixed: '#001d33'
  on-primary-fixed-variant: '#004a77'
  secondary-fixed: '#6ffbbe'
  secondary-fixed-dim: '#4edea3'
  on-secondary-fixed: '#002113'
  on-secondary-fixed-variant: '#005236'
  tertiary-fixed: '#ffddb8'
  tertiary-fixed-dim: '#ffb95f'
  on-tertiary-fixed: '#2a1700'
  on-tertiary-fixed-variant: '#653e00'
  background: '#131315'
  on-background: '#e5e1e4'
  surface-variant: '#353437'
typography:
  display-lg:
    fontFamily: Inter
    fontSize: 48px
    fontWeight: '700'
    lineHeight: 56px
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.01em
  headline-md-mobile:
    fontFamily: Inter
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
  body-base:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  data-mono:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '450'
    lineHeight: 18px
  data-mono-sm:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '400'
    lineHeight: 16px
  label-caps:
    fontFamily: Inter
    fontSize: 11px
    fontWeight: '700'
    lineHeight: 16px
    letterSpacing: 0.05em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  unit: 4px
  container-padding: 24px
  gutter: 16px
  stack-sm: 8px
  stack-md: 16px
  stack-lg: 32px
---

## Brand & Style
The design system embodies a "Cyber Immune" philosophy: autonomous, vigilant, and authoritative. It is engineered for high-stakes Security Operations Centers (SOC) where clarity and rapid response are paramount.

The aesthetic follows a **Modern Corporate** approach with **Technical Minimalism**. It avoids decorative flourishes or "gamer-centric" neon aesthetics in favor of a precise, tool-like interface. Surfaces are deep and layered, utilizing ultra-thin borders to define structure rather than heavy shadows. The emotional response should be one of absolute control and systematic reliability.

## Colors
The palette is optimized for long-duration monitoring in low-light environments. 

- **Primary (#00A3FF):** Reserved for "Active Defense" and primary navigation.
- **Success/Verified (#10B981):** Indicates "Immune" status or successful mitigation.
- **Warning (#F59E0B):** Represents anomalies requiring investigation.
- **Critical (#EF4444):** Strictly reserved for confirmed breaches or critical vulnerabilities.
- **Surfaces:** Use `#0A0A0C` for the global background and `#121214` for primary containers.
- **Borders:** Use white with 6-10% opacity (`#ffffff10`) to create structural definition without visual noise.

## Typography
This design system utilizes a dual-font strategy to separate UI narrative from technical telemetry.

1.  **Inter (UI & Narrative):** Used for all structural navigation, headlines, and descriptive text. It provides a modern, legible foundation for high-density layouts.
2.  **JetBrains Mono (Technical Data):** Used for all log entries, IP addresses, hash values, code snippets, and metric readouts. This ensures that technical characters (0/O, 1/l) are never confused during critical incidents.

Maintain high contrast by using pure white for headlines and an 80% white (Alpha) for body text.

## Layout & Spacing
The layout uses a **12-column Fluid Grid** designed for density. In a SOC context, information throughput is prioritized over whitespace. 

- **Density:** Use a tight 4px baseline grid. 
- **Margins:** 24px outer margins for desktop; 16px for mobile.
- **Breakpoints:**
  - Mobile: < 768px (Single column stack)
  - Tablet: 768px - 1280px (Condensed multi-column)
  - Desktop: 1280px+ (Full telemetry dash)
- **Reflow:** In technical tables, priority columns (Status, IP, Severity) are fixed, while descriptive columns (Message) are fluid.

## Elevation & Depth
Traditional drop shadows are prohibited. Depth is achieved through **Tonal Layering** and **Active Glows**.

- **Level 0 (Base):** `#0A0A0C` (Background).
- **Level 1 (Containers):** `#121214` with a 1px border of `#ffffff10`.
- **Level 2 (Popovers/Modals):** `#1A1A1C` with a 1px border of `#ffffff20`.
- **Active State:** Instead of a shadow, use a subtle outer glow using the primary color at 15% opacity (e.g., `0 0 12px #00A3FF26`) to imply an element is "energized" or "scanning."

## Shapes
The shape language is **Technical and Precise**. 

Use a 4px (Soft) radius for standard containers, buttons, and input fields. This provides just enough softness to remain modern while maintaining the rigid, structural feel of a security terminal. 

- **Status Indicators:** Use square pips for static data and circular pips for active/live processes.
- **Tags/Chips:** Use 2px radius for a more "industrial" appearance.

## Components
- **Buttons:** Solid `#00A3FF` for primary actions. Ghost buttons with 1px `#ffffff10` borders for secondary telemetry filtering.
- **Data Tables (SOC-style):** High-density rows (32px height). Hover states should trigger a full-row highlight of `#ffffff05`. Use JetBrains Mono for all cell data.
- **Immune Cycle Visualization:** A specialized circular or linear progress component showing four stages: *Identify, Protect, Detect, Respond*. Use a gradient stroke that transitions from Blue to Green as the cycle completes.
- **Telemetry Cards:** Cards should include a "Header" section with a 1px bottom border and a "Footer" section for timestamp metadata in `label-caps`.
- **Alert Badges:** Critical alerts should use a subtle pulse animation (0.8s ease-in-out) to draw attention without being disruptive.
- **Input Fields:** Dark fill (`#00000030`) with a 1px border. Focus state changes border color to Primary Blue with a 4px inner glow.