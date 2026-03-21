# ShipSafe.org Landing Page — Design Spec

## Overview

Marketing landing page for shipsafe.org. Single-page, Shuttle.dev-level polish with a tropical night / Caribbean sailing theme. Next.js 15 + Tailwind CSS + Framer Motion. Separate repo from the CLI.

**Visual direction:** "Tropical Night Seafarer" — deep navy sky, gold moonlight, palm silhouettes, sailboat, twinkling stars. Warm and approachable, not corporate. Premium feel with indie dev tool personality.

**Reference:** Shuttle.dev for animation quality and CRO structure. Cyberduck.io for friendly indie energy.

---

## Logo / Brand Mark

**Mark:** Minimal sailboat silhouette in gold on navy. Single-stroke geometric style — triangular sail + curved hull. Works at 16px favicon size and 48px nav size.

**Wordmark:** "ShipSafe" in Inter 700 with the sailboat mark replacing the anchor emoji currently used. Gold on dark backgrounds, navy on light.

**Favicon:** Sailboat mark only, gold on navy circle.

---

## Color Palette

| Token | Value | Usage |
|-------|-------|-------|
| `navy-deep` | `#050a18` | Page background |
| `navy` | `#0a1628` | Card backgrounds |
| `navy-mid` | `#0f2040` | Elevated surfaces |
| `navy-light` | `#1a3d5c` | Borders, water |
| `gold` | `#d4a54a` | Primary accent, CTAs, logo |
| `gold-light` | `#e8c675` | Highlights, gradients |
| `cream` | `#f1e8d8` | Primary text |
| `cream-dim` | `rgba(241,232,216,0.7)` | Secondary text |
| `text-muted` | `rgba(148,163,184,0.8)` | Tertiary text |
| `success` | `#4ade80` | Terminal success |

## Typography

| Role | Font | Weight | Size |
|------|------|--------|------|
| Headings | Playfair Display | 700-800 | 40-64px |
| Body | Inter | 400-500 | 14-18px |
| UI / Nav | Inter | 500-700 | 12-15px |
| Code / Terminal | SF Mono / Fira Code | 400-600 | 13-14px |

---

## Page Sections (top to bottom)

### 1. Navigation (fixed)
- Logo (sailboat mark + "ShipSafe") left
- Links: Features, Pricing, Docs, GitHub
- CTA button: "Install Free" (gold outline)
- Transparent on load → frosted glass (`backdrop-filter: blur`) on scroll
- Animation: background opacity transitions based on scroll position

### 2. Hero
- **Background scene:** Animated star field (CSS twinkling), moon with radial gradient glow, palm silhouette (left), sailboat (center-right) with bobbing animation, water gradient with shimmer, moon reflection column
- **Badge:** Pulsing dot + "Now with knowledge graph security analysis"
- **Headline:** "Ship code that's actually safe." — serif, 64px, "actually safe." in gold gradient
- **Subhead:** "Security scanning, auto-fix, and production monitoring — all from your terminal. One command. Zero config."
- **CTAs:** "Get Started Free" (gold solid) + "See How It Works →" (ghost)
- **Animations:**
  - Stars: CSS twinkle with random delays (already built)
  - Moon + palms: parallax on scroll (Framer Motion `useScroll` + `useTransform`)
  - Sailboat: CSS bob keyframe + scroll parallax
  - Hero text: fade-up + stagger on page load (Framer Motion)
  - Badge: fade-in with 0.5s delay

### 3. Terminal Mockup
- macOS-style window chrome (red/yellow/green dots)
- Frosted glass background with gold border glow
- Positioned to overlap hero/next section slightly (negative margin)
- **Terminal content (exact copy):**
  ```
  $ shipsafe scan                           [typed, 0.0-1.0s]
                                            [pause 0.3s]
  Scanning 847 files...                     [fade in, dim]
                                            [pause 0.8s]
  ✓ Pattern engine — 0 secrets, 0 vulns     [fade in, green ✓]
  ✓ Knowledge graph — 0 attack paths        [fade in, 0.2s delay]
  ✓ Taint analysis — 0 unsanitized flows    [fade in, 0.2s delay]
                                            [pause 0.4s]
  Score: A | 0 findings | 1.2s              [fade in, gold "A"]
  Smooth sailing. Ship it. ⛵                [fade in, green]
  ```
- **Animation:** Typewriter effect — command types character-by-character, then results appear line-by-line with delays as noted above. Blinking cursor throughout. Total sequence: ~4 seconds. Triggers when terminal scrolls into view (`whileInView`).

### 4. Social Proof Bar
- "Trusted by teams shipping fast" label
- 5 placeholder company names in monochrome cream at 35% opacity (e.g., "ACME", "TERRAFORM", "SHIPYARD", "HARBOR", "CLOUDFLEET")
- When real logos available: white/monochrome SVGs, max height 24px, all same visual weight
- Thin gold border separators top/bottom
- **Animation:** Logos fade in with stagger on scroll into view

### 5. Features Grid (3x2)
- Section header: "Everything you need to ship safely."
- 6 feature cards:
  1. One-Command Scanning (wraps Semgrep/Gitleaks/Trivy)
  2. Knowledge Graph Engine (attack paths, missing auth, taint analysis)
  3. Auto-Fix (secrets → .env automatically)
  4. MCP Server (7 tools for AI assistants)
  5. Production Monitoring (error capture, PII scrubbing)
  6. Git Hooks (pre-commit scanning)
- Cards: navy glass background, gold border on hover, lift + shadow
- **Animation:** Cards fade up + stagger (`whileInView`, 0.1s delay between)

### 6. How It Works (3-step)
- Step 1: Install (`npm install -g shipsafe`)
- Step 2: Scan (`shipsafe scan`)
- Step 3: Ship (score A, deploy with confidence)
- Horizontal layout with numbered circles and connecting line
- **Animation:** Steps reveal left-to-right on scroll

### 7. Pricing (3-column)
- Gold "Most Popular" badge on PRO
- **FREE ($0/mo):** Pattern scanning (Semgrep, Gitleaks, Trivy) · 1 project · Pre-commit hooks · Community support → "Get Started Free"
- **PRO ($19/mo, featured):** Everything in Free · Knowledge graph engine · Auto-fix (--fix) · Production monitoring · MCP server for AI assistants · 5 projects → "Start Pro Trial" (gold CTA)
- **TEAM ($49/mo):** Everything in Pro · GitHub App (PR scanning) · Source map upload · 20 projects · Priority support → "Contact Sales"
- **Animation:** Cards scale up from 0.95 on scroll into view, staggered

### 8. Final CTA
- "Ready to ship safely?"
- Install command block with copy button
- **Animation:** Fade up on scroll

### 9. Footer
- "Built in San Juan, PR 🇵🇷"
- Links: Docs, GitHub, Twitter
- © ShipSafe

---

## Animations — Technical Spec

### Framer Motion Patterns
```
// Scroll-triggered fade up (reusable)
whileInView={{ opacity: 1, y: 0 }}
initial={{ opacity: 0, y: 30 }}
transition={{ duration: 0.6, ease: "easeOut" }}
viewport={{ once: true, margin: "-100px" }}

// Stagger children
transition={{ staggerChildren: 0.1 }}

// Parallax
const { scrollYProgress } = useScroll()
const moonY = useTransform(scrollYProgress, [0, 1], [0, -80])

// Nav background
const navBg = useTransform(scrollY, [0, 100], ["rgba(5,10,24,0)", "rgba(5,10,24,0.8)"])
```

### CSS Animations
- Star twinkle: opacity oscillation with random duration/delay
- Sailboat bob: translateY + slight rotate, 6s ease-in-out infinite
- Water shimmer: scaleX pulse, 8s ease-in-out infinite
- Badge dot pulse: opacity + box-shadow, 2s infinite

### Typewriter Terminal
- Uses Framer Motion `animate` with delay chain
- Each line has a start delay relative to previous line
- Cursor element blinks via CSS animation
- Total sequence: ~4 seconds

---

## Accessibility

### `prefers-reduced-motion`
- Wrap all Framer Motion animations in `useReducedMotion()` check
- When reduced motion: all `whileInView` animations show instantly (no transition), star twinkle disabled (static opacity), sailboat bob disabled, typewriter shows all lines at once, parallax disabled (elements at rest position)
- Water shimmer reduced to static gradient

### Keyboard & Screen Reader
- All interactive elements focusable with visible focus rings (gold outline)
- Semantic HTML: `<nav>`, `<main>`, `<section>`, `<footer>`
- Skip-to-content link hidden until focused
- Terminal mockup uses `aria-label="ShipSafe scan output example"`
- Pricing cards use proper heading hierarchy

---

## Responsive Breakpoints

| Breakpoint | Layout Changes |
|------------|---------------|
| Desktop (1024px+) | Full layout as designed |
| Tablet (768-1023px) | Features 2-column, pricing stacks, hero text 48px, scene scales proportionally |
| Mobile (<768px) | Single column, hamburger nav, hero 36px, terminal full-width, scene simplified |

### Mobile Nav (< 768px)
- Hamburger icon (3 lines) replaces link list
- Opens full-screen overlay (navy-deep background, 100vh)
- Links stacked vertically, centered, 18px, 48px tap targets
- "Install Free" CTA at bottom of overlay
- Close on link click, close button (X), or scroll
- Framer Motion `AnimatePresence` for slide-down enter / slide-up exit

### Mobile Scene Behavior
- Stars: reduced count (6 instead of 12), no parallax
- Moon: static position (no parallax), slightly smaller
- Palm silhouette: hidden on mobile (< 768px) — too much visual noise at small sizes
- Sailboat: centered below text, bob animation kept, no parallax
- Water: reduced height, shimmer kept

### How It Works — Mobile
- Vertical layout, connecting line becomes vertical bar on left
- Steps stack vertically with step numbers aligned to the bar

---

## Tech Stack

- **Framework:** Next.js 15 (App Router, static export)
- **Styling:** Tailwind CSS 3.4 (stable config-file-based setup)
- **Animations:** Framer Motion 11
- **Fonts:** `next/font/google` for Inter + Playfair Display (self-hosted, zero layout shift, `font-display: swap`)
- **Hosting:** Vercel (or static export to any CDN)
- **Repo:** Separate repo (`ICXCNIKAanon/shipsafe-site`, private)

---

## Project Structure

```
shipsafe-site/
├── app/
│   ├── layout.tsx          # Root layout, fonts, metadata
│   ├── page.tsx            # Landing page (imports sections)
│   ├── not-found.tsx       # 404 page (tropical night theme, "Lost at sea?")
│   ├── opengraph-image.tsx # Dynamic OG image via @vercel/og
│   └── globals.css         # Tailwind base + custom animations
├── components/
│   ├── nav.tsx             # Fixed navigation
│   ├── hero.tsx            # Hero section + scene
│   ├── star-field.tsx      # Animated stars
│   ├── scene.tsx           # Moon, palms, sailboat, water
│   ├── terminal.tsx        # Typewriter terminal mockup
│   ├── social-proof.tsx    # Logo bar
│   ├── features.tsx        # Feature grid
│   ├── how-it-works.tsx    # 3-step flow
│   ├── pricing.tsx         # Pricing cards
│   ├── final-cta.tsx       # Bottom CTA
│   └── footer.tsx          # Footer
├── public/
│   ├── favicon.svg         # Sailboat mark
│   └── og-image.png        # Social share image
├── tailwind.config.ts
├── next.config.ts
└── package.json
```

---

## SEO & Meta

- Title: "ShipSafe — Security for Vibe Coders"
- Description: "One-command security scanning, auto-fix, and production monitoring. Ship code you trust."
- OG image: Generated via `@vercel/og` at `/app/opengraph-image.tsx` — navy background, gold sailboat mark, headline text, 1200x630
- Structured data: SoftwareApplication schema

---

## 404 Page

"Lost at sea?" headline in serif, sailboat illustration, "Back to shore →" CTA linking to `/`. Same tropical night background, minimal — just the message and a way home.

---

## Notes

- This spec lives in the CLI repo for now. It will be copied to `shipsafe-site` repo when scaffolded.
- Pricing is subject to change before launch — the feature gates match what's already enforced in the CLI (`src/cli/license-gate.ts`).
