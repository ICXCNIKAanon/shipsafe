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
- Shows `$ shipsafe scan` output with syntax coloring
- **Animation:** Typewriter effect — lines appear sequentially with realistic timing. Cursor blinks, then command types out, then results appear line by line.
- Frosted glass background with gold border glow
- Positioned to overlap hero/next section slightly (negative margin)

### 4. Social Proof Bar
- "Trusted by teams shipping fast" label
- 5 logo placeholders (replace with real logos when available)
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
- FREE ($0) / PRO ($19/mo, featured) / TEAM ($49/mo)
- Gold "Most Popular" badge on PRO
- Feature lists with gold checkmarks
- CTAs: "Get Started Free" / "Start Pro Trial" (gold) / "Contact Sales"
- **Animation:** Cards scale up from 0.95 on scroll into view, staggered

### 8. Final CTA
- "Ready to ship safely?"
- Install command block with copy button
- **Animation:** Fade up on scroll

### 9. Footer
- "Built in San Juan, PR 🇵🇷"
- Links: Docs, GitHub, Twitter
- © Connect Holdings LLC

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

## Responsive Breakpoints

| Breakpoint | Layout Changes |
|------------|---------------|
| Desktop (1024px+) | Full layout as designed |
| Tablet (768-1023px) | Features 2-column, pricing stacks, hero text smaller |
| Mobile (<768px) | Single column everything, nav becomes hamburger, hero 36px, terminal full-width |

---

## Tech Stack

- **Framework:** Next.js 15 (App Router, static export)
- **Styling:** Tailwind CSS 4
- **Animations:** Framer Motion 11
- **Fonts:** Google Fonts (Inter + Playfair Display)
- **Hosting:** Vercel (or static export to any CDN)
- **Repo:** Separate repo (`jakewlittle-cs/shipsafe-site`, private)

---

## Project Structure

```
shipsafe-site/
├── app/
│   ├── layout.tsx          # Root layout, fonts, metadata
│   ├── page.tsx            # Landing page (imports sections)
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
- OG image: Hero scene rendered as static PNG (1200x630)
- Structured data: SoftwareApplication schema
