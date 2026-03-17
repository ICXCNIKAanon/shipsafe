# ShipSafe.org Landing Page Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the shipsafe.org marketing landing page with Shuttle.dev-level animation polish and a tropical night Caribbean sailing theme.

**Architecture:** Next.js 15 App Router with static export. Each page section is an isolated component. Framer Motion handles scroll-triggered animations and parallax. Tailwind CSS for styling with custom color tokens. All animations respect `prefers-reduced-motion`.

**Tech Stack:** Next.js 15, Tailwind CSS 3.4, Framer Motion 11, next/font/google, @vercel/og

**Spec:** `docs/superpowers/specs/2026-03-17-landing-page-design.md`

**Animation convention:** All `whileInView` animations MUST use `viewport={{ once: true, margin: "-100px" }}` so they trigger 100px before elements enter the viewport (smoother UX).

---

### Task 1: Scaffold Project + Tailwind + Fonts

**Files:**
- Create: `~/shipsafe-site/package.json`
- Create: `~/shipsafe-site/next.config.ts`
- Create: `~/shipsafe-site/tailwind.config.ts`
- Create: `~/shipsafe-site/postcss.config.mjs`
- Create: `~/shipsafe-site/tsconfig.json`
- Create: `~/shipsafe-site/app/layout.tsx`
- Create: `~/shipsafe-site/app/page.tsx`
- Create: `~/shipsafe-site/app/globals.css`
- Create: `~/shipsafe-site/.gitignore`

- [ ] **Step 1: Create project directory and initialize**

```bash
mkdir ~/shipsafe-site && cd ~/shipsafe-site
npx create-next-app@latest . --typescript --tailwind --eslint --app --src-dir=false --import-alias="@/*" --use-npm
```

- [ ] **Step 2: Install dependencies**

```bash
cd ~/shipsafe-site
npm install framer-motion
```

- [ ] **Step 3: Configure Tailwind with ShipSafe color tokens**

Replace `tailwind.config.ts` with custom theme extending the ShipSafe palette:
- Colors: navy-deep, navy, navy-mid, navy-light, gold, gold-light, cream, cream-dim, text-muted, success
- Font families: sans (Inter), serif (Playfair Display), mono (SF Mono/Fira Code)

- [ ] **Step 4: Configure layout.tsx with next/font**

- Import Inter and Playfair_Display from `next/font/google`
- Set metadata: title "ShipSafe — Security for Vibe Coders", description, openGraph
- Apply Inter as body font, expose Playfair via CSS variable `--font-serif`
- Set `<body className="bg-navy-deep text-cream">`

- [ ] **Step 5: Set up globals.css with custom CSS animations**

Add keyframes for: `twinkle` (star opacity), `bob` (sailboat movement), `shimmer` (water), `pulse-dot` (badge), `blink` (cursor). Add base styles: `scroll-behavior: smooth`, reduced-motion media query overrides.

- [ ] **Step 6: Create placeholder page.tsx**

```tsx
export default function Home() {
  return <main>ShipSafe — coming soon</main>;
}
```

- [ ] **Step 7: Verify dev server starts**

```bash
cd ~/shipsafe-site && npm run dev
```
Open http://localhost:3000 — should show placeholder text on navy-deep background with Inter font.

- [ ] **Step 8: Initialize git and commit**

```bash
cd ~/shipsafe-site && git init && git add -A && git commit -m "chore: scaffold Next.js 15 + Tailwind + Framer Motion"
```

---

### Task 2: Sailboat Logo SVG + Favicon

**Files:**
- Create: `~/shipsafe-site/components/logo.tsx`
- Create: `~/shipsafe-site/public/favicon.svg`
- Modify: `~/shipsafe-site/app/layout.tsx` (add favicon link)

- [ ] **Step 1: Create SVG sailboat logo component**

Minimal geometric sailboat: triangular main sail, smaller jib sail, curved hull. All in gold (`#d4a54a`). Component accepts `className` and `size` props. Should render cleanly at 16px (favicon) through 48px (nav).

- [ ] **Step 2: Create favicon.svg**

Sailboat mark centered in a navy circle background (`#0a1628`), mark in gold. 32x32 viewBox.

- [ ] **Step 3: Add favicon to layout.tsx**

```tsx
<link rel="icon" href="/favicon.svg" type="image/svg+xml" />
```

- [ ] **Step 4: Verify favicon loads in browser**

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add sailboat logo SVG and favicon"
```

---

### Task 3: Star Field + Scene Components (Moon, Palms, Sailboat, Water)

**Files:**
- Create: `~/shipsafe-site/components/star-field.tsx`
- Create: `~/shipsafe-site/components/scene.tsx`

- [ ] **Step 1: Build StarField component**

Renders 12 absolutely positioned dots with CSS `twinkle` animation. Each star gets randomized `--duration` (3-7s), `--delay` (0-3s), `--min-opacity` (0.1-0.3), `--max-opacity` (0.4-0.9). Responsive: render only 6 stars on mobile via prop or media query. Stars are `position: fixed` so they persist during scroll.

- [ ] **Step 2: Build Moon + MoonReflection sub-components in scene.tsx**

Moon: radial gradient div with box-shadow glow, absolute positioned top-right. MoonReflection: blurred gradient column below moon.

- [ ] **Step 3: Build PalmLeft sub-component in scene.tsx**

Trunk divs (3 segments for natural curve) + 5-6 frond divs, absolute positioned bottom-left. Hidden on mobile (`hidden md:block`).

- [ ] **Step 4: Build Sailboat sub-component in scene.tsx**

Mast (thin div), main sail (CSS triangle), jib sail (smaller triangle), hull (border-based shape). Apply `bob` animation class. Absolute positioned center-right.

- [ ] **Step 5: Build Water + WaterShimmer in scene.tsx**

Water: gradient div anchored to bottom. WaterShimmer: animated gradient line with `shimmer` keyframe.

- [ ] **Step 6: Wire parallax to Moon, Palms, Sailboat**

Use Framer Motion `useScroll()` + `useTransform()`:
- Moon: moves up at 0.3x scroll speed
- Palm: moves up at 0.5x scroll speed (foreground)
- Sailboat: moves up at 0.4x scroll speed
- Water: no parallax (anchored to bottom)

Wrap all parallax in `useReducedMotion()` check — return static positions when reduced motion preferred.

- [ ] **Step 7: Verify scene renders in hero area**

Temporarily add `<StarField />` and `<Scene />` to page.tsx. Check: stars twinkle, sailboat bobs, moon glows, water shimmers. Scroll and verify parallax layers move at different speeds.

- [ ] **Step 8: Commit**

```bash
git add -A && git commit -m "feat: add animated star field and parallax scene (moon, palms, sailboat, water)"
```

---

### Task 4: Navigation with Scroll-Aware Background

**Files:**
- Create: `~/shipsafe-site/components/nav.tsx`
- Modify: `~/shipsafe-site/app/page.tsx`

- [ ] **Step 1: Build Nav component**

Fixed position nav with: Logo (sailboat SVG + "ShipSafe" text), desktop links (Features, Pricing, Docs, GitHub), CTA button ("Install Free").

Use Framer Motion `useScroll()` to transition background from `transparent` to `rgba(5,10,24,0.85)` with `backdrop-filter: blur(12px)` after 100px scroll. Gold bottom border fades in simultaneously.

- [ ] **Step 2: Add mobile hamburger menu**

At `< 768px`: hide desktop links, show hamburger button (3 gold lines). On click, open full-screen overlay with `AnimatePresence` (slide down). Links stacked vertically, "Install Free" at bottom. Close on link click, X button, or scroll (use scroll event listener to close when `window.scrollY` changes).

- [ ] **Step 3: Add smooth scroll anchors**

Features → `#features`, Pricing → `#pricing`. Use `scroll-behavior: smooth` + offset for fixed nav height.

- [ ] **Step 4: Verify nav behavior**

Desktop: links visible, background transitions on scroll. Mobile (resize to <768px): hamburger appears, overlay opens/closes with animation. Scroll anchors work.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add scroll-aware navigation with mobile hamburger menu"
```

---

### Task 5: Hero Section

**Files:**
- Create: `~/shipsafe-site/components/hero.tsx`
- Modify: `~/shipsafe-site/app/page.tsx`

- [ ] **Step 1: Build Hero component**

Full viewport height section. Contains: Scene + StarField as background layers, then hero content on top (z-10).

Hero content (centered): Badge (pulsing gold dot + text), H1 ("Ship code that's" + line break + "actually safe." in gold gradient), subtitle paragraph, two CTA buttons.

- [ ] **Step 2: Add entrance animations**

Use Framer Motion `motion.div` with stagger container:
- Badge: fade in + slide up, 0.5s delay
- H1: fade in + slide up, 0.7s delay
- Subtitle: fade in + slide up, 0.9s delay
- CTAs: fade in + slide up, 1.1s delay

All wrapped in `useReducedMotion()` — show instantly when reduced motion.

- [ ] **Step 3: Style CTAs**

Primary (gold solid): `bg-gold text-navy-deep`, hover glow shadow + translateY(-1px). Secondary (ghost): transparent with cream border, hover brightens.

- [ ] **Step 4: Responsive check**

Desktop: 64px heading, centered. Tablet: 48px. Mobile: 36px, palms hidden, sailboat centered below text.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add hero section with entrance animations and parallax scene"
```

---

### Task 6: Terminal Mockup with Typewriter Effect

**Files:**
- Create: `~/shipsafe-site/components/terminal.tsx`
- Modify: `~/shipsafe-site/app/page.tsx`

- [ ] **Step 1: Build Terminal chrome**

macOS window frame: rounded container with frosted glass background (`backdrop-filter: blur(20px)`), gold border glow, traffic light dots (red/yellow/green).

- [ ] **Step 2: Implement typewriter animation**

Use Framer Motion `useInView` to trigger when terminal scrolls into viewport. Animation sequence:
1. Cursor blinks (CSS `blink` animation)
2. `$ shipsafe scan` types character-by-character (0.0-1.0s)
3. Pause 0.3s
4. "Scanning 847 files..." fades in (dim)
5. Pause 0.8s
6. Three success lines fade in with 0.2s stagger (green checkmarks)
7. Pause 0.4s
8. Score line fades in (gold "A")
9. "Smooth sailing" fades in (green)

Use `useReducedMotion()` — when reduced motion, show all lines immediately.

- [ ] **Step 3: Add accessibility attributes**

Add `aria-label="ShipSafe scan output example"` to the terminal container. Add `role="img"` since it's a decorative code display, not interactive.

- [ ] **Step 4: Position with negative margin**

`-mt-20` to overlap with hero section bottom. Center with `max-w-2xl mx-auto`.

- [ ] **Step 5: Verify animation plays on scroll**

Scroll down until terminal enters viewport. Typewriter should play once. Check reduced motion with browser devtools (Rendering > Emulate prefers-reduced-motion).

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: add terminal mockup with typewriter animation"
```

---

### Task 7: Social Proof Bar

**Files:**
- Create: `~/shipsafe-site/components/social-proof.tsx`
- Modify: `~/shipsafe-site/app/page.tsx`

- [ ] **Step 1: Build SocialProof component**

Section with gold top/bottom borders. Centered label "Trusted by teams shipping fast" in muted text. 5 placeholder company names ("ACME", "TERRAFORM", "SHIPYARD", "HARBOR", "CLOUDFLEET") in cream at 35% opacity, flex row with gap, bold monospace.

- [ ] **Step 2: Add scroll-triggered fade-in stagger**

Framer Motion `motion.div` stagger container — each logo fades up with 0.1s delay. `whileInView`, `viewport={{ once: true }}`.

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "feat: add social proof bar with staggered fade-in"
```

---

### Task 8: Features Grid

**Files:**
- Create: `~/shipsafe-site/components/features.tsx`
- Modify: `~/shipsafe-site/app/page.tsx`

- [ ] **Step 1: Build Features component**

Section with `id="features"`. Header: overline "Features" in gold, H2 "Everything you need to ship safely." in serif, subtitle paragraph.

3x2 grid of feature cards. Each card: icon (emoji), H3 title, description paragraph. Background `navy/30%` opacity, gold border on hover, lift + shadow transition.

Data array:
```ts
const features = [
  { icon: "🔍", title: "One-Command Scanning", desc: "..." },
  { icon: "🧠", title: "Knowledge Graph Engine", desc: "..." },
  { icon: "🔧", title: "Auto-Fix", desc: "..." },
  { icon: "🤖", title: "MCP Server", desc: "..." },
  { icon: "📡", title: "Production Monitoring", desc: "..." },
  { icon: "🪝", title: "Git Hooks", desc: "..." },
];
```

- [ ] **Step 2: Add scroll-triggered stagger animation**

Cards fade up + stagger 0.1s using Framer Motion `whileInView`. Responsive: 2-column on tablet, 1-column on mobile.

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "feat: add features grid with hover effects and scroll animation"
```

---

### Task 9: How It Works

**Files:**
- Create: `~/shipsafe-site/components/how-it-works.tsx`
- Modify: `~/shipsafe-site/app/page.tsx`

- [ ] **Step 1: Build HowItWorks component**

3-step horizontal layout with connecting line. Each step: gold numbered circle, title, description, code snippet.
- Step 1: "Install" — `npm install -g shipsafe`
- Step 2: "Scan" — `shipsafe scan`
- Step 3: "Ship" — Score A, deploy with confidence

Connecting line: thin gold line between circles (CSS pseudo-element or absolute div).

- [ ] **Step 2: Add scroll animation**

Steps reveal left-to-right with Framer Motion stagger. Mobile: vertical layout with connecting bar on left.

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "feat: add how-it-works 3-step section"
```

---

### Task 10: Pricing Section

**Files:**
- Create: `~/shipsafe-site/components/pricing.tsx`
- Modify: `~/shipsafe-site/app/page.tsx`

- [ ] **Step 1: Build Pricing component**

Section with `id="pricing"`. Header: overline + H2.

3-column grid. Each card: tier name, price, description, feature list with gold checkmarks, CTA button.

- FREE: $0/mo, secondary CTA
- PRO: $19/mo, featured card (gold border, glow, "Most Popular" badge), primary gold CTA
- TEAM: $49/mo, secondary CTA

Feature lists as specified in the design spec.

- [ ] **Step 2: Add scroll animation**

Cards scale from 0.95 → 1.0 + fade in, staggered. Responsive: stack on tablet/mobile with PRO card first (reorder via CSS order).

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "feat: add pricing section with tier cards"
```

---

### Task 11: Final CTA + Footer

**Files:**
- Create: `~/shipsafe-site/components/final-cta.tsx`
- Create: `~/shipsafe-site/components/footer.tsx`
- Modify: `~/shipsafe-site/app/page.tsx`

- [ ] **Step 1: Build FinalCTA component**

Centered section: H2 "Ready to ship safely?", subtitle, install command block with copy-to-clipboard button. Copy button uses `navigator.clipboard.writeText()`, shows "Copied!" feedback for 2 seconds.

- [ ] **Step 2: Build Footer component**

Semantic `<footer>`. Left: sailboat logo + "Connect Holdings LLC · Built in San Juan, PR 🇵🇷". Right: links (Docs, GitHub, Twitter). Gold top border.

- [ ] **Step 3: Add fade-up animation to FinalCTA**

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat: add final CTA with copy button and footer"
```

---

### Task 12: 404 Page + OG Image + Structured Data

**Files:**
- Create: `~/shipsafe-site/app/not-found.tsx`
- Create: `~/shipsafe-site/app/opengraph-image.tsx`
- Create: `~/shipsafe-site/public/og-image.png` (static fallback)
- Modify: `~/shipsafe-site/app/layout.tsx` (add structured data)

- [ ] **Step 1: Build 404 page**

Navy-deep background with star field. Centered: H1 "Lost at sea?" in serif, subtitle "This page doesn't exist.", "Back to shore →" link to `/`. Sailboat logo above heading.

- [ ] **Step 2: Build OG image route**

Use `next/og` (built into Next.js 15). 1200x630 image: navy-deep background, centered gold sailboat SVG mark, "ShipSafe" wordmark, tagline "Security for Vibe Coders" in cream.

- [ ] **Step 3: Generate static OG fallback**

Run the dev server, fetch `/opengraph-image` as PNG, save to `public/og-image.png` as a static fallback for platforms that don't execute the dynamic route. Add to layout.tsx metadata: `openGraph: { images: ['/og-image.png'] }`.

- [ ] **Step 4: Add JSON-LD structured data to layout.tsx**

Add `<script type="application/ld+json">` in layout with SoftwareApplication schema:
```json
{
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  "name": "ShipSafe",
  "applicationCategory": "DeveloperApplication",
  "operatingSystem": "macOS, Linux, Windows",
  "offers": { "@type": "Offer", "price": "0", "priceCurrency": "USD" },
  "description": "One-command security scanning, auto-fix, and production monitoring.",
  "url": "https://shipsafe.org"
}
```

- [ ] **Step 5: Verify OG image and structured data**

Visit `/opengraph-image` — should render PNG. Validate JSON-LD with Google's Rich Results Test or Schema.org validator.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: add 404 page, OG image, and structured data"
```

---

### Task 13: Assemble Page + Polish + Responsive QA

**Files:**
- Modify: `~/shipsafe-site/app/page.tsx`

- [ ] **Step 1: Assemble all sections in page.tsx**

Import order: Nav, Hero (with StarField + Scene), Terminal, SocialProof, Features, HowItWorks, Pricing, FinalCTA, Footer. Add skip-to-content link.

```tsx
export default function Home() {
  return (
    <>
      <a href="#main" className="sr-only focus:not-sr-only ...">Skip to content</a>
      <Nav />
      <main id="main">
        <Hero />
        <Terminal />
        <SocialProof />
        <Features />
        <HowItWorks />
        <Pricing />
        <FinalCTA />
      </main>
      <Footer />
    </>
  );
}
```

- [ ] **Step 2: Desktop QA (1440px+)**

Full scroll through: all animations fire, parallax smooth, nav transitions, terminal typewriter plays, cards hover correctly, pricing badges render, copy button works, all scroll anchors work.

- [ ] **Step 3: Tablet QA (768-1023px)**

Resize browser. Check: features 2-column, pricing stacks correctly, hero text 48px, scene scales, no horizontal overflow.

- [ ] **Step 4: Mobile QA (375px)**

Check: hamburger menu works, hero 36px, palm hidden, terminal full-width, all sections single-column, no overflow, tap targets 48px+, footer readable.

- [ ] **Step 5: Reduced motion QA**

Chrome DevTools > Rendering > Emulate prefers-reduced-motion. All animations should be instant/disabled. No janky half-states.

- [ ] **Step 6: Lighthouse audit**

Run Lighthouse on localhost. Target: Performance 90+, Accessibility 100, Best Practices 100, SEO 100.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat: assemble complete landing page with responsive + a11y polish"
```

---

### Task 14: Create GitHub Repo + Push

**Files:**
- No new files

- [ ] **Step 1: Create private repo on GitHub**

```bash
cd ~/shipsafe-site
gh repo create jakewlittle-cs/shipsafe-site --private --source=. --push
```

- [ ] **Step 2: Verify repo exists and is private**

```bash
gh repo view jakewlittle-cs/shipsafe-site --json isPrivate
```

- [ ] **Step 3: Done**

Site is built, pushed, and ready for Vercel deployment.
