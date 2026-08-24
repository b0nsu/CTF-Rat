# CTF-Rat Desktop UI/UX foundations

This document is the design-development contract for the Desktop workbench. It is intentionally narrower than a general-purpose application design system: CTF-Rat is a dense, long-running technical workbench where the user watches STATE, evidence, terminal output, and solver control without creating a second solver UI model.

## Research basis

The current foundation is informed by these public product/design-system references:

- VS Code UX Guidelines — containers, views, sidebars, panel, and status architecture: https://code.visualstudio.com/api/ux-guidelines/overview
- VS Code Sidebars — keep related views grouped and avoid excessive view containers: https://code.visualstudio.com/api/ux-guidelines/sidebars
- VS Code Panel — supporting views such as terminal/output benefit from horizontal space: https://code.visualstudio.com/api/ux-guidelines/panel
- GitHub Primer color usage — use functional/semantic tokens instead of raw base colors in components: https://primer.style/product/getting-started/foundations/color-usage/
- Atlassian Design Tokens — tokens are a single source of truth for repeatable UI decisions: https://atlassian.design/tokens/design-tokens
- Atlassian Spacing — use a constrained spacing scale and compact values for dense UI: https://atlassian.design/foundations/grid-beta/applying-grid
- Atlassian Typography — relative type units and a small hierarchy improve consistency and accessibility: https://atlassian.design/foundations/typography/
- WCAG 2.2 Target Size (Minimum) — pointer targets should be at least 24×24 CSS px unless an exception applies: https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum
- WCAG 2.2 Focus Appearance — visible focus indicators should have sufficient area and contrast: https://www.w3.org/WAI/WCAG22/Understanding/focus-appearance.html

These are references, not dependencies. CTF-Rat keeps its own visual language and does not import another product's component library.

## Workbench information architecture

The default layout follows a stable technical-workbench model:

```text
┌──────────────────────── challenge / solver controls ────────────────────────┐
├──────────────────────── replay / live status ───────────────────────────────┤
├──────────────────────── current solver focus ───────────────────────────────┤
│ Primary context │               Main activity               │ Inspector     │
│ STATE           │ Activity Timeline                         │ selected      │
│ artifacts       ├───────────────────────────────────────────┤ event /       │
│                 │ Terminal / supporting execution output    │ artifact      │
└─────────────────┴───────────────────────────────────────────┴───────────────┘
```

Rules:

1. **Left is durable context.** STATE counts and artifact discovery live in the primary sidebar.
2. **Center is current work.** The activity timeline is the dominant surface.
3. **Bottom is supporting execution.** Terminal output is important but should not displace the reasoning/evidence timeline.
4. **Right is detail.** Inspector content always reflects the user's explicit selection.
5. **Top bars are status/control, not dashboards.** Keep only challenge identity, bounded solver controls, replay, connection, and compact solver focus.
6. **Do not create a second reasoning model.** UI labels and summaries must project canonical STATE/query/artifact data.

## Design tokens

`src/tokens.css` is the only place component-independent raw visual values should normally be introduced.

Token categories:

- `--font-*`, `--text-*`, `--line-*`, `--weight-*`
- `--space-*`
- `--radius-*`, geometry, panel sizing
- `--color-surface-*`, `--color-fg-*`, `--color-border-*`
- semantic state roles: accent, success, warning, danger, focus
- motion duration/easing

Component CSS should prefer semantic roles such as `--color-fg-muted` or `--color-surface-selected` instead of raw hex values. A raw value is acceptable only for a very local optical adjustment and should be migrated into a semantic token if reused.

### Density

CTF-Rat is deliberately compact, but compact does not mean tiny.

- Base layout rhythm: 4/8 px with 2/6/12 px intermediate compact values.
- Standard controls: 32 px height.
- Repeating interactive timeline rows: 44 px minimum.
- Artifact rows: 46 px minimum.
- Small status labels may be visually shorter because they are not interactive.
- Body/component text: primarily 12–14 px equivalent in relative units.
- Monospace is reserved for identifiers, digests, cursors, terminal data, and code-like values.

## Color and state

Color communicates role, not decoration.

- Accent: selection, current route, interactive emphasis.
- Success: running/verified-positive state.
- Warning: finished/historical/attention state.
- Danger: offline, destructive stop, errors.
- Neutral: ordinary metadata and inactive state.

Never encode a state only with color. Every important state also has text such as `RUNNING`, `OFFLINE`, `LIVE`, `HISTORICAL`, or a STATE status value.

## Selection and inspector behavior

There is one visible inspector context at a time.

- Clicking an artifact selects the artifact and shows its preview.
- Clicking a timeline event clears artifact selection and shows the event immediately.
- Selected rows use both a background/border treatment and `aria-pressed` semantics.
- Long identifiers remain copyable/readable through the inspector and use native title text where truncation is unavoidable.

This prevents stale detail panes where the main selection and inspector disagree.

## Keyboard and accessibility

Baseline requirements:

- Every interactive control has a visible `:focus-visible` indicator.
- Focus styling is at least a 2 CSS px outline in the default theme.
- Pointer targets are at least 24×24 CSS px; standard workbench controls are larger.
- Replay has an accessible label and announces LIVE versus historical sequence value.
- Connection changes use a polite status region; errors use an alert region.
- Scrollable terminal and inspector code blocks are keyboard-focusable.
- Reduced-motion preferences suppress non-essential transitions.
- Forced-colors mode receives explicit selected/focus boundaries.

Keyboard behavior should stay native unless there is a measured need for a command palette or custom roving-focus interaction.

## Responsive window behavior

The packaged window currently has a 1100 px minimum width. The layout therefore optimizes for desktop workbench sizes instead of collapsing into a mobile navigation model.

- Above ~1280 px: standard sidebar and inspector widths.
- Between 1140–1280 px: both side regions contract before the center activity surface.
- Near minimum width: secondary focus labels may collapse while values remain visible.
- The center timeline keeps the largest flexible share of available space.

Do not hide canonical evidence solely to make a narrow layout look cleaner.

## Interaction guidance for v0.3

Future controls such as FAST, DEEP, Verify, Function Card, Primitive/Finding views, or intervention intents should follow these rules:

1. Add a control only when it maps to a typed/bounded backend intent.
2. Prefer existing workbench regions before creating new containers.
3. Keep primary-sidebar view count small; use tabs/filters inside a related view when appropriate.
4. Put wide supporting output in the bottom panel rather than permanently widening sidebars.
5. Put selected-object detail in the inspector, not a new modal by default.
6. Reuse semantic tokens; do not add feature-specific raw colors.
7. Provide loading, empty, disabled, success, error, and focus states before considering a component complete.
8. Preserve STATE/artifact/query source-of-truth boundaries.

## Design-development workflow

For UI work, use this sequence:

1. **Evidence:** identify the user task and canonical data source.
2. **Placement:** choose the existing workbench region before inventing a new one.
3. **State model:** list idle/loading/live/selected/disabled/error/historical states.
4. **Token mapping:** implement with semantic tokens and the spacing/type scale.
5. **Keyboard pass:** tab through controls and verify focus/target behavior.
6. **Narrow-window pass:** test around 1440, 1280, 1140, and the 1100 px minimum.
7. **Build pass:** TypeScript/Vite build plus Tauri compile/package checks.
8. **Regression pass:** ensure Desktop presentation did not alter canonical solver behavior.

## Current non-goals

- No custom theme editor in v0.2.
- No imported UI component framework merely for visual consistency.
- No mobile layout.
- No free-form HTTP command surface.
- No Desktop-specific finding/evidence database.
- No animation-heavy solver visualization.

The foundation is intentionally conservative so v0.3 can add operational controls and richer projections without redesigning the shell again.
