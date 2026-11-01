# Dashboard layout and navigation

The overview header puts the brand and filter grid on separate rows. Controls
shrink inside their columns and reflow at tablet/mobile widths; long category
labels cannot force the search field over the logo. The featured "Dated reference
cases" shortcut row has been removed. Named-case search and dated notes remain
available in CVE details.

## Independent attention pagination

`attention_page` is a zero-based URL parameter with six rows per page. The
attention query uses bounded LIMIT/OFFSET and a stable CVE tie-breaker. Negative,
invalid and oversized page parameters are normalized/clamped to available pages.

- Attention navigation preserves publication pagination, date range, search,
  product, severity, category and the View all setting.
- Publication navigation preserves the attention page.
- Changing the filter form resets pagination rather than retaining an out-of-range
  selection. The attention queue still ignores publication dates by design.
- Each page shows its row range and total alongside Previous/Next controls;
  unavailable controls are disabled. Links anchor back to the attention queue.

Signal chips are compact; curated Exploit-DB entry counts are distinguished from
unverified repository candidates, with explanatory titles on their chips.

## CVE detail

The primary grid contains scores, components and source documents first. Score
history and public exploit evidence follow in the same grid. On narrow screens
the sections stack, keeping the scores first and containing long tables/charts
inside their own scroll regions.

Long descriptions have a short preview and an explicit full-description
disclosure. Evidence context, dated reference notes and source-event history are
collapsed initially. No source notes or descriptions are deleted; expanding them
reveals the existing material without pushing every chart below it by default.

## Validation on 1 November 2026

- Full suite: 257 passing tests, including SQL page boundaries, filter-state
  preservation, invalid-page clamping and detail section order.
- Browser checks at widths 1440, 1024 and 390: no horizontal page overflow;
  the brand and filter controls occupy separate vertical bands.
- Real attention pagination: page 1 contained rows 1-6, page 2 contained 7-12
  with different CVE identifiers and preserved filters.
- PHP2Shell desktop detail at 1440x900: primary cards began at y=263 and the
  history card ended at y=890; contextual disclosures were initially closed.
- Local screenshots: `data/ui-checks/home-layout.jpg` and
  `data/ui-checks/cve-layout.jpg` (ignored runtime artifacts).

These measurements describe this viewport/dataset, not every possible content
combination. Reference data, scoring formulas and public/anonymous access are
unchanged by the layout work.
