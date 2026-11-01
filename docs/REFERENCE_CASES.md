# Dated reference cases and contextual presentation

The public radar separates four live dimensions in the collapsed Evidence context section of CVE details:

- Observed attention over 30 days: documents, deduplicated story titles and
  publisher domains. These counts are not independent corroborations.
- Technical conditions from a validated CVSS vector and the CNA/vendor record.
- Exploitation observations recorded in the configured inputs.
- Known scale: the current inputs do not establish global prevalence or victim
  counts. An EPSS probability is not a measure of successful compromises.

Dated reference notes provide the fifth dimension: **how the evidence changed**.
They are editorially reviewed source summaries in
[`config/reference_cases.json`](../config/reference_cases.json), not automated
assertions extracted from news headlines, nor overrides of live scoring inputs.
No accounts, CMDB or personal tracking are introduced.

## PHP2Shell

The curated reference covers CVE-2026-109618 and CVE-2026-109619. Searching
`PHP2Shell` returns both identifiers, including when the CNA descriptions do not
contain that nickname. Use the public search field to find it; featured reference-case shortcuts are not displayed on the home page.

Its dated notes preserve these distinct observations:

| Publicly available | Observation | Source and scope |
|---|---|---|
| 21 October 2026 | Attempts observed before disclosure; success on real systems unclear | [AWS MadPot telemetry](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/) |
| 25 October | Earlier attribution withdrawn | [Unit 42](https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/), its particular incident attribution |
| 26 October | Both CVEs added to KEV | [CISA catalog](https://github.com/cisagov/kev-data/blob/main/known_exploited_vulnerabilities.json), known exploitation rather than a victim count |
| 26 October | Early sample did not show mass exploitation | [CrowdSec](https://www.crowdsec.net/vulntracking-report/cve-2026-109618-php2shell-no-mass-exploitation-yet), observations from 21-25 October |
| 27 October | Captured attempts had not completed the chain | [Wiz](https://www.wiz.io/blog/php2shell-exploitation-so-far), its telemetry |
| 29 October | Campaign confirmed in a specific deployment context | [Unit 42](https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/), exposed PAN-OS management interfaces |

These statements are retained together rather than allowing the latest sentence
to erase earlier uncertainty, a correction or another provider's narrower
sample. Publication dates control availability: a report published on the 26th
about the 21-25 observation window is not treated as knowledge available on the
25th. The notes do not claim that a specific campaign describes all PHP systems.

## Linux kernel IPv4 TCP RCE

The reference covers CVE-2026-98432 specifically; generic searches for `kernel`
are not forced onto this identifier. [AWS's bulletin](https://aws.amazon.com/security/security-bulletins/2026-160-aws/)
describes conditional unauthenticated RCE. That establishes technical potential,
not exploitation prevalence. Its publication at 22:15 PDT on 30 October is
represented as available on 31 October UTC.

The case remains useful when the numeric index is low: the technical capability,
the available activity observations and the unknown scale are visibly separate.
It is not hardcoded to a desired score or an Overhyped label.

## Presentation compatibility

The formulas, thresholds, numeric scores and stored category/rule identifiers
are unchanged by this presentation change. Their public wording is descriptive:

| Stored identifier | Public wording |
|---|---|
| `Earned the hype` | High attention + observed exploitation |
| `Sleeper` | Observed exploitation + lower recent attention |
| `Overhyped` | High attention + lower observed evidence |

The UI does not claim that observed exploitation justifies every headline.
Filters and existing links continue using the persisted identifiers. Webhook
JSON retains `category` and adds `category_label`; human alert text uses the
descriptive wording. Deduplication keys remain unchanged.

The home plot is labelled **Current scores by publication date** because its
points are current cohort averages, not reconstructed past scores. Search aliases
scope that cohort query as well. Individual score-history charts remain distinct
from the dated source-note timeline.

The detail header says **Page generated**, with score-evaluation and EPSS dates
shown separately. Rendering the page does not establish fresh source collection.

## Review and validation

References were reviewed on 1 November 2026. Requests for an earlier as-of date
exclude later notes. A later date does not silently extend the review horizon:
the UI marks the reference as awaiting a newer review. This is not a complete
historical backtest or a reconstruction of every source at the cutoff.

If curated references contain exploitation reports missing from live input
flags, the page highlights that coverage gap instead of quietly changing scores.
Tests cover chronology, retraction, partial telemetry, later confirmation,
conditional RCE, source scope, stale editorial review, search and HTML escaping.
