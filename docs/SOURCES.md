# Source registry and admission checks

Current configuration: **44 feeds** (30 in `rss`, 14 in `rss_regex_only`).
The cvefeed.io catalogue is also treated as advisory/catalogue content rather
than press. KEV, EPSS, CVE List V5, Exploit-DB CSV, CIRCL and GHSA remain separate
structured ingestion sources; their counts should not be conflated with feed counts.

## Specialist press for observing possible Hype

The public radar collects global news coverage without accounts, a CMDB or
personal product tracking. News articles are attention observations; an alarming
headline or a large number of stories does not prove exaggeration or exploitation.

| Added publication | Feed | Role |
|---|---|---|
| The Register | [Security Atom](https://www.theregister.com/security/headlines.atom) | English-language technology/security reporting |
| Infosecurity Magazine | [News RSS](https://www.infosecurity-magazine.com/rss/news/) | Specialist security news |
| Security Affairs | [RSS](https://securityaffairs.com/feed) | Security reporting and analysis |
| CSO Online | [RSS](https://www.csoonline.com/feed/) | Security industry reporting |
| Hispasec / Una al Día | [RSS](https://unaaldia.hispasec.com/feed) | Spanish-language security reporting |

These complement The Hacker News, BleepingComputer, SecurityWeek, The Record,
Dark Reading, Help Net Security, KrebsOnSecurity and CyberScoop already configured.
The `rss` group also contains vendor/research publications; it is not a claim that
all entries come from independent newsrooms. Technical advisories remain a
separate document class and do not contribute to Hype.

The reader extracts explicit CVEs from publisher-provided Atom content and
WordPress `content:encoded`, as well as titles, summaries and links. This fixes
feeds whose lead has no identifier but whose article body names the CVE.
Article bodies are processed transiently: only identifiers are retained from the
additional body field, not the full article. Scripts, styles and comments are
excluded. No paywall bypass, unrestricted article crawler or guessed CVE mapping
is introduced.

Verified IDs are included in the LLM input and used as an output allowlist.
The extractor cache is versioned so old summary-only verdicts do not suppress
new body evidence; cache refresh also updates its timestamp. Several explicit
CVEs can be associated with the same story as mentions, not necessarily as its
primary subject or independently corroborated facts.

The [dated press intake](scoring-audit/2026-11-01-press-coverage.json) records the
real ingestion and test results. The local test uses deterministic heuristic tone
without LLM calls. That fallback is not a calibrated multilingual assessment;
Spanish and English headline scores should not be treated as equally validated.
Simple title clustering also does not detect every syndicated/paraphrased story.

Cybersecurity Dive and Cybernews returned usable feeds but no CVE references in
the sampled fields; SC World's tested feed URL returned HTML rather than entries.
They are not advertised as integrated CVE coverage. They need a bounded, attributed
article-resolution adapter before they can contribute reliably.

## Additional primary advisory sources

| Publisher | Feed | Classification | Contribution |
|---|---|---|---|
| Ubuntu | [USN RSS](https://ubuntu.com/security/notices/rss.xml) | advisory | Ubuntu package security notices and explicit CVE references |
| Debian | [DSA long RSS](https://www.debian.org/security/dsa-long) | advisory | Debian security advisories including their expanded descriptions |
| CERT-FR / ANSSI | [Avis RSS](https://cert.cyber.gouv.fr/avis/feed/) | advisory | Technical notices, complementary to the existing alert feed |
| CERT/CC | [Vulnerability Notes Atom](https://www.kb.cert.org/vuls/atomfeed/) | advisory | Coordinated vulnerability notes and explicit CVE references |

These are references to technical documents, not automatic confirmation of
exploitation, proof that a patch applies to a particular asset, or independent
press attention. They pass through deterministic CVE extraction without an LLM.
Multiple explicit CVEs per item are retained and `(cve_id,url)` deduplicates
repeated retrievals. Documents appear in CVE details as **Technical advisory**.
They do not contribute to the recent-press aggregate used by Hype.

## Admission criteria

1. Public publisher-controlled endpoint, usable without private credentials.
2. HTTP response and parsed RSS/Atom entries checked from this environment.
3. CVE identifiers must be present in the fields actually extracted by the
   reader; a healthy URL alone does not establish useful CVE coverage.
4. Preserve original document URL, publisher, date and document kind.
5. Exercise the production ingestion path in the isolated lab, including
   repeated-fetch deduplication and unchanged Hype for advisory-only additions.
6. Keep per-feed results in `source_runs`, including errors and extracted counts.

The dated [probe and intake report](scoring-audit/2026-11-01-source-expansion.json)
records this validation. It is a snapshot, not an ongoing availability guarantee.

## Candidates not enabled by this change

- Red Hat RHSA RSS responded and returned entries, but its observed feed body
  did not contain CVE identifiers usable by the current reader. It needs a
  structured Security Data API/CSAF mapping adapter before admission. Adding
  that RSS URL alone would inflate the configured-source count without useful
  CVE enrichment.
- JVN RSS also returned entries without CVEs usable in the feed. It needs an
  explicit detail/structured-record adapter.
- The tested JPCERT English Atom URL returned HTTP 404; it is not configured.

The checks intentionally avoid guessing CVEs from product names or silently
classifying vendor notices as news. Increasing source coverage can still change
the amount of evidence available; it does not establish predictive calibration.
