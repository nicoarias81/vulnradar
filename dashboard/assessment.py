"""Evidence dimensions for the public view. No inference of victim counts."""
from datetime import datetime, timedelta, timezone
from html import escape
from urllib.parse import urlsplit

from core.reference_cases import case_for_cve
from core.scoring import exploit_ease


def _day(value):
    try:
        return datetime.fromisoformat(str(value).replace('Z','+00:00')).date()
    except (ValueError,TypeError):
        return None


def assessment(row, mentions, *, asof=None):
    today=_day(asof) if asof else datetime.now(timezone.utc).date()
    if today is None:
        raise ValueError('Invalid assessment date')
    recent=[m for m in mentions if m.get('kind')=='press' and (day:=_day(m.get('published'))) is not None
            and today-timedelta(days=30)<=day<=today]
    stories={m.get('story_key') or m.get('url') for m in recent}
    domains={str(m.get('domain') or urlsplit(m.get('url') or '').hostname or '').lower().removeprefix('www.') for m in recent}
    domains.discard('')
    if row.get('in_kev'):
        activity='Exploitation recorded in CISA KEV.'
    elif row.get('wild_confirmation'):
        activity='An exploitation observation from a configured trusted reporter is present.'
    elif row.get('exploitdb_poc_count') or row.get('validated_poc_count'):
        activity='Public PoC evidence is present; no trusted exploitation observation is recorded in these inputs.'
    elif row.get('poc_count'):
        activity=('Public exploit repositories reference this CVE, but none is validated; '
                  'no trusted exploitation observation is recorded in these inputs.')
    else:
        activity='No trusted exploitation observation is recorded in these inputs. This does not establish absence of exploitation.'
    vector=row.get('cvss_vector') or ''
    conditions=[]
    if exploit_ease(vector):
        metrics=dict(p.split(':') for p in vector.upper().split('/')[1:])
        conditions.append({'N':'network access','A':'adjacent access','L':'local access','P':'physical access'}[metrics['AV']])
        conditions.append({'N':'no prior privileges','L':'low privileges','H':'high privileges'}[metrics['PR']])
        conditions.append({'N':'no user interaction','R':'user interaction','P':'passive user interaction','A':'active user interaction'}[metrics['UI']])
        if metrics.get('AC')=='H' or metrics.get('AT')=='P':
            conditions.append('additional attack conditions')
    reference=case_for_cve(row.get('cve_id'),asof=today.isoformat())
    coverage_gap=bool(reference and not row.get('in_kev') and not row.get('wild_confirmation') and
                      any(n['kind'] in ('catalog_confirmation','confirmed_campaign') for n in reference['notes']))
    return {
        'asof':today.isoformat(),
        'attention':{'stories':len(stories),'documents':len(recent),'domains':sorted(domains)},
        'technical_conditions':', '.join(conditions) if conditions else 'Technical conditions are not available as a validated CVSS vector.',
        'activity':activity,
        'scope':'Global prevalence and successful-compromise counts are not quantified by these inputs. Neither KEV membership nor EPSS is a victim count.',
        'score_evaluated':str(row.get('calculated_at') or 'not available'),
        'epss_date':str(row.get('epss_date') or 'not available'),
        'reference':reference,
        'reference_coverage_gap':coverage_gap,
    }


def assessment_html(row, mentions, *, asof=None):
    view=assessment(row,mentions,asof=asof)
    attention=view['attention']
    dimensions=[
        ('Attention, last 30 days',f"{attention['stories']} distinct story titles; {attention['documents']} press documents; {len(attention['domains'])} publisher domains. These are coverage observations, not independent confirmations."),
        ('Technical potential',view['technical_conditions']+'. See the CNA/vendor description for the capability and affected configurations.'),
        ('Observed activity',view['activity']),
        ('Known scale',view['scope']),
    ]
    body=''.join(f'<div><dt>{escape(label)}</dt><dd class="muted">{escape(text)}</dd></div>' for label,text in dimensions)
    reference=view['reference']
    notes=''
    if reference:
        links=' · '.join(f'<a class="link" href="/cve?cve={escape(cve)}">{escape(cve)}</a>' for cve in reference['cves'])
        items=''.join(
            f'<li style="margin:12px 0"><b>{escape(n["available_on"])} · {escape(n["title"])}</b>'
            f'<p style="margin:4px 0">{escape(n["statement"])}</p><div class="muted">Scope: {escape(n["scope"])}</div>'
            f'<a class="link" href="{escape(n["url"])}" target="_blank" rel="noopener">{escape(n["source"])}</a></li>'
            for n in reference['notes'])
        notes=(f'<details class="expand"><summary>Dated reference: {escape(reference["name"])}</summary>'
               f'<p class="muted">Source notes through {escape(reference["asof"])}; editorial review {escape(reference["reviewed_on"])}. '
               'These notes do not override live scores or establish global absence of attacks.</p>'
               f'<p>{links}</p><ol>{items}</ol></details>')
        if reference['stale_review']:
            notes+='<p class="muted">This dated reference has not been reviewed through the current date; later developments may not be included.</p>'
        if view['reference_coverage_gap']:
            notes+='<p class="muted">Dated reference sources contain exploitation reports absent from the current input flags. Review source freshness before interpreting the score.</p>'
    return ('<section class="card" style="margin-bottom:16px" aria-labelledby="evidence-context">'
            '<h2 class="h3" id="evidence-context">Evidence in context</h2>'
            '<p class="muted">Attention, technical potential, observed activity and known scale are separate dimensions. '
            'An exploitation report does not establish that every headline was proportionate.</p>'
            f'<dl class="evidence-dimensions">{body}</dl><p class="muted">Score evaluated: {escape(view["score_evaluated"])} · EPSS snapshot: {escape(view["epss_date"])}</p>'
            f'{notes}</section>')
