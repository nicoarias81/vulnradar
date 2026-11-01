"""HTML for the three screens, aligned with the UI specs + mockups."""
from __future__ import annotations

from datetime import datetime
from html import escape
import math
from urllib.parse import urlencode
from core.labels import category_display

from dashboard.theme import (
    AGENT_COLORS,
    CATEGORY_BLURB,
    CATEGORY_COLORS,
    CATEGORY_DETAIL,
    CATEGORY_LABEL,
    SEVERITY_COLORS,
)

VTYPE_COLORS = {
    "RCE": "#EF4444",
    "AUTH BYPASS": "#A78BFA",
    "INFO DISCLOSURE": "#38BDF8",
    "XSS": "#22C55E",
    "PRIV ESC": "#A78BFA",
    "DoS": "#6B7280",
    "SQLi": "#F97316",
    "SSRF": "#818CF8",
    "OPEN REDIRECT": "#22D3EE",
}

FLAME_SVG = (
    '<svg class="flame" viewBox="0 0 32 32" aria-hidden="true">'
    '<path fill="#FF6B00" d="M16 2.2c.3 4.4-2.8 7-3.1 10.8 0 2 1.4 3.8 3.1 3.8s3.1-1.8 3.1-3.8c0-2.8 2.3-4.6 3.6-7.2 3.1 3.6 4.6 7.7 4.6 11.3 0 6.4-4.9 11.3-11.3 11.3S4.7 23.5 4.7 17.1C4.7 11.2 9.6 5.6 16 2.2z"/>'
    '<path fill="#FFB347" d="M16 16.8c.3 1.8-1 3-1.8 4.6 1 .14 1.8 2.2 1.8 2.2s1.8-1.3 2.6-3.2c-.8-2-2.1-2.9-2.6-3.6z"/>'
    "</svg>"
)

INFO_SVG = (
    '<svg class="info" viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">'
    '<circle cx="8" cy="8" r="6.5" fill="none" stroke="#64748B" stroke-width="1.4"/>'
    '<circle cx="8" cy="5.2" r="0.9" fill="#64748B"/>'
    '<rect x="7.3" y="7.2" width="1.4" height="5" rx="0.7" fill="#64748B"/>'
    "</svg>"
)

PAGE_CSS = """
:root {
  --bg: #0F172A; --card: #1E293B; --elevated: #334155; --text: #F8FAFC;
  --text-muted: #94A3B8; --hype: #FF6B00; --reality: #22D3EE;
  --overhyped: #EF4444; --earned: #22C55E; --sleeper: #EAB308;
  --quiet: #6B7280; --border: #334155; --plot: #0B1220;
}
* { box-sizing: border-box; }
html, body {
  margin: 0; padding: 0; background: var(--bg); color: var(--text);
  font-family: Inter, system-ui, -apple-system, sans-serif;
  color-scheme: dark;
}
a { color: inherit; }
.page { max-width: 1440px; margin: 0 auto; padding: 8px 24px 28px; }
.top {
  display: flex; align-items: center; justify-content: space-between;
  gap: 16px; min-height: 64px; height: auto; flex-wrap: wrap; margin-bottom: 16px;
}
.brand { display: flex; align-items: center; gap: 10px; text-decoration: none; flex-shrink: 0; }
.brandwrap { display: flex; align-items: center; gap: 14px; min-width: 0; }
.nan-chip { display: inline-flex; align-items: center; flex-shrink: 0; opacity: .7; transition: opacity .15s ease; }
.nan-chip:hover { opacity: 1; }
.nan-chip img { display: block; height: 18px; }
.flame { width: 40px; height: 40px; display: block; flex-shrink: 0; }
.title { font-size: 22px; font-weight: 700; margin: 0; color: var(--text); line-height: 1.1; white-space: nowrap; }
.title .humo { color: var(--hype); }
.sub { margin: 2px 0 0; color: var(--text-muted); font-size: 12px; }
.live { color: var(--text-muted); font-size: 12px; letter-spacing: .08em; text-transform: uppercase; white-space: nowrap; }
.live b { color: var(--earned); }
.live .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--earned); display: inline-block; margin: 0 6px 0 10px; box-shadow: 0 0 8px var(--earned); }
.filters { display: flex; gap: 14px; align-items: flex-end; margin-left: auto; }
.filter { display: flex; flex-direction: column; gap: 4px; min-width: 148px; }
.filter label {
  font-size: 11px; letter-spacing: .08em; text-transform: uppercase;
  color: var(--text-muted); font-weight: 600;
}
.filter select, .filter input[type="search"], .filter input[type="text"], .range {
  background: var(--bg); border: 1px solid var(--border); color: var(--text);
  border-radius: 8px; height: 36px; font: 13px Inter, sans-serif;
}
.filter select { padding: 0 12px; min-width: 148px; }
.filter input[type="search"] { padding: 0 12px; min-width: 210px; }
.filter input[type="text"] { padding: 0 30px 0 12px; min-width: 168px;
  background-image: url("data:image/svg+xml;utf8,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M1 1l4 4 4-4' fill='none' stroke='%238b98a7' stroke-width='1.6' stroke-linecap='round'/%3E%3C/svg%3E");
  background-repeat: no-repeat; background-position: right 11px center; }
.range {
  display: flex; align-items: center; gap: 6px; padding: 0 10px; min-width: 240px;
}
.range input {
  background: transparent; border: 0; color: var(--text); font: 13px Inter, sans-serif;
  color-scheme: dark; width: 118px; outline: none;
}
.range .sep { color: var(--text-muted); }
.row { display: grid; gap: 16px; }
.row-60 {
  grid-template-columns: minmax(0, 3fr) minmax(0, 2fr);
  align-items: stretch;
}
.dash-row { grid-template-rows: minmax(680px, calc(100vh - 190px)); }
.row-333 { grid-template-columns: minmax(0, 30fr) minmax(0, 35fr) minmax(0, 35fr); }
.row-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }
.card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: 12px; padding: 16px 18px;
}
.h3 {
  font-size: 12px; letter-spacing: .1em; text-transform: uppercase;
  color: var(--text); margin: 0; font-weight: 700; display: flex; align-items: center; gap: 6px;
}
.h3.accent { color: var(--hype); }
svg.info, .info { width: 14px; height: 14px; flex-shrink: 0; }
.h3 .info { opacity: .85; }
.muted { color: var(--text-muted); font-size: 13px; margin: 4px 0 10px; }
.scatter-card { display: flex; flex-direction: column; justify-content: space-between; min-height: 0; overflow: hidden; }
.scatter-body { display: grid; grid-template-columns: minmax(0, 1fr) 190px; gap: 4px 8px; flex: 1; min-height: 0; align-items: start; align-content: center; }
.plot { background: var(--plot); border-radius: 8px; display: block; width: 100%; height: auto; }
.table-card { display: flex; flex-direction: column; min-height: 0; overflow: hidden; }
.table-card > .h3, .table-card > .pager, .scatter-card > .h3, .scatter-card > .muted, .scatter-card > .note { flex-shrink: 0; }
.table-scroll { overflow-x: hidden; overflow-y: auto; flex: 1; min-height: 0; }
.table-scroll thead th { position: sticky; top: 0; background: var(--card); z-index: 1; }
.col-stack { display: flex; flex-direction: column; gap: 16px; min-height: 0; }
.col-stack > .card { min-height: 0; }
.col-stack > .acc-card { flex: 0 0 auto; }
.col-stack > .table-card:last-child { flex: 1 1 auto; }
.acc-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.acc-head .h3 { color: var(--hype); }
.acc-count { font-size: 11px; color: var(--text-muted); font-variant-numeric: tabular-nums; }
.acc-crit { font-size: 11px; color: var(--text-muted); margin: 4px 0 8px; }
.acc-table { font-size: 12.5px; }
.acc-table td { padding: 5px 6px; }
.sig { display: flex; gap: 4px; flex-wrap: wrap; }
.sig span {
  font-size: 10.5px; font-weight: 600; padding: 1px 6px; border-radius: 5px;
  white-space: nowrap; border: 1px solid transparent;
}
.sig .s-kev { background: rgba(239,68,68,.16); color: #F87171; border-color: rgba(239,68,68,.35); }
.sig .s-poc { background: rgba(255,107,0,.14); color: #FF8A3D; border-color: rgba(255,107,0,.32); }
.sig .s-epss { background: rgba(96,165,250,.14); color: #93C5FD; border-color: rgba(96,165,250,.32); }
.sig .s-none { color: var(--text-muted); border: 0; }
.reality-bar {
  display: inline-block; width: 34px; height: 4px; border-radius: 2px;
  background: #243044; vertical-align: middle; margin-right: 6px; overflow: hidden;
}
.reality-bar i { display: block; height: 100%; background: var(--reality); border-radius: 2px; }
.reality-num { font-size: 12px; color: var(--text-muted); font-variant-numeric: tabular-nums; }
.tl-strip { padding-top: 10px; border-top: 1px solid var(--border); }
.tl-strip .tl-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 2px; }
.tl-strip .tl-head .rng { font-size: 11px; color: var(--text-muted); font-variant-numeric: tabular-nums; }
.tl-strip .tl-head .mini { display: flex; align-items: center; gap: 10px; font-size: 10.5px; color: var(--text-muted); }
.tl-strip .tl-head .mini i { width: 6px; height: 6px; border-radius: 50%; display: inline-block; margin-right: 4px; }
.tl-strip .tl-head .mini .h { background: var(--hype); }
.tl-strip .tl-head .mini .r { background: var(--reality); }
.tl-strip .tl-svg { display: block; width: 100%; height: 78px; }
.plot-wrap { position: relative; width: 100%; }
.plot-wrap a { cursor: pointer; }
.plot-tip {
  position: absolute; z-index: 6; min-width: 170px; max-width: 260px;
  background: #1E293B; border: 1px solid #475569; border-radius: 8px;
  padding: 8px 10px; font-size: 12px; color: var(--text);
  box-shadow: 0 10px 28px rgba(0,0,0,.45); pointer-events: none;
}
.plot-tip b { display: block; font-size: 13px; font-variant-numeric: tabular-nums; }
.plot-tip .name { color: var(--hype); font-weight: 700; margin: 2px 0 4px; }
.plot-tip .meta { color: var(--text-muted); margin-top: 2px; }
.brand-name { display: block; color: var(--hype); font-size: 12px; font-weight: 600; margin-top: 2px; }
.brand-hero { color: var(--hype); font-size: 18px; font-weight: 700; margin: 0 0 6px; }
.legend { display: flex; flex-direction: column; gap: 14px; justify-content: center; padding: 8px 4px 8px 8px; }
.legend b { font-size: 13px; font-weight: 600; }
.legend .muted { font-size: 11px; margin: 2px 0 0; }
.note {
  border: 1px solid var(--border); border-radius: 8px;
  padding: 8px 12px; color: var(--text-muted); font-size: 12px; margin-top: 12px;
  display: flex; align-items: center; gap: 8px;
}
.note .info { flex-shrink: 0; }
.table { width: 100%; border-collapse: collapse; font-size: 14px; }
.table th {
  text-align: left; color: var(--text-muted); font-size: 11px; letter-spacing: .08em;
  text-transform: uppercase; padding: 8px 6px; border-bottom: 1px solid var(--border); font-weight: 600;
}
.table td { padding: 10px 6px; border-bottom: 1px solid var(--border); vertical-align: middle; }
.table td:first-child { white-space: nowrap; }
.table tr:hover td { background: var(--elevated); }
a.link { color: #60A5FA; text-decoration: none; font-weight: 600; font-variant-numeric: tabular-nums; }
a.link:hover { text-decoration: underline; }
.badge {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 3px 10px; border-radius: 999px;
  font-size: 11px; font-weight: 700; letter-spacing: .04em; white-space: nowrap;
}
.badge .pip { width: 7px; height: 7px; border-radius: 50%; display: inline-block; }
.pager {
  display: flex; justify-content: space-between; align-items: center;
  margin-top: 12px; color: var(--text-muted); font-size: 12px;
}
.pager .viewall { color: #60A5FA; text-decoration: none; font-weight: 600; }
.pager .viewall:hover { text-decoration: underline; }
.pager a.nav, .pager span.disabled {
  display: inline-flex; align-items: center; justify-content: center;
  width: 32px; height: 28px; border: 1px solid var(--border); border-radius: 8px;
  color: var(--text); text-decoration: none; background: var(--bg);
}
.pager span.disabled { opacity: .35; }

.tl-legend { text-align: center; margin: 6px 0 0; font-size: 12px; color: var(--text-muted); }
.tl-legend .h { color: var(--hype); }
.tl-legend .r { color: var(--reality); }
.tl-mark { cursor: pointer; }
.tl-mark:hover circle { stroke-width: 2.8; }
.tl-mark text { font-weight: 700; letter-spacing: .01em; }
.tl-chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
.tl-chip {
  display: inline-flex; align-items: center; gap: 7px;
  padding: 5px 10px; border: 1px solid #334155; border-radius: 999px;
  background: #0F172A; color: #E2E8F0; text-decoration: none; font-size: 12px;
  transition: border-color .15s ease, transform .15s ease;
}
.tl-chip i { width: 8px; height: 8px; border-radius: 50%; background: var(--c, #FF6B00); flex: none; }
.tl-chip b { font-weight: 700; color: var(--c, #E2E8F0); }
.tl-chip span { font-family: ui-monospace, monospace; font-size: 11px; color: #94A3B8; }
.tl-chip em { font-style: normal; font-size: 11px; color: #94A3B8; }
.tl-chip:hover { border-color: var(--c, #FF6B00); transform: translateY(-1px); }
.tl-note { color: #64748B; font-size: 11px; margin: 6px 0 0; }
.dia .tip { opacity: 0; transition: opacity .12s ease; }
.dia:hover .tip { opacity: 1; }
.back {
  display: inline-flex; align-items: center; gap: 6px;
  color: var(--text); text-decoration: none; font-size: 13px; font-weight: 600;
  border: 1px solid var(--border); background: var(--card); border-radius: 8px;
  padding: 6px 12px; margin: 0 0 12px;
}
.back:hover { border-color: var(--hype); color: var(--hype); }
.cve-title { display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; margin: 0 0 16px; }
.cve-title h1 { margin: 0 0 6px; font-size: 28px; font-weight: 700; font-variant-numeric: tabular-nums; }
.badges { display: flex; gap: 8px; flex-wrap: wrap; padding-top: 6px; }
.hype-row {
  background: var(--bg); border: 1px solid var(--border); border-radius: 10px;
  padding: 10px 12px; margin: 8px 0;
  display: grid; grid-template-columns: 22px 1fr auto; gap: 6px 8px; align-items: center;
}
.bar-wrap { background: var(--elevated); border-radius: 6px; height: 8px; grid-column: 2 / -1; }
.bar { height: 8px; border-radius: 6px; background: linear-gradient(90deg, #FF6B00, #FB923C); }
.hype-row .lbl { font-size: 11px; letter-spacing: .06em; text-transform: uppercase; color: var(--text-muted); }
.hype-row .val { font-variant-numeric: tabular-nums; font-weight: 700; font-size: 13px; }
.hype-total {
  display: flex; justify-content: space-between; align-items: center;
  background: rgba(255,107,0,.08); border: 1px solid rgba(255,107,0,.35);
  border-radius: 10px; padding: 12px 14px; margin-top: 12px;
  color: var(--hype); font-weight: 700; letter-spacing: .08em;
}
.hype-total b { font-size: 22px; font-variant-numeric: tabular-nums; }
.score { font-size: 56px; font-weight: 700; line-height: 1; font-variant-numeric: tabular-nums; }
.score small { font-size: 16px; color: var(--text-muted); font-weight: 600; }
.score-row { display: flex; margin: 20px 0 24px; }
.score-col { flex: 1; padding: 0 12px; }
.score-col + .score-col { border-left: 1px solid var(--border); }
.hype { color: var(--hype); }
.reality { color: var(--reality); }
.banner {
  border: 1px solid rgba(255,107,0,.45); background: rgba(255,107,0,.08);
  border-radius: 12px; padding: 14px 16px;
}
.banner strong { color: var(--hype); letter-spacing: .06em; font-size: 16px; display: flex; align-items: center; gap: 6px; }
.foot-note { color: var(--text-muted); font-size: 12px; margin-top: 14px; display: flex; gap: 6px; align-items: flex-start; }
.tl { border-left: 2px solid var(--reality); margin: 8px 0 4px 7px; padding-left: 16px; }
.tl-item { position: relative; margin: 0 0 14px; }
.tl-item::before {
  content: ""; position: absolute; left: -21px; top: 5px;
  width: 10px; height: 10px; border-radius: 50%; background: var(--reality);
  box-shadow: 0 0 0 3px rgba(34,211,238,.18);
}
.agent-head { display: flex; align-items: center; gap: 10px; }
/* Mentions and PoCs: expandable list without JS */
.mention { margin: 8px 0; }
.mention a { text-decoration: none; }
.mention a:hover { text-decoration: underline; }
details.expand { margin-top: 10px; border-top: 1px solid var(--border); padding-top: 8px; }
details.expand > summary {
  cursor: pointer; color: var(--hype); font-size: 12px; letter-spacing: .04em;
  list-style: none; display: flex; align-items: center; gap: 6px;
}
details.expand > summary::-webkit-details-marker { display: none; }
details.expand > summary::before { content: "▸"; transition: transform .15s; }
details.expand[open] > summary::before { transform: rotate(90deg); }
details.expand > summary:hover { text-decoration: underline; }
table.mini { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 12px; }
table.mini th {
  text-align: left; font-weight: 600; color: var(--text-muted); font-size: 10px;
  letter-spacing: .08em; text-transform: uppercase; padding: 4px 6px;
  border-bottom: 1px solid var(--border);
}
table.mini td { padding: 5px 6px; border-bottom: 1px solid rgba(255,255,255,.04); }
table.mini td.num { text-align: right; font-variant-numeric: tabular-nums; color: var(--hype); font-weight: 600; }
table.mini tr:hover td { background: rgba(255,255,255,.03); }
.agent-icon {
  width: 40px; height: 40px; border-radius: 50%;
  display: flex; align-items: center; justify-content: center; flex-shrink: 0;
}
.agent-icon svg { width: 20px; height: 20px; }
.dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 6px; }
.ok { background: var(--earned); box-shadow: 0 0 8px var(--earned); }
.stale { background: var(--sleeper); }
.err { background: var(--overhyped); }
.progress-row { display: flex; align-items: center; gap: 10px; margin: 10px 0 8px; }
.progress { background: var(--elevated); border-radius: 99px; height: 6px; flex: 1; }
.progress > span { display: block; height: 6px; border-radius: 99px; }
.progress-pct { color: var(--text-muted); font-size: 11px; letter-spacing: .06em; white-space: nowrap; }
.metrics {
  display: grid; grid-template-columns: 1fr 1fr; gap: 8px;
  border-top: 1px solid var(--border); padding-top: 10px; margin-top: 8px;
}
.metrics b { display: block; font-size: 18px; font-variant-numeric: tabular-nums; }
.metrics span { font-size: 11px; letter-spacing: .06em; text-transform: uppercase; color: var(--text-muted); }
.spark { display: block; width: 100%; height: 32px; margin: 8px 0 0; }
.footer {
  display: flex; justify-content: space-between; align-items: center; gap: 12px;
  color: var(--text-muted); font-size: 12px; margin-top: 16px;
}
.foot-right { display: flex; align-items: center; }
.foot-right img { display: block; opacity: .75; transition: opacity .15s ease; }
.foot-right img:hover { opacity: 1; }
.ico { width: 16px; height: 16px; display: inline-block; vertical-align: -3px; }
.empty { color: var(--text-muted); padding: 40px 8px; text-align: center; }
.callout {
  position: absolute; right: 18px; bottom: 28px;
  border: 1px solid var(--border); background: var(--card);
  border-radius: 8px; padding: 8px 10px; font-size: 11px; color: var(--text-muted);
}
.callout b { color: var(--hype); font-size: 16px; display: block; }
.mini-wrap { position: relative; }
.log-row { display: grid; grid-template-columns: 70px 40px 56px 140px 1fr; gap: 10px; padding: 7px 0; border-bottom: 1px solid var(--border); font-size: 13px; }
.log-row .lvl-INFO { color: var(--text-muted); }
.log-row .lvl-WARN { color: var(--hype); }
.log-row .lvl-ERROR { color: var(--overhyped); }
.log-row .lvl-DEBUG { color: #64748B; }
.feed-foot { color: var(--text-muted); font-size: 12px; margin-top: 10px; }
.live a { color: var(--text-muted); text-decoration: none; margin-left: 12px; text-transform: none; letter-spacing: 0; font-weight: 600; }
.live a:hover { color: var(--hype); }
.login-card { max-width: 400px; margin: 72px auto; }
.login-card .filter { min-width: 0; margin: 12px 0; }
.login-card input[type="text"], .login-card input[type="password"] {
  background: var(--bg); border: 1px solid var(--border); color: var(--text);
  border-radius: 8px; height: 40px; padding: 0 12px; width: 100%;
  font: 14px Inter, sans-serif;
}
.login-card button {
  margin-top: 8px; width: 100%; height: 40px; border: 0; border-radius: 8px;
  background: var(--hype); color: #fff; font-weight: 700; cursor: pointer; font-size: 14px;
}
.login-error { color: var(--overhyped); font-size: 13px; margin: 0 0 12px; }
/* Header controls use their own fluid grid: never compete with the brand. */
.overview-top { display: grid; grid-template-columns: minmax(0,1fr); gap: 12px; padding: 8px 0; }
.row > *, .card, .col-stack, .table-scroll { min-width: 0; }
.overview-top .brandwrap { flex-wrap: wrap; gap: 8px 14px; }
.filters { display: grid; width: 100%; margin-left: 0; gap: 12px;
  grid-template-columns: minmax(160px,1.1fr) minmax(260px,1.4fr) minmax(120px,.8fr) minmax(140px,1fr) minmax(220px,1.5fr); }
.filter, .filter select, .filter input[type="search"], .filter input[type="text"] { min-width: 0; width: 100%; }
.filter select { text-overflow: ellipsis; }
.range { min-width: 0; width: 100%; }
.range input { flex: 1; min-width: 0; width: 100%; }
.attention-pager { border-top: 1px solid var(--border); padding-top: 8px; margin-top: 8px; flex-shrink: 0; gap: 8px; flex-wrap: wrap; }
.acc-card .acc-table td { padding: 6px; }
.acc-card .sig span { line-height: 1.25; padding: 2px 5px; font-size: 10px; }
.pager-controls { display: flex; gap: 6px; }
#attention-queue { scroll-margin-top: 12px; }
/* Detail: useful cards first; long prose is progressive disclosure. */
.detail-page .top { margin-bottom: 8px; }
.detail-page .live { white-space: normal; text-align: right; line-height: 1.5; }
.detail-page .cve-title > div { min-width: 0; }
.detail-page .cve-title h1 { font-size: 25px; }
.cve-summary { max-width: 100ch; line-height: 1.5; margin-bottom: 4px; }
.description-details { margin: 4px 0 10px; }
.description-details > summary, .context-disclosure > summary { cursor: pointer; color: var(--text-muted); font-size: 12px; }
.full-description { white-space: pre-wrap; overflow-wrap: anywhere; font: inherit; font-size: 13px; color: var(--text-muted); line-height: 1.6; }
.detail-grid { display: grid; gap: 16px; grid-template-columns: minmax(0,1fr) minmax(0,1fr) minmax(0,1.1fr);
  grid-template-areas: 'summary components sources' 'history history pocs'; align-items: stretch; }
.detail-grid > .card { min-width: 0; }
.detail-summary { grid-area: summary; }
.detail-components { grid-area: components; }
.detail-sources { grid-area: sources; }
.detail-history { grid-area: history; }
.detail-pocs { grid-area: pocs; }
.detail-scroll { max-height: 244px; overflow: auto; overscroll-behavior: contain; padding-right: 6px; margin-top: 8px; }
.detail-grid a.link { overflow-wrap: anywhere; }
.detail-summary .score { font-size: 46px; }
.detail-summary .score-row { margin: 16px 0; }
.detail-summary .score-col { padding: 0 8px; }
.detail-summary .banner { padding: 10px 12px; }
.detail-summary .banner strong { font-size: 12px; letter-spacing: .03em; }
.detail-summary .banner .muted { font-size: 12px; line-height: 1.5; }
.detail-summary .foot-note { margin-top: 8px; font-size: 11px; }
.detail-history { min-height: 190px; }
.chart-scroll { overflow-x: auto; margin-top: 12px; }
.chart-scroll .tl-svg { width: 100%; min-width: 520px; display: block; }
.context-disclosure { margin-top: 16px; }
.context-disclosure > summary { color: var(--text); font-weight: 600; font-size: 13px; }
.context-disclosure > .card { border: 0; background: transparent; padding: 12px 0 0; margin-bottom: 0 !important; }
.evidence-dimensions { display: grid; grid-template-columns: repeat(2,minmax(0,1fr)); gap: 12px 20px; }
.evidence-dimensions dt { font-size: 12px; font-weight: 700; }
.evidence-dimensions dd { margin: 4px 0 0; line-height: 1.5; }
@media (max-width: 1100px) {
  .row-60, .row-333, .row-4 { grid-template-columns: 1fr; }
  .row-60, .dash-row { grid-template-rows: auto; }
  .filters { grid-template-columns: repeat(3,minmax(0,1fr)); }
  .filter-category { grid-column: span 2; }
  .scatter-body { grid-template-columns: minmax(0,1fr) 190px; }
  .table-card { max-height: 520px; }
  .detail-grid { grid-template-columns: repeat(2,minmax(0,1fr)); grid-template-areas: 'summary components' 'history history' 'sources pocs'; }
}
@media (max-width: 700px) {
  .page { padding: 8px 16px 24px; }
  .filters { grid-template-columns: repeat(2,minmax(0,1fr)); }
  .filter-search, .filter-dates, .filter-category { grid-column: span 2; }
  .top { gap: 10px; }
  .detail-page .live { font-size: 10px; text-align: left; }
  .detail-page .cve-title { flex-direction: column; gap: 6px; }
  .detail-page .cve-title h1 { font-size: 23px; overflow-wrap: anywhere; }
  .detail-grid { grid-template-columns: minmax(0,1fr); grid-template-areas: 'summary' 'components' 'history' 'sources' 'pocs'; }
  .evidence-dimensions { grid-template-columns: minmax(0,1fr); }
  .scatter-body { grid-template-columns: minmax(0,1fr); }
  .legend { display: grid; grid-template-columns: repeat(2,minmax(0,1fr)); padding-left: 0; }
  .tl-strip .tl-head { flex-wrap: wrap; gap: 6px; }
  .table-scroll { overflow-x: auto; }
  .table { font-size: 12px; }
  .badge { font-size: 10px; padding: 3px 6px; }
  .footer { flex-wrap: wrap; }
}

"""


def document(body: str, *, refresh: int | None = None, track: bool | None = None) -> str:
    meta = f'<meta http-equiv="refresh" content="{int(refresh)}">' if refresh else ""
    # Auto-refresh views (/soc reloads every 8s) count every reload as
    # a visit and eat half the Umami metrics: they are not tracked.
    if track is None:
        track = refresh is None
    analytics = (
        '<script defer src="https://analytics.munalabs.eu/script.js" '
        'data-website-id="2f0e03ec-fd86-48cd-b7d0-c916b987c564"></script>'
        if track else ""
    )
    return (
        "<!DOCTYPE html><html lang='en'><head>"
        '<meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"{meta}"
        "<title>VulnRadar — Hype vs Reality</title>"
        '<link rel="preconnect" href="https://fonts.googleapis.com">'
        '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">'
        f"{analytics}"
        f"<style>{PAGE_CSS}</style></head><body>{body}"
        "<script>(function(){"
        "var pi=document.getElementById('product-filter'),pl=document.getElementById('product-list');"
        "if(pi&&pl){var t=null,last='';"
        "pi.addEventListener('input',function(){var q=pi.value.trim();"
        "if(q===last)return;last=q;clearTimeout(t);"
        "if(q.length<2){pl.replaceChildren();return;}"
        "t=setTimeout(function(){fetch('/api/products?q='+encodeURIComponent(q))"
        ".then(function(r){return r.json();}).then(function(rows){"
        "pl.replaceChildren();(rows||[]).forEach(function(row){"
        "var o=document.createElement('option');o.value=row.p;pl.appendChild(o);});})"
        ".catch(function(){});},160);});}"
        "var f=document.getElementById('filters');if(f){"
        "f.querySelectorAll('select,input').forEach(function(el){el.addEventListener('change',function(){f.submit();});});}"
        "var b=document.getElementById('back-dash');"
        "if(b){b.addEventListener('click',function(e){if(history.length>1){e.preventDefault();history.back();}});}"
        "document.querySelectorAll('.plot-wrap').forEach(function(wrap){"
        "var tip=wrap.querySelector('.plot-tip');if(!tip)return;"
        "function fill(el){tip.replaceChildren();var t=document.createElement('b');t.textContent=el.getAttribute('data-cve')||'';"
        "tip.appendChild(t);var n=el.getAttribute('data-name');if(n){var d=document.createElement('div');d.className='name';d.textContent=n;tip.appendChild(d);}"
        "var m=document.createElement('div');m.className='meta';"
        "m.textContent='Hype '+(el.getAttribute('data-hype')||'—')+' · Reality '+(el.getAttribute('data-reality')||'—');"
        "tip.appendChild(m);var c=el.getAttribute('data-cat');if(c){var k=document.createElement('div');k.className='meta';k.textContent=c;tip.appendChild(k);}"
        "tip.hidden=false;}"
        "wrap.addEventListener('pointerover',function(e){var el=e.target.closest('[data-cve]');if(el)fill(el);});"
        "wrap.addEventListener('pointermove',function(e){if(tip.hidden)return;var r=wrap.getBoundingClientRect();"
        "var x=e.clientX-r.left+14,y=e.clientY-r.top+14;if(x+190>r.width)x=e.clientX-r.left-200;if(y+90>r.height)y=e.clientY-r.top-100;"
        "tip.style.left=x+'px';tip.style.top=y+'px';});"
        "wrap.addEventListener('pointerout',function(e){if(!wrap.contains(e.relatedTarget))tip.hidden=true;});"
        "});"
        "})();</script>"
        "</body></html>"
    )


def logo(subtitle: str = "") -> str:
    sub = f'<p class="sub">{escape(subtitle)}</p>' if subtitle else ""
    return (
        '<div class="brandwrap">'
        f'<a class="brand" href="/">{FLAME_SVG}<div>'
        '<p class="title">Vuln<span class="humo">Radar</span></p>'
        f"{sub}</div></a>"
        '<a class="nan-chip" href="https://nan.builders/?ref=built-with-nan" '
        'target="_blank" rel="noopener" title="Built with NaN">'
        '<img src="https://nan.builders/badge/built-with-nan-compact.svg" '
        'alt="Built with NaN" height="18"></a>'
        "</div>"
    )


def badge(text: str, color: str, *, pip: bool = True) -> str:
    pip_html = f'<span class="pip" style="background:{color}"></span>' if pip else ""
    return (
        f'<span class="badge" style="background:{color}22;color:{color};'
        f'border:1px solid {color}55">{pip_html}{escape(text)}</span>'
    )


def _opt(value: str, label: str, current: str) -> str:
    sel = " selected" if value == current else ""
    return f'<option value="{escape(value)}"{sel}>{escape(label)}</option>'


def _qs(base: str, **params) -> str:
    clean = {
        k: v for k, v in params.items()
        if v not in (None, "", "All severities", "All categories", "All products", "0")
    }
    q = urlencode(clean)
    return f"{base}?{q}" if q else base


def _icon(kind: str) -> str:
    paths = {
        "shield": '<path fill="#94A3B8" d="M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5l8-3z"/>',
        "clock": '<circle cx="12" cy="12" r="9" fill="none" stroke="#94A3B8" stroke-width="2"/><path fill="none" stroke="#94A3B8" stroke-width="2" d="M12 7v6l4 2"/>',
        "bolt": '<path fill="#94A3B8" d="M13 2L4 14h7l-1 8 10-14h-7z"/>',
        "tag": '<path fill="none" stroke="#94A3B8" stroke-width="2" d="M3 12l9-9h7v7l-9 9-7-7z"/><circle cx="16.5" cy="7.5" r="1.2" fill="#94A3B8"/>',
        "git": '<circle cx="12" cy="6" r="2.2" fill="#94A3B8"/><circle cx="7" cy="18" r="2.2" fill="#94A3B8"/><circle cx="17" cy="18" r="2.2" fill="#94A3B8"/><path fill="none" stroke="#94A3B8" stroke-width="2" d="M12 8v4M12 12H7v4M12 12h5v4"/>',
        "flame": FLAME_SVG.replace('class="flame"', 'class="ico"'),
    }
    if kind == "flame":
        return paths["flame"]
    return f'<svg class="ico" viewBox="0 0 24 24" aria-hidden="true">{paths.get(kind, "")}</svg>'


def agent_icon_svg(key: str, color: str) -> str:
    inner = {
        "sync": f'<path fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" d="M20 12a8 8 0 1 1-2.2-5.5M20 4v6h-6"/>',
        "enrich": (
            f'<ellipse cx="12" cy="7" rx="7" ry="3" fill="none" stroke="{color}" stroke-width="2"/>'
            f'<path fill="none" stroke="{color}" stroke-width="2" d="M5 7v10c0 1.7 3.1 3 7 3s7-1.3 7-3V7"/>'
        ),
        "score": f'<path fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" d="M4 12h3l3-7 4 14 3-7h3"/>',
        "alert": (
            f'<path fill="none" stroke="{color}" stroke-width="2" d="M6 16v-5a6 6 0 1 1 12 0v5l1.5 2H4.5L6 16z"/>'
            f'<path fill="none" stroke="{color}" stroke-width="2" d="M10 20a2 2 0 0 0 4 0"/>'
        ),
    }.get(key, f'<circle cx="12" cy="12" r="5" fill="{color}"/>')
    return (
        f'<div class="agent-icon" style="background:{color}22;border:1px solid {color}55">'
        f'<svg viewBox="0 0 24 24" aria-hidden="true">{inner}</svg></div>'
    )


def _xy(value: float, lo: float, hi: float, start: float, size: float, *, invert: bool = False) -> float:
    span = max(hi - lo, 0.001)
    t = (float(value) - lo) / span
    t = 0 if t < 0 else 1 if t > 1 else t
    return start + (1 - t) * size if invert else start + t * size


def scatter_svg(rows, width: int = 520, height: int = 340, *, mode: str = "category") -> str:
    l, t, r, b = 52, 12, 12, 44
    pw, ph = width - l - r, height - t - b
    grid = []
    if mode == "split":
        labels = [(0, "LOW"), (5, "MEDIUM"), (10, "HIGH")]
        for val, lab in labels:
            x = _xy(val, 0, 10, l, pw)
            y = _xy(val, 0, 10, t, ph, invert=True)
            grid.append(f'<line x1="{l}" y1="{y:.1f}" x2="{l+pw}" y2="{y:.1f}" stroke="#334155" stroke-width="1"/>')
            grid.append(f'<line x1="{x:.1f}" y1="{t}" x2="{x:.1f}" y2="{t+ph}" stroke="#334155" stroke-width="1"/>')
            grid.append(f'<text x="{x:.1f}" y="{t+ph+18}" fill="#94A3B8" font-size="11" text-anchor="middle">{lab}</text>')
            grid.append(f'<text x="{l-8}" y="{y+4:.1f}" fill="#94A3B8" font-size="11" text-anchor="end">{lab}</text>')
        xlab, ylab = "HYPE (ATTENTION)", "REALITY (THREAT INDEX)"
    else:
        for i in range(0, 11, 2):
            x = _xy(i, 0, 10, l, pw)
            y = _xy(i, 0, 10, t, ph, invert=True)
            grid.append(f'<line x1="{l}" y1="{y:.1f}" x2="{l+pw}" y2="{y:.1f}" stroke="#334155" stroke-width="1"/>')
            grid.append(f'<line x1="{x:.1f}" y1="{t}" x2="{x:.1f}" y2="{t+ph}" stroke="#334155" stroke-width="1"/>')
            grid.append(f'<text x="{x:.1f}" y="{t+ph+18}" fill="#94A3B8" font-size="11" text-anchor="middle">{i}</text>')
            grid.append(f'<text x="{l-8}" y="{y+4:.1f}" fill="#94A3B8" font-size="11" text-anchor="end">{i}</text>')
        xlab, ylab = "REALITY (Observed Impact)", "HYPE (Perceived Buzz)"
    dots = []
    high_low = 0
    cat_rank = {"Quiet": 0, "Sleeper": 1, "Earned the hype": 2, "Overhyped": 3}
    plot_rows = sorted(
        list(rows)[:400],
        key=lambda row: (
            1 if str(row.get("brand_name") or "").strip() else 0,
            cat_rank.get(row.get("category") or "Quiet", 0),
        ),
    )
    for row in plot_rows:
        hype = float(row.get("hype") or 0)
        reality = float(row.get("reality") or 0)
        if hype >= 6.6 and reality <= 3.3:
            high_low += 1
        if mode == "split":
            color = "#FF6B00" if hype > reality else "#22D3EE"
            cx = _xy(hype, 0, 10, l, pw)
            cy = _xy(reality, 0, 10, t, ph, invert=True)
        else:
            cat = row.get("category") or "Quiet"
            color = CATEGORY_COLORS.get(cat, "#6B7280")
            cx = _xy(reality, 0, 10, l, pw)
            cy = _xy(hype, 0, 10, t, ph, invert=True)
        cve = escape(str(row.get("cve_id") or ""), quote=True)
        brand = escape(str(row.get("brand_name") or "").strip(), quote=True)
        cat = escape(category_display(row.get("category")), quote=True)
        href = f"/cve?cve={cve}"
        dots.append(
            f'<a href="{href}" data-cve="{cve}" data-name="{brand}" '
            f'data-hype="{hype:.1f}" data-reality="{reality:.1f}" data-cat="{cat}">'
            f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="9" fill="transparent"/>'
            f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="5" fill="{color}" fill-opacity="0.92"/>'
            "</a>"
        )
    extra = ""
    if mode != "split":
        x0, y0 = _xy(0, 0, 10, l, pw), _xy(0, 0, 10, t, ph, invert=True)
        x1, y1 = _xy(10, 0, 10, l, pw), _xy(10, 0, 10, t, ph, invert=True)
        extra = f'<line x1="{x0:.1f}" y1="{y0:.1f}" x2="{x1:.1f}" y2="{y1:.1f}" stroke="#94A3B8" stroke-dasharray="5 4"/>'
    svg = (
        f'<div class="plot-wrap"><svg class="plot" viewBox="0 0 {width} {height}" width="100%" height="{height}" preserveAspectRatio="xMidYMid meet" role="img">'
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#0B1220"/>'
        f"{''.join(grid)}{extra}{''.join(dots)}"
        f'<text x="{l+pw/2:.1f}" y="{height-6}" fill="#94A3B8" font-size="11" text-anchor="middle">{xlab}</text>'
        f'<text x="14" y="{t+ph/2:.1f}" fill="#94A3B8" font-size="11" text-anchor="middle" '
        f'transform="rotate(-90 14 {t+ph/2:.1f})">{ylab}</text>'
        '</svg><div class="plot-tip" hidden></div></div>'
    )
    if mode == "split" and rows:
        ratio = 100.0 * high_low / max(len(rows), 1)
        pct = f"{ratio:.0f}%" if ratio >= 1 else (f"{ratio:.1f}%" if high_low else "0%")
        svg = (
            f'<div class="mini-wrap">{svg}'
            f'<div class="callout"><b>{high_low} ({pct})</b>HIGH HYPE / LOW REALITY</div></div>'
        )
    return svg


def sparkline_svg(values, color: str, width: int = 160, height: int = 32) -> str:
    if not values:
        values = [0.2] * 12
    n = max(len(values) - 1, 1)
    pts = []
    for i, raw in enumerate(values):
        x = i / n * (width - 4) + 2
        y = (1 - max(0, min(1, float(raw)))) * (height - 6) + 3
        pts.append(f"{x:.1f},{y:.1f}")
    return (
        f'<svg class="spark" viewBox="0 0 {width} {height}" width="100%" height="{height}" aria-hidden="true">'
        f'<polyline fill="none" stroke="{color}" stroke-width="2" stroke-linejoin="round" '
        f'stroke-linecap="round" points="{" ".join(pts)}"/></svg>'
    )


def _nice_ceiling(pico: float) -> float:
    """Axis ceiling with a readable, fine step: 1.4 -> 2, 3.4 -> 4, 9.2 -> 10, 47 -> 50."""
    if pico <= 0:
        return 10.0
    objetivo = pico * 1.08
    exp = math.floor(math.log10(objetivo))
    for k in (exp - 1, exp, exp + 1):
        for factor in (1, 1.5, 2, 2.5, 3, 4, 5, 10):
            paso = factor * 10 ** k
            if paso * 5 >= objetivo:
                return float(round(paso * 5, 4))
    return float(round(10 ** (exp + 2) * 5, 4))


def _fecha_larga(day: str) -> str:
    try:
        dt = datetime.strptime(str(day)[:10], "%Y-%m-%d")
        return dt.strftime("%d %b %Y")
    except ValueError:
        return str(day)[:10]


def timeline_svg(series, highlights=None, width: int = 1200, height: int = 220,
                 compact: bool = False) -> str:
    if not series:
        return '<p class="muted">No publication dates to build the series.</p>'
    highlights = highlights or []
    l, t, r, b = 44, 26, 16, 40
    pw, ph = width - l - r, height - t - b
    dates = [item["date"] for item in series]
    n = max(len(dates) - 1, 1)

    def smooth(key):
        raw = [float(item.get(key) or 0) for item in series]
        out = []
        for i, val in enumerate(raw):
            chunk = raw[max(0, i - 1) : i + 2]
            out.append(sum(chunk) / len(chunk))
        return out

    # Auto-zoom: the axis hugs the real range. With a fixed 0-10 (or 0-ceiling) the
    # daily averages, which live between 0.3 and 2, stayed glued to the floor.
    hype_vals, reality_vals = smooth("hype"), smooth("reality")
    if compact:
        # Strip at the bottom of the scatter: no highlights or value axis, only the
        # shape of the two series and three reference dates.
        l, r, t, b = 12, 12, 6, 18
        pw, ph = width - l - r, height - t - b
        techo = max(hype_vals + reality_vals + [0.1]) * 1.15

        def px(i):
            return l + (i / n) * pw

        def py(val):
            return t + ph - (max(0.0, val) / techo) * ph

        def linea(vals, color):
            pts = " ".join(f"{px(i):.1f},{py(v):.1f}" for i, v in enumerate(vals))
            return (f'<polyline points="{pts}" fill="none" stroke="{color}" '
                    'stroke-width="1.8" stroke-linejoin="round" stroke-linecap="round"/>')

        ultimo = len(dates) - 1
        ticks = []
        for i in (0, ultimo // 2, ultimo):
            anchor = "start" if i == 0 else ("end" if i == ultimo else "middle")
            ticks.append(
                f'<text x="{px(i):.1f}" y="{height - 4}" fill="#8b98a7" '
                f'font-size="10" text-anchor="{anchor}">{escape(str(dates[i])[5:])}</text>'
            )
        return (
            f'<svg class="tl-svg" viewBox="0 0 {width} {height}" role="img" '
            f'aria-label="Score evolution">'
            f'<line x1="{l}" y1="{t + ph}" x2="{l + pw}" y2="{t + ph}" stroke="#243044"/>'
            + linea(hype_vals, "#FF6B00") + linea(reality_vals, "#22C55E")
            + "".join(ticks) + "</svg>"
        )
    all_vals = hype_vals + reality_vals
    peak = max(all_vals + [0.0])
    floor_val = min(all_vals + [0.0])
    techo = _nice_ceiling(peak)
    base = 0.0
    if techo > 0 and (peak - floor_val) / techo < 0.5:
        paso = techo / 5
        base = max(0.0, math.floor(max(0.0, floor_val - paso) / paso) * paso)
    alto = max(techo - base, 0.1)

    def y_de(val):
        return _xy(max(0.0, float(val) - base), 0, alto, t, ph, invert=True)

    def points(vals):
        return [(l + (i / n) * pw, y_de(val)) for i, val in enumerate(vals)]

    def polyline(vals, color):
        pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in points(vals))
        return f'<polyline fill="none" stroke="{color}" stroke-width="2.6" stroke-linejoin="round" stroke-linecap="round" points="{pts}"/>'

    ticks = []
    step = max(1, len(dates) // 6)
    for i, day in enumerate(dates):
        if i % step != 0 and i != len(dates) - 1:
            continue
        x = l + (i / n) * pw
        ticks.append(
            f'<text x="{x:.1f}" y="{height-10}" fill="#94A3B8" font-size="11" text-anchor="middle">{escape(_tick(day))}</text>'
        )

    yticks = []
    pasos = 5
    for i in range(pasos + 1):
        valor = base + alto * i / pasos
        y = y_de(valor)
        yticks.append(f'<line x1="{l}" y1="{y:.1f}" x2="{l+pw}" y2="{y:.1f}" stroke="#334155" opacity=".7"/>')
        etiqueta = f"{valor:.0f}" if alto >= 10 else f"{valor:.1f}"
        yticks.append(f'<text x="{l-6}" y="{y+4:.1f}" fill="#94A3B8" font-size="11" text-anchor="end">{etiqueta}</text>')

    # Hover: custom tooltip via CSS (the native <title> is slow and barely visible).
    ancho = pw / max(len(series) - 1, 1)
    hover = []
    for i, item in enumerate(series):
        x = l + (i / n) * pw
        top = item.get("top_cve") or {}
        fecha = _fecha_larga(item["date"])
        h_val = float(item.get("hype") or 0)
        r_val = float(item.get("reality") or 0)
        n_val = int(item.get("n") or 0)
        # On the home page each point is the average of N CVEs; in a single
        # CVE card the series is snapshots of its score. There "0 CVEs" says nothing:
        # the category of the moment is shown instead.
        if "n" in item:
            cabecera = f"{fecha} · {n_val} CVEs"
        else:
            cabecera = f"{fecha} · {CATEGORY_LABEL.get(str(item.get('category') or ''), 'score')}"
        tx = min(max(x - 95, l), l + pw - 190)
        linea_top = ""
        if top.get("cve_id"):
            nombre = top.get("brand_name") or ""
            linea_top = f"{top['cve_id']}{' · ' + nombre if nombre else ''}"
        hover.append(
            f'<g class="dia">'
            f'<rect x="{x - ancho / 2:.1f}" y="{t}" width="{ancho:.1f}" height="{ph}" '
            f'fill="#FFFFFF" fill-opacity="0.001" pointer-events="all"/>'
            f'<g class="tip" pointer-events="none">'
            f'<rect x="{tx:.1f}" y="{t + 4}" width="190" height="56" rx="5" '
            f'fill="#0F172A" stroke="#334155" stroke-width="1"/>'
            f'<text x="{tx + 9:.1f}" y="{t + 21}" fill="#E2E8F0" font-size="11">{escape(cabecera)}</text>'
            f'<text x="{tx + 9:.1f}" y="{t + 37}" fill="#FF6B00" font-size="11" font-weight="700">Hype {h_val:.1f}</text>'
            f'<text x="{tx + 95:.1f}" y="{t + 37}" fill="#22D3EE" font-size="11" font-weight="700">Reality {r_val:.1f}</text>'
            f'<text x="{tx + 9:.1f}" y="{t + 52}" fill="#94A3B8" font-size="10">{escape(linea_top[:38])}</text>'
            f"</g></g>"
        )

    puntos = "".join(
        f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.2" fill="{color}" opacity=".85" pointer-events="none"/>'
        for vals, color in ((hype_vals, "#FF6B00"), (reality_vals, "#22D3EE"))
        for x, y in points(vals)
    )

    # The noisiest CVEs of the period: vertical guide on their day and a
    # staggered label in lanes. Their hype lives on a different scale than the axis
    # (daily averages), so marking them as a point pushed them out of the area and, with
    # consecutive dates, the labels overlapped.
    palette = ("#F472B6", "#A78BFA", "#34D399")
    indice_dia = {item["date"]: i for i, item in enumerate(series)}
    validos = []
    for hito in highlights[:3]:
        i = indice_dia.get(str(hito.get("date"))[:10])
        if i is None or not hito.get("cve_id"):
            continue
        validos.append((i, hito))
    validos.sort(key=lambda par: par[0])

    marcas, chips = [], []
    ocupado: dict[int, float] = {}
    # The guides start below every lane: if they start in the lane,
    # the vertical line of a highlighted CVE crosses the text next to it.
    inicio_guia = t + 17 + (len(validos) + 1) * 14
    for k, (i, hito) in enumerate(validos):
        color = palette[k % len(palette)]
        cve = hito["cve_id"]
        etiqueta = (hito.get("brand_name") or f"CVE {cve.rsplit('-', 1)[-1]}")[:18]
        ancho_txt = len(etiqueta) * 5.7 + 12
        x = l + (i / n) * pw
        carril = 0
        while ocupado.get(carril, -1e9) > x - ancho_txt:
            carril += 1
        ocupado[carril] = x + ancho_txt
        ty = t + 12 + carril * 14
        tx = min(max(x, l + ancho_txt / 2), l + pw - ancho_txt / 2)
        hype_v = float(hito.get("hype") or 0)
        reality_v = float(hito.get("reality") or 0)
        marcas.append(
            f'<a href="/cve?cve={escape(cve)}" class="tl-mark">'
            f'<line x1="{x:.1f}" y1="{ty + 4:.1f}" x2="{x:.1f}" y2="{inicio_guia:.1f}" '
            f'stroke="{color}" stroke-width="1" opacity=".45"/>'
            f'<line x1="{x:.1f}" y1="{inicio_guia:.1f}" x2="{x:.1f}" y2="{t + ph}" '
            f'stroke="{color}" stroke-width="1.2" stroke-dasharray="3 3" opacity=".5"/>'
            f'<circle cx="{x:.1f}" cy="{inicio_guia:.1f}" r="3" fill="{color}"/>'
            f'<text x="{tx:.1f}" y="{ty:.1f}" fill="{color}" font-size="10.5" text-anchor="middle" '
            f'paint-order="stroke" stroke="#0B1220" stroke-width="3">{escape(etiqueta)}</text>'
            f"<title>{escape(f'{cve} · Hype {hype_v:.1f} · Reality {reality_v:.1f}')}</title></a>"
        )
        chips.append(
            f'<a class="tl-chip" href="/cve?cve={escape(cve)}" style="--c:{color}">'
            f"<i></i><b>{escape(etiqueta)}</b><span>{escape(cve)}</span>"
            f"<em>H {hype_v:.1f} · R {reality_v:.1f}</em></a>"
        )

    leyenda_destacados = ""
    if chips:
        leyenda_destacados = (
            '<div class="tl-chips">'
            + "".join(chips)
            + "</div>"
            '<p class="tl-note">Per-CVE score (absolute scale), '
            "not the daily average the chart plots.</p>"
        )

    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img">'
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#0B1220" rx="6"/>'
        f"{''.join(yticks)}{polyline(hype_vals, '#FF6B00')}{polyline(reality_vals, '#22D3EE')}"
        # Hover before the marks: if the bands go on top, they swallow the click.
        f"{puntos}{''.join(hover)}{''.join(marcas)}{''.join(ticks)}"
        "</svg>"
        '<p class="tl-legend"><span class="h">━</span> Hype Score (Perceived)&nbsp;&nbsp;'
        '<span class="r">━</span> Reality Score (Observed)</p>'
        f"{leyenda_destacados}"
    )


def _tick(day: str) -> str:
    try:
        dt = datetime.strptime(str(day)[:10], "%Y-%m-%d")
        return f"{dt.strftime('%b')} {dt.day}"
    except ValueError:
        return str(day)[:10]


def legend_html() -> str:
    items = []
    for name, color in CATEGORY_COLORS.items():
        items.append(
            f'<div><span style="color:{color}">●</span> '
            f'<b style="color:{color}">{escape(category_display(name))}</b>'
            f'<div class="muted">{escape(CATEGORY_BLURB[name])}</div></div>'
        )
    return '<div class="legend">' + "".join(items) + "</div>"


def overview_html(
    *,
    logo_html: str,
    scatter_div: str,
    timeline_div: str,
    table_rows: str,
    total: int,
    page: int,
    page_size: int,
    severity: str,
    category: str,
    since: str,
    until: str,
    show_all: bool = False,
    query: str = "",
    product: str = "",
    products=None,
    actionable_rows: str = "",
    actionable_total: int = 0,
    attention_page: int = 0,
    attention_page_size: int = 6,
) -> str:
    product_options = "".join(
        f'<option value="{escape(str(row["product"]))}">' for row in (products or [])
    )
    # The value travels in the text input; "All products" is the placeholder.
    product_value = "" if product in (None, "", "All products") else str(product)
    start = page * page_size + 1 if total else 0
    end = min(total, page * page_size + page_size)
    max_page = max(0, (total - 1) // page_size) if total else 0
    common = dict(severity=severity, category=category, since=since, until=until)
    if product and product != "All products":
        common["product"] = product
    if query:
        common["q"] = query
    if show_all:
        common["all"] = "1"
    if attention_page:
        common["attention_page"] = str(attention_page)
    prev = _qs("/", **common, page=str(page - 1)) if page > 0 else None
    nxt = _qs("/", **common, page=str(page + 1)) if page < max_page else None
    prev_el = f'<a class="nav" href="{prev}">‹</a>' if prev else '<span class="disabled">‹</span>'
    nxt_el = f'<a class="nav" href="{nxt}">›</a>' if nxt else '<span class="disabled">›</span>'
    all_href = _qs("/", **{k: v for k, v in common.items() if k != "all"}, all="1")
    paged_href = _qs("/", **{k: v for k, v in common.items() if k != "all"})
    view = (
        f'<a class="viewall" href="{paged_href}">Show pages ←</a>'
        if show_all else
        f'<a class="viewall" href="{all_href}">View all CVEs →</a>'
    )
    hidden_all = '<input type="hidden" name="all" value="1">' if show_all else ""
    pager_btns = f"<span>{prev_el} {nxt_el}</span>"
    attention_common={k:v for k,v in common.items() if k!='attention_page'}
    attention_common['page']=str(page)
    attention_max=max(0,(actionable_total-1)//attention_page_size)
    attention_prev=(_qs('/',**attention_common,attention_page=str(attention_page-1))+'#attention-queue') if attention_page>0 else None
    attention_next=(_qs('/',**attention_common,attention_page=str(attention_page+1))+'#attention-queue') if attention_page<attention_max else None
    attention_start=attention_page*attention_page_size+1 if actionable_total else 0
    attention_end=min(actionable_total,(attention_page+1)*attention_page_size)
    attention_prev_el=(f'<a class="nav" aria-label="Previous attention page" href="{escape(attention_prev)}">‹</a>'
                       if attention_prev else '<span class="disabled" aria-hidden="true">‹</span>')
    attention_next_el=(f'<a class="nav" aria-label="Next attention page" href="{escape(attention_next)}">›</a>'
                       if attention_next else '<span class="disabled" aria-hidden="true">›</span>')
    body = f"""
<div class="page">
  <div class="top overview-top">
    {logo_html}
    <form class="filters" id="filters" method="get" action="/">
      {hidden_all}
      <div class="filter filter-search"><label>Search</label>
        <input type="search" name="q" value="{escape(query)}"
               placeholder="CVE ID, PHP2Shell or Log4Shell" autocomplete="off">
      </div>
      <div class="filter filter-dates"><label>Publication dates</label>
        <div class="range">
          <input type="date" name="since" value="{escape(since)}">
          <span class="sep">–</span>
          <input type="date" name="until" value="{escape(until)}">
        </div>
      </div>
      <div class="filter"><label>Severity</label>
        <select name="severity">
          {_opt("All severities", "All severities", severity)}
          {_opt("CRITICAL", "CRITICAL", severity)}
          {_opt("HIGH", "HIGH", severity)}
          {_opt("MEDIUM", "MEDIUM", severity)}
          {_opt("LOW", "LOW", severity)}
        </select>
      </div>
      <div class="filter"><label>Product</label>
        <input type="text" name="product" id="product-filter" list="product-list"
               placeholder="All products" autocomplete="off" spellcheck="false"
               value="{escape(product_value)}">
        <datalist id="product-list">{product_options}</datalist>
      </div>
      <div class="filter filter-category"><label>Category</label>
        <select name="category">
          {_opt("All categories", "All categories", category)}
          {_opt("Overhyped", category_display("Overhyped"), category)}
          {_opt("Earned the hype", category_display("Earned the hype"), category)}
          {_opt("Sleeper", category_display("Sleeper"), category)}
          {_opt("Quiet", category_display("Quiet"), category)}
          {_opt("Unknown", category_display("Unknown"), category)}
          {_opt("Watch", category_display("Watch"), category)}
        </select>
      </div>
    </form>
  </div>
  <div class="row row-60 dash-row">
    <div class="card scatter-card">
      <p class="h3">Hype vs Reality {INFO_SVG}</p>
      <p class="muted">Public attention compared with exploitation evidence and prediction; global impact is not quantified</p>
      <div class="scatter-body">{scatter_div}{legend_html()}</div>
      <div class="tl-strip">
        <div class="tl-head"><span class="h3">Current scores by publication date {INFO_SVG}</span>
          <span class="mini"><span><i class="h"></i>Hype</span><span><i class="r"></i>Reality</span></span>
          <span class="rng">{escape(since)} → {escape(until)}</span></div>
        {timeline_div}
      </div>
    </div>
    <div class="col-stack">
      <div class="card table-card acc-card" id="attention-queue">
        <div class="acc-head">
          <p class="h3">Pay attention to {INFO_SVG}</p>
          <span class="acc-count">{actionable_total:,} matching</span>
        </div>
        <p class="acc-crit">All publication dates; search, product, severity and category filters apply. Confirmed exploitation, fresh EPSS ≥ 0.70 or curated public PoC.</p>
        <div class="table-scroll">
          <table class="table acc-table"><thead><tr>
            <th>CVE ID</th><th>Severity</th><th>Signals</th><th>Reality</th>
          </tr></thead><tbody>{actionable_rows}</tbody></table>
        </div>
        <nav class="pager attention-pager" aria-label="Pay attention to pagination">
          <span>{attention_start:,}–{attention_end:,} of {actionable_total:,}</span>
          <span>Page {attention_page+1 if actionable_total else 0:,} / {attention_max+1 if actionable_total else 0:,}</span>
          <span class="pager-controls">{attention_prev_el} {attention_next_el}</span>
        </nav>
      </div>
      <div class="card table-card">
        <p class="h3">CVEs in publication range</p>
        <div class="table-scroll">
        <table class="table"><thead><tr>
          <th>CVE ID</th><th>Severity</th><th>Score</th><th>Category</th><th>Published</th>
        </tr></thead><tbody>{table_rows or '<tr><td colspan="5" class="muted">No CVEs.</td></tr>'}</tbody></table>
        </div>
        <div class="pager"><span>{view}</span><span>{start}–{end} of {total}</span>{pager_btns}</div>
      </div>
    </div>
  </div>
  <div class="footer">
    <span>Source: CVE List V5 · CISA KEV · FIRST EPSS · GitHub · RSS</span>
    <span>VulnRadar</span>
  </div>
</div>
"""
    # Reloads the home page every minute: scores are recalculated often and
    # reading is passive. track=False so the visit metrics are not inflated.
    return document(body, refresh=60)


def detail_html(
    *,
    cve_id: str,
    description: str,
    badges: str,
    bars: str,
    hype: float,
    reality: float,
    category: str,
    events: str,
    mentions: str,
    pocs_html: str,
    poc_count: int,
    now: str,
    mention_count: int = 0,
    brand_name: str = "",
    timeline: str = "",
    caveat: str = "",
    evidence_context: str = "",
) -> str:
    cat = category or "Quiet"
    based = (
        f'<div class="foot-note">{INFO_SVG} Sources: {mention_count} documents and public datasets.</div>'
        if mention_count else
        f'<div class="foot-note">{INFO_SVG} Based on public data to date.</div>'
    )
    description_text=' '.join((description or 'No description.').split())
    preview=description_text[:280]+('…' if len(description_text)>280 else '')
    expanded_description=(f'<details class="description-details"><summary>Read full description</summary>'
                          f'<div class="full-description">{escape(description or "")}</div></details>') if len(description_text)>280 else ''
    body = f"""
<div class="page detail-page">
  <div class="top">
    {logo("Data against noise.")}
    <div class="live">Page generated: {escape(now)}</div>
  </div>
  <a class="back" href="/" id="back-dash">← Dashboard</a>
  <div class="cve-title">
    <div>
      <h1>{escape(cve_id)}</h1>
      {f'<p class="brand-hero">{escape(brand_name)}</p>' if brand_name else ""}
      <p class="muted cve-summary">{escape(preview)}</p>
      {expanded_description}
    </div>
    <div class="badges">{badges}</div>
  </div>
  <div class="detail-grid">
    <section class="card detail-summary" id="cve-summary">
      <h2 class="h3 accent">Attention and evidence</h2>
      <div class="score-row">
        <div class="score-col"><div class="muted">HYPE SCORE</div><div class="score hype">{hype:.1f}<small>/10</small></div></div>
        <div class="score-col"><div class="muted">REALITY SCORE</div><div class="score reality">{reality:.1f}<small>/10</small></div></div>
      </div>
      <div class="banner"><strong>{escape(CATEGORY_LABEL.get(cat,cat))}</strong>
        <p class="muted" style="margin:6px 0 0">{escape(CATEGORY_DETAIL.get(cat,""))}</p></div>
      {based}
    </section>
    <section class="card detail-components" id="hype-components">
      <h2 class="h3 accent">Hype components</h2>
      {bars}
      <div class="hype-total"><span>HYPE TOTAL</span><b>{int(round(hype*10))}/100</b></div>
    </section>
    <section class="card detail-sources" id="source-documents">
      <h2 class="h3">Sources and documents</h2>
      <div class="detail-scroll">{mentions}</div>
    </section>
    <section class="card detail-history" id="score-history">
      <h2 class="h3">Score evolution {INFO_SVG}</h2>
      <p class="muted"><span class="hype">● Hype</span> &nbsp; <span class="reality">● Reality</span></p>
      <div class="chart-scroll">{timeline or '<p class="muted">No changes recorded yet: the series starts with the next recalculation.</p>'}</div>
    </section>
    <section class="card detail-pocs" id="public-exploits">
      <h2 class="h3">Public exploit evidence</h2>
      <div class="detail-scroll">{pocs_html}</div>
    </section>
  </div>
  <details class="card context-disclosure" id="evidence-context-panel">
    <summary>Evidence context and dated references</summary>
    {f'<p class="muted" style="margin-top:12px">{escape(caveat)}</p>' if caveat else ''}
    {evidence_context}
  </details>
  <details class="card context-disclosure" id="source-event-timeline">
    <summary>Source event timeline</summary>
    <div class="tl">{events}</div>
  </details>
  <div class="footer"><span>Source: CVE List V5 · CISA KEV · FIRST EPSS · GitHub · RSS</span><span>VulnRadar</span></div>
</div>
"""
    return document(body)


def agents_html(
    *,
    now: str,
    cards: str,
    feed_rows: str,
    scatter_div: str,
    logs: str,
) -> str:
    body = f"""
<div class="page">
  <div class="top">
    {logo()}
    <div class="live">SOC MONITORING · REAL-TIME AGENTS <span class="dot"></span><b>LIVE</b> &nbsp; {escape(now)} &nbsp; · &nbsp; AUTO-REFRESH ON <a href="/soc/logout">Logout</a></div>
  </div>
  <div class="row row-4">{cards}</div>
  <div class="row row-60" style="margin-top:16px">
    <div class="card">
      <p class="h3">Live processing feed</p>
      <p class="muted">Real-time agent activity and event stream</p>
      <table class="table"><thead><tr>
        <th>Time</th><th>Agent</th><th>Event</th><th>Details</th><th>Status</th>
      </tr></thead><tbody>{feed_rows or '<tr><td colspan="5" class="muted">The worker has not written any events yet.</td></tr>'}</tbody></table>
      <p class="feed-foot">Showing latest events · Auto-refreshing…</p>
    </div>
    <div class="card scatter-card" style="min-height:320px">
      <p class="h3">Hype vs Reality</p>
      <p class="muted">Signal distribution</p>
      {scatter_div}
    </div>
  </div>
  <div class="card" style="margin-top:16px">
    <p class="h3">System logs</p>
    {logs}
  </div>
</div>
"""
    return document(body, refresh=8)


def login_html(*, error: str = "") -> str:
    err = f'<p class="login-error">{escape(error)}</p>' if error else ""
    body = f"""
<div class="page">
  <div class="login-card card">
    {logo()}
    <p class="h3" style="margin-top:18px">SOC monitoring</p>
    <p class="muted">Internal agent panel. Not part of the public dashboard.</p>
    {err}
    <form method="post" action="/soc" autocomplete="off">
      <div class="filter"><label>Username</label>
        <input type="text" name="user" autofocus>
      </div>
      <div class="filter"><label>Password</label>
        <input type="password" name="password">
      </div>
      <button type="submit">Sign in</button>
    </form>
  </div>
</div>
"""
    return document(body)


def hype_bar(label: str, pct: int, icon: str) -> str:
    pct = max(0, min(100, pct))
    return (
        f'<div class="hype-row">{_icon(icon)}'
        f'<div class="lbl">{escape(label)}</div>'
        f'<div class="val">{pct}/100</div>'
        f'<div class="bar-wrap"><div class="bar" style="width:{pct}%"></div></div></div>'
    )


def agent_card(key: str, name: str, status: str, metric_a, metric_b, spark: str = "") -> str:
    color = AGENT_COLORS.get(key, "#FF6B00")
    healthy = status in ("SUCCESS", "RUNNING", "INFO")
    if status == "RUNNING":
        label = "RUNNING"
    elif healthy:
        label = "HEALTHY"
    else:
        label = status or "PENDING"
    dot = "ok" if healthy and status != "RUNNING" else ("stale" if status == "RUNNING" else "err")
    progress = {"SUCCESS": 100, "INFO": 100, "RUNNING": 62, "ERROR": 18}.get(status, 0)
    a_value, a_label = metric_a
    b_value, b_label = metric_b
    return (
        f'<div class="card"><div class="agent-head">'
        f"{agent_icon_svg(key, color)}"
        f'<div><b>{escape(name)}</b>'
        f'<div class="muted"><span class="dot {dot}"></span>{escape(label)}</div></div></div>'
        f"{spark}"
        f'<div class="progress-row"><div class="progress">'
        f'<span style="width:{progress}%;background:{color}"></span></div>'
        f'<div class="progress-pct">PROGRESS {progress}%</div></div>'
        f'<div class="metrics">'
        f'<div><b>{escape(str(a_value))}</b><span>{escape(a_label)}</span></div>'
        f'<div><b>{escape(str(b_value))}</b><span>{escape(b_label)}</span></div>'
        f"</div></div>"
    )
