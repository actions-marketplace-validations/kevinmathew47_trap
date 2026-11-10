// Self-contained dashboard page. Every value is escaped: user agents and paths come from attackers.

function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const TYPE_LABEL = {
  honeypot: 'Honeypot path',
  'hidden-link': 'Hidden link',
  'robots-bait': 'Ignored robots.txt',
  'ai-bait': 'AI bait',
  canary: 'Stolen fake secret used',
};

export function renderDashboard({ stats, bans, events, mode }) {
  const tiles = [
    ['Requests seen', stats.requests],
    ['Traps triggered', stats.trapsTriggered],
    ['Clients banned now', stats.activeBans],
    ['Fake pages served', stats.wastedResponses],
  ]
    .map(([label, value]) => `<div class="tile"><div class="num">${esc(value)}</div><div class="lbl">${esc(label)}</div></div>`)
    .join('');

  const banRows = bans.length
    ? bans
        .map(
          (b) =>
            `<tr><td class="mono">${esc(b.ip)}</td><td>${esc(b.reasons.map((r) => TYPE_LABEL[r] || r).join(', '))}</td>` +
            `<td>${esc(b.wastedResponses)}</td><td class="mono">${esc(b.until.replace('T', ' ').slice(0, 19))}</td></tr>`
        )
        .join('')
    : '<tr><td colspan="4" class="empty">Nobody is banned right now.</td></tr>';

  const eventRows = events.length
    ? events
        .map(
          (e) =>
            `<tr><td class="mono">${esc(e.time.replace('T', ' ').slice(0, 19))}</td>` +
            `<td><span class="tag t-${esc(e.type)}">${esc(TYPE_LABEL[e.type] || e.type)}</span></td>` +
            `<td class="mono">${esc(e.ip)}</td><td>${esc(e.client)}</td>` +
            `<td class="mono path">${esc(e.method)} ${esc(e.path)}${e.detail ? ` <em>(${esc(e.detail)})</em>` : ''}</td>` +
            `<td class="ua">${esc(e.userAgent)}</td></tr>`
        )
        .join('')
    : '<tr><td colspan="6" class="empty">No traps triggered yet.</td></tr>';

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<meta http-equiv="refresh" content="5">
<title>trapkit</title>
<style>
:root{--bg:#f6f5f1;--card:#fff;--ink:#1c1b19;--mute:#6b6862;--line:#e3e0d8;--accent:#b4381f}
@media (prefers-color-scheme:dark){:root{--bg:#141412;--card:#1e1d1a;--ink:#eeece6;--mute:#9a968d;--line:#33312c;--accent:#ff7a59}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:14px;margin:28px 0 8px;color:var(--mute);text-transform:uppercase;letter-spacing:.06em}
.sub{color:var(--mute);margin:0 0 20px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.num{font-size:28px;font-weight:650;font-variant-numeric:tabular-nums}.lbl{color:var(--mute)}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;min-width:640px}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;color:var(--mute);font-size:12px}tr:last-child td{border-bottom:0}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;white-space:nowrap}
.path{white-space:normal;word-break:break-all}.ua{color:var(--mute);font-size:12px;max-width:260px;word-break:break-word}
.tag{display:inline-block;padding:1px 8px;border-radius:99px;border:1px solid var(--line);font-size:12px;white-space:nowrap}
.t-canary{border-color:var(--accent);color:var(--accent);font-weight:600}
.empty{color:var(--mute);text-align:center;padding:24px}
</style></head><body><main>
<h1>trapkit</h1>
<p class="sub">Mode: <strong>${esc(mode)}</strong>. This page refreshes every 5 seconds.</p>
<div class="tiles">${tiles}</div>
<h2>Banned clients</h2>
<div class="wrap"><table><tr><th>IP</th><th>Caught by</th><th>Fake pages served</th><th>Banned until (UTC)</th></tr>${banRows}</table></div>
<h2>Recent trap hits</h2>
<div class="wrap"><table><tr><th>Time (UTC)</th><th>Trap</th><th>IP</th><th>Client</th><th>Request</th><th>User agent</th></tr>${eventRows}</table></div>
</main></body></html>`;
}
