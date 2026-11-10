// Output formats for scan results: terminal text, Markdown report, SVG badge.

const GRADE_COLOR = { A: '#2ea44f', B: '#7cb342', C: '#dfb317', D: '#e67e22', F: '#d73a49' };
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const NOTE = 'This is a pattern scan. It finds common mistakes; a clean result does not prove the app is secure.';

function painter(enabled) {
  const wrap = (code) => (text) => (enabled ? `\u001b[${code}m${text}\u001b[0m` : String(text));
  return { bold: wrap('1'), dim: wrap('2'), red: wrap('31'), yellow: wrap('33'), green: wrap('32'), cyan: wrap('36'), magenta: wrap('35') };
}

export function formatTerminal(result, { color = false } = {}) {
  const c = painter(color);
  const paint = { critical: c.magenta, high: c.red, medium: c.yellow, low: c.dim };
  const gradePaint = result.grade === 'A' || result.grade === 'B' ? c.green : result.grade === 'C' ? c.yellow : c.red;
  const out = [];

  out.push('');
  out.push(`  ${c.bold('trapkit scan')}  ${c.dim(result.root)}`);
  out.push('');
  out.push(`  Security grade: ${c.bold(gradePaint(result.grade))}   ${c.dim(`score ${result.score}/100, ${result.filesScanned} files checked`)}`);
  out.push(`  ${SEVERITIES.map((s) => paint[s](`${result.counts[s]} ${s}`)).join('   ')}`);
  out.push('');

  if (result.findings.length === 0) {
    out.push(`  ${c.green('No known patterns found.')}`);
  }
  for (const f of result.findings) {
    out.push(`  ${paint[f.severity](f.severity.toUpperCase().padEnd(8))} ${c.bold(f.title)}`);
    out.push(`           ${c.cyan(`${f.file}:${f.line}`)}`);
    out.push(`           ${c.dim(f.snippet)}`);
    out.push(`           Fix: ${f.fix}`);
    out.push('');
  }
  out.push(`  ${c.dim(NOTE)}`);
  out.push('');
  return out.join('\n');
}

export function formatMarkdown(result) {
  const out = [];
  out.push('# Security report');
  out.push('');
  out.push(`**Grade ${result.grade}** (score ${result.score}/100, ${result.filesScanned} files checked)`);
  out.push('');
  out.push('| Severity | Count |');
  out.push('|---|---|');
  for (const s of SEVERITIES) out.push(`| ${s} | ${result.counts[s]} |`);
  out.push('');
  if (result.findings.length === 0) out.push('No known patterns found.');
  for (const s of SEVERITIES) {
    const group = result.findings.filter((f) => f.severity === s);
    if (group.length === 0) continue;
    out.push(`## ${s[0].toUpperCase() + s.slice(1)}`);
    out.push('');
    for (const f of group) {
      out.push(`### ${f.title}`);
      out.push('');
      out.push(`- Where: \`${f.file}:${f.line}\``);
      out.push(`- Code: \`${f.snippet.replace(/`/g, "'")}\``);
      out.push(`- Fix: ${f.fix}`);
      out.push(`- Rule: \`${f.rule}\``);
      out.push('');
    }
  }
  out.push(`_${NOTE}_`);
  out.push('');
  return out.join('\n');
}

export function formatBadge(result) {
  const color = GRADE_COLOR[result.grade] || '#9f9f9f';
  const label = 'trapkit security';
  const left = 108;
  const right = 28;
  const width = left + right;
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="20" role="img" aria-label="${label}: ${result.grade}">` +
    `<title>${label}: ${result.grade}</title>` +
    `<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>` +
    `<clipPath id="r"><rect width="${width}" height="20" rx="3" fill="#fff"/></clipPath>` +
    `<g clip-path="url(#r)"><rect width="${left}" height="20" fill="#555"/><rect x="${left}" width="${right}" height="20" fill="${color}"/>` +
    `<rect width="${width}" height="20" fill="url(#s)"/></g>` +
    `<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">` +
    `<text x="${left / 2}" y="14">${label}</text>` +
    `<text x="${left + right / 2}" y="14" font-weight="bold">${result.grade}</text></g></svg>\n`
  );
}
