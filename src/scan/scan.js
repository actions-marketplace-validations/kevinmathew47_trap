// Walk a project, apply the rules, and grade the result.

import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { LINE_RULES, FILE_RULES, PROJECT_RULES, RATE_LIMITERS } from './rules.js';

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.next', '.nuxt', '.svelte-kit', '.vercel', '.turbo', '.cache', 'dist', 'build', 'out',
  'coverage', 'vendor', '__pycache__', '.venv', 'venv', 'env', '.idea', '.vscode', 'target', '.expo',
]);
const SCAN_EXTS = new Set(['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'vue', 'svelte', 'html', 'py', 'sql', 'rules', 'json', 'yml', 'yaml', 'toml']);
const SKIP_FILES = /^(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|composer\.lock|.*\.min\.(?:js|css)|.*\.map)$/;
const MAX_FILE_BYTES = 1_000_000;
const MAX_FILES = 20_000;

const WEIGHT = { critical: 25, high: 12, medium: 5, low: 1 };
const ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function globToRegex(pattern) {
  const cleaned = pattern.replace(/^\.?\//, '').replace(/\/$/, '');
  const body = cleaned
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\u0000')
    .replace(/\*/g, '[^/]*')
    .replace(/\u0000/g, '.*');
  return new RegExp(`(?:^|/)${body}(?:/|$)`);
}

async function readIgnore(root) {
  try {
    const text = await readFile(path.join(root, '.trapkitignore'), 'utf8');
    return text
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#'));
  } catch {
    return [];
  }
}

async function walk(root, ignore) {
  const files = [];
  const queue = [''];
  while (queue.length && files.length < MAX_FILES) {
    const relDir = queue.pop();
    let entries;
    try {
      entries = await readdir(path.join(root, relDir), { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const rel = relDir ? `${relDir}/${entry.name}` : entry.name;
      if (ignore.some((re) => re.test(rel))) continue;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) queue.push(rel);
      } else if (entry.isFile()) {
        files.push(rel);
      }
    }
  }
  return files.sort();
}

function extOf(name) {
  if (/^\.env(?:\..+)?$/.test(name)) return 'env';
  const dot = name.lastIndexOf('.');
  return dot <= 0 ? '' : name.slice(dot + 1).toLowerCase();
}

function isClientFile(rel, text) {
  if (/^\s*(?:\/\/[^\n]*\n|\/\*[\s\S]*?\*\/\s*)*["']use client["']/.test(text)) return true;
  if (/["']use server["']/.test(text.slice(0, 400))) return false;
  if (/(?:^|\/)(?:api|server|lib\/server|functions|middleware)(?:\/|\.)/.test(rel)) return false;
  if (/\.(?:vue|svelte|html)$/.test(rel)) return true;
  return /(?:^|\/)(?:components|public|hooks|client|frontend)\//.test(rel);
}

function isComment(line) {
  return /^\s*(?:\/\/|#|\*|\/\*|<!--)/.test(line);
}

function mask(snippet, match) {
  const value = match[1] || match[0];
  if (value.length < 8) return snippet;
  return snippet.split(value).join(value.slice(0, 4) + '…' + '*'.repeat(6));
}

function tidy(snippet) {
  const text = snippet.trim().replace(/\s+/g, ' ');
  return text.length > 160 ? text.slice(0, 157) + '...' : text;
}

export function grade(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  let penalty = 0;
  for (const finding of findings) {
    counts[finding.severity]++;
    penalty += WEIGHT[finding.severity];
  }
  const score = Math.max(0, 100 - penalty);
  let letter = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  // One critical hole is enough to lose the app, so it can never grade above D.
  if (counts.critical > 0 && (letter === 'A' || letter === 'B' || letter === 'C')) letter = 'D';
  if (counts.high > 0 && letter === 'A') letter = 'B';
  return { score, grade: letter, counts };
}

/**
 * Scan a project folder.
 * @param {string} root
 * @param {{ignore?: string[]}} [options]
 */
export async function scan(root, options = {}) {
  const absolute = path.resolve(root);
  const info = await stat(absolute).catch(() => null);
  if (!info || !info.isDirectory()) throw new Error(`trapkit: "${root}" is not a folder`);

  const patterns = [...(await readIgnore(absolute)), ...(options.ignore || [])];
  const ignore = patterns.map(globToRegex);
  const relFiles = await walk(absolute, ignore);

  const findings = [];
  const seen = new Set();
  const add = (rule, file, line, snippet) => {
    const key = `${rule.id}:${file}:${line}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push({ rule: rule.id, title: rule.title, severity: rule.severity, file, line, snippet: tidy(snippet), fix: rule.fix });
  };

  const project = { envFiles: [], gitignore: '', dependencies: [], mentionsRateLimit: false };
  let filesScanned = 0;

  for (const rel of relFiles) {
    const name = rel.slice(rel.lastIndexOf('/') + 1);
    const ext = extOf(name);
    if (ext === 'env' && !rel.includes('/')) project.envFiles.push(rel);
    if (rel === '.gitignore') {
      project.gitignore = await readFile(path.join(absolute, rel), 'utf8').catch(() => '');
      continue;
    }
    if (!(SCAN_EXTS.has(ext) || ext === 'env') || SKIP_FILES.test(name)) continue;

    const full = path.join(absolute, rel);
    const size = await stat(full).then((s) => s.size, () => Infinity);
    if (size > MAX_FILE_BYTES) continue;
    const text = await readFile(full, 'utf8').catch(() => null);
    if (text == null || text.includes('\u0000')) continue;
    filesScanned++;

    if (rel === 'package.json') {
      try {
        const pkg = JSON.parse(text);
        project.dependencies = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
      } catch {
        // unreadable package.json: carry on without dependency info
      }
    }
    if (!project.mentionsRateLimit && ext !== 'json' && RATE_LIMITERS.test(text)) project.mentionsRateLimit = true;

    const lines = text.split(/\r?\n/);
    const file = { rel, ext, text, lines, client: isClientFile(rel, text) };
    // A real .env file is where secrets belong; only its public-prefix mistakes matter.
    const isRealEnv = ext === 'env' && !/\.(?:example|sample|template)$/.test(name);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length > 2000) continue;
      if (/trapkit-ignore/.test(line) || (i > 0 && /trapkit-ignore-next-line/.test(lines[i - 1]))) continue;
      const comment = isComment(line);
      for (const rule of LINE_RULES) {
        if (rule.exts && !rule.exts.includes(ext)) continue;
        if (rule.clientOnly && !file.client) continue;
        if (rule.skipComments && comment) continue;
        if (isRealEnv && rule.id !== 'public-env-secret') continue;
        if (rule.skipEnvFiles && ext === 'env') continue;
        const match = rule.pattern.exec(line);
        if (!match) continue;
        if (rule.accept && !rule.accept(match, line, file)) continue;
        add(rule, rel, i + 1, rule.secret ? mask(line, match) : line);
      }
    }

    for (const rule of FILE_RULES) {
      if (!rule.applies(file)) continue;
      for (const hit of rule.check(file)) {
        if (/trapkit-ignore/.test(lines[hit.line - 1] || '')) continue;
        add(rule, rel, hit.line, hit.snippet);
      }
    }
  }

  for (const rule of PROJECT_RULES) {
    for (const hit of rule.check(project)) add(rule, hit.file, hit.line, hit.snippet);
  }

  findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity] || a.file.localeCompare(b.file) || a.line - b.line);
  return { root: absolute, filesScanned, findings, ...grade(findings) };
}
