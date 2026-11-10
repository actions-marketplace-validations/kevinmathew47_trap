import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { scan, grade } from '../src/scan/scan.js';
import { formatBadge, formatMarkdown, formatTerminal } from '../src/scan/report.js';

const CLI = fileURLToPath(new URL('../bin/trapkit.js', import.meta.url));

// Fake secrets are assembled at run time so this repo never contains a string that looks like a real key.
const FAKE = {
  stripe: 'sk_' + 'live_' + '4eC39HqLyjWDarjtT1zdp7dcAbCd',
  aws: 'AKIA' + 'IOSFODNN7EXAMPLQ',
  github: 'ghp_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8',
  generic: 'q9Zk27Lm4Xw81Rt6Yb3N',
};

async function project(files) {
  const dir = await mkdtemp(path.join(tmpdir(), 'trapkit-test-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    await mkdir(path.dirname(full), { recursive: true });
    await writeFile(full, content);
  }
  return dir;
}

const rules = (result) => result.findings.map((f) => f.rule);

test('a clean project gets an A', async () => {
  const dir = await project({
    'package.json': JSON.stringify({ dependencies: { express: '4', helmet: '7', 'express-rate-limit': '7' } }),
    '.gitignore': 'node_modules\n.env*\n',
    '.env': 'STRIPE_SECRET_KEY=' + FAKE.stripe + '\n',
    'server.js': [
      "import express from 'express';",
      'const app = express();',
      "app.get('/user', async (req, res) => {",
      "  const rows = await db.query('select * from users where id = $1', [req.query.id]);",
      '  res.json(rows);',
      '});',
    ].join('\n'),
  });
  try {
    const result = await scan(dir);
    assert.deepEqual(result.findings, []);
    assert.equal(result.grade, 'A');
    assert.equal(result.score, 100);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('common JavaScript holes are found', async () => {
  const dir = await project({
    'package.json': JSON.stringify({ dependencies: { express: '4' } }),
    '.env': 'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=abc\n',
    'server.js': [
      `const stripe = require('stripe')('${FAKE.stripe}');`,
      `const awsKey = '${FAKE.aws}';`,
      `const token = '${FAKE.github}';`,
      `const config = { password: '${FAKE.generic}' };`,
      'db.query(`select * from users where id = ${req.query.id}`);',
      'db.query("select * from users where name = \'" + req.body.name + "\'");',
      'exec(`convert ${req.query.file} out.png`);',
      'const out = eval(req.body.expr);',
      'fs.readFile(req.query.path, cb);',
      'const page = await fetch(req.query.url);',
      'res.redirect(req.query.next);',
      'await User.create(req.body);',
      "app.use(cors());",
      'const agent = new https.Agent({ rejectUnauthorized: false });',
      "jwt.verify(token, key, { algorithms: ['none'] });",
      "const signed = jwt.sign(payload, 'supersecret');",
      'const claims = jwt.decode(token);',
      "res.cookie('sid', id, { httpOnly: false });",
      "const hash = crypto.createHash('md5').update(pw).digest('hex');",
      'const resetToken = Math.random().toString(36);',
    ].join('\n'),
    'components/Admin.jsx': ["'use client';", 'const key = process.env.SUPABASE_SERVICE_ROLE_KEY;', '<div dangerouslySetInnerHTML={{ __html: bio }} />'].join('\n'),
    'app/api/posts/route.ts': ['export async function POST(request) {', '  const data = await request.json();', '  return Response.json(await db.insert(data));', '}'].join('\n'),
    'app/api/safe/route.ts': ['export async function POST(request) {', '  const session = await auth();', '  if (!session) return new Response(null, { status: 401 });', '}'].join('\n'),
    'supabase/migrations/001.sql': ['create table public.profiles (id uuid primary key);', 'create table notes (id uuid primary key);', 'alter table notes enable row level security;'].join('\n'),
    'firestore.rules': 'match /{document=**} { allow read, write: if true; }\n',
  });
  try {
    const result = await scan(dir);
    const found = new Set(rules(result));
    for (const id of [
      'secret-stripe-key', 'secret-aws-key', 'secret-github-token', 'secret-hardcoded', 'public-env-secret',
      'service-role-in-client', 'sql-injection', 'command-injection', 'eval', 'path-traversal', 'ssrf',
      'open-redirect', 'mass-assignment', 'xss-raw-html', 'cors-wildcard', 'tls-check-disabled', 'jwt-none',
      'jwt-hardcoded-secret', 'jwt-decode-only', 'cookie-not-httponly', 'weak-hash', 'weak-random',
      'api-route-no-auth', 'supabase-no-rls', 'firebase-open-rules', 'env-file-not-ignored', 'no-rate-limit',
      'no-security-headers',
    ]) {
      assert.ok(found.has(id), `expected rule ${id}`);
    }
    assert.equal(result.grade, 'F');

    // both SQL styles on their own lines
    assert.equal(result.findings.filter((f) => f.rule === 'sql-injection').length, 2);
    // the route with an auth check is not reported
    assert.deepEqual(result.findings.filter((f) => f.rule === 'api-route-no-auth').map((f) => f.file), ['app/api/posts/route.ts']);
    // only the table without RLS is reported
    const rls = result.findings.filter((f) => f.rule === 'supabase-no-rls');
    assert.equal(rls.length, 1);
    assert.match(rls[0].snippet, /profiles/);
    // secrets are masked in the output
    const text = JSON.stringify(result);
    for (const secret of Object.values(FAKE)) assert.ok(!text.includes(secret), 'secret leaked into the report');
    // critical findings come first
    assert.equal(result.findings[0].severity, 'critical');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('common Python holes are found', async () => {
  const dir = await project({
    'app.py': [
      'cur.execute(f"select * from users where id = {user_id}")',
      'cur.execute("select * from users where id = %s" % user_id)',
      'subprocess.run(cmd, shell=True)',
      'data = pickle.loads(blob)',
      'cfg = yaml.load(text)',
      'requests.get(url, verify=False)',
      'app.run(host="0.0.0.0", debug=True)',
      'digest = hashlib.md5(pw).hexdigest()',
    ].join('\n'),
    'safe.py': ['cur.execute("select * from users where id = %s", (user_id,))', 'cfg = yaml.load(text, Loader=yaml.SafeLoader)', 'subprocess.run(["ls", path])'].join('\n'),
  });
  try {
    const result = await scan(dir);
    const found = new Set(rules(result));
    for (const id of ['sql-injection', 'command-injection', 'unsafe-deserialization', 'tls-check-disabled', 'debug-mode', 'weak-hash']) {
      assert.ok(found.has(id), `expected rule ${id}`);
    }
    assert.deepEqual(result.findings.filter((f) => f.file === 'safe.py'), []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('safe look-alikes are not reported', async () => {
  const dir = await project({
    '.gitignore': '.env\n',
    'lib.js': [
      "const apiKey = process.env.API_KEY;",
      "const password = 'your-password-here';",
      "const secret = '${SECRET_FROM_VAULT}';",
      '// db.query(`select * from users where id = ${id}`);',
      'const rows = await sql`select * from users where id = ${id}`;',
      "const m = /a(b)/.exec(`${input}`);",
      "el.innerHTML = '<b>static</b>';",
      'const jitter = Math.random() * 100;',
      "const x = evaluate(expr);",
      "await db.user.create({ data: { name: req.body.name } });",
      "const mask = 'task-0123456789abcdef0123456789abcdef0123';",
    ].join('\n'),
    'node_modules/bad/index.js': 'eval(req.body.x)',
    'dist/bundle.js': 'eval(req.body.x)',
  });
  try {
    const result = await scan(dir);
    assert.deepEqual(result.findings, []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('ignore comments and .trapkitignore are respected', async () => {
  const dir = await project({
    '.trapkitignore': '# fixtures\nfixtures/\n*.gen.js\n',
    'a.js': ['eval(input); // trapkit-ignore', '// trapkit-ignore-next-line', 'eval(input);', 'eval(input);'].join('\n'),
    'fixtures/bad.js': 'eval(input);',
    'src/out.gen.js': 'eval(input);',
  });
  try {
    const result = await scan(dir);
    assert.deepEqual(result.findings.map((f) => `${f.file}:${f.line}`), ['a.js:4']);
    const viaOption = await scan(dir, { ignore: ['a.js'] });
    assert.deepEqual(viaOption.findings, []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('grading rules', () => {
  const f = (severity) => ({ severity });
  assert.equal(grade([]).grade, 'A');
  assert.equal(grade([f('low'), f('low')]).grade, 'A');
  assert.equal(grade([f('high')]).grade, 'B');
  assert.equal(grade([f('critical')]).grade, 'D');
  assert.equal(grade([f('medium'), f('medium'), f('medium')]).grade, 'B');
  assert.equal(grade(Array(10).fill(f('critical'))).grade, 'F');
  assert.equal(grade(Array(10).fill(f('critical'))).score, 0);
});

test('report formats', async () => {
  const dir = await project({ 'a.js': 'eval(input);' });
  try {
    const result = await scan(dir);
    assert.match(formatBadge(result), /^<svg [^>]*aria-label="trapkit security: B"/);
    assert.match(formatMarkdown(result), /\*\*Grade B\*\*/);
    assert.match(formatMarkdown(result), /`a\.js:1`/);
    const plain = formatTerminal(result);
    assert.ok(!plain.includes('\u001b['));
    assert.match(plain, /Security grade: B/);
    assert.ok(formatTerminal(result, { color: true }).includes('\u001b['));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

function cli(args) {
  return new Promise((resolve) => {
    execFile(process.execPath, [CLI, ...args], (error, stdout, stderr) => {
      resolve({ code: error ? error.code : 0, stdout, stderr });
    });
  });
}

test('command line: exit codes, json, report and badge files', async () => {
  const dir = await project({ 'a.js': 'eval(input);' });
  try {
    const failing = await cli(['scan', dir]);
    assert.equal(failing.code, 1);
    assert.match(failing.stdout, /Code is executed from a string/);

    assert.equal((await cli(['scan', dir, '--fail-on', 'critical'])).code, 0);
    assert.equal((await cli(['scan', dir, '--fail-on', 'never'])).code, 0);

    const report = path.join(dir, 'report.md');
    const badge = path.join(dir, 'badge.svg');
    const json = await cli(['scan', dir, '--json', '--report', report, '--badge', badge, '--fail-on', 'never']);
    assert.equal(JSON.parse(json.stdout).grade, 'B');
    assert.match(await readFile(report, 'utf8'), /# Security report/);
    assert.match(await readFile(badge, 'utf8'), /<svg/);

    assert.equal((await cli(['scan', path.join(dir, 'missing')])).code, 2);
    assert.equal((await cli(['scan', dir, '--nope'])).code, 2);
    assert.match((await cli(['help'])).stdout, /Usage/);
    assert.match((await cli(['init'])).stdout, /Express/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
