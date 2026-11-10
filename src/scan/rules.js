// Scanner rules. Each line rule is a regex with a plain-language title and fix.
// These are pattern checks: they catch common mistakes, they do not prove an app is safe.

const JS = ['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'vue', 'svelte', 'html'];
const PY = ['py'];
const USER_INPUT = '(?:req|request|ctx)\\.(?:query|body|params|headers|cookies)';

const PLACEHOLDER = /your|xxxx|example|changeme|change_me|placeholder|dummy|sample|redacted|todo|\*{3}|<[^>]+>|\$\{|process\.env|import\.meta|os\.environ|getenv/i;

function looksRandom(value) {
  if (PLACEHOLDER.test(value)) return false;
  if (/^(.)\1+$/.test(value)) return false;
  if (!/[0-9]/.test(value) || !/[a-zA-Z]/.test(value)) return false;
  return new Set(value).size >= 8;
}

/** @type {Array<{id:string,title:string,severity:string,fix:string,exts?:string[],secret?:boolean,skipComments?:boolean,pattern:RegExp,accept?:(m:RegExpExecArray,line:string,file:object)=>boolean}>} */
export const LINE_RULES = [
  // --- secrets ---------------------------------------------------------------------------------
  {
    id: 'secret-aws-key',
    title: 'AWS access key in the code',
    severity: 'critical',
    secret: true,
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    fix: 'Delete it from the code, rotate the key in AWS, and load it from an environment variable.',
  },
  {
    id: 'secret-stripe-key',
    title: 'Stripe live secret key in the code',
    severity: 'critical',
    secret: true,
    pattern: /\b[sr]k_live_[0-9a-zA-Z]{20,}\b/,
    fix: 'Roll the key in the Stripe dashboard and load it from an environment variable on the server only.',
  },
  {
    id: 'secret-ai-key',
    title: 'AI provider API key in the code',
    severity: 'critical',
    secret: true,
    pattern: /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}/,
    fix: 'Revoke the key with the provider and load a new one from an environment variable on the server only.',
  },
  {
    id: 'secret-github-token',
    title: 'GitHub token in the code',
    severity: 'critical',
    secret: true,
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b/,
    fix: 'Revoke the token on GitHub and load a new one from an environment variable.',
  },
  {
    id: 'secret-slack-token',
    title: 'Slack token in the code',
    severity: 'high',
    secret: true,
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}/,
    fix: 'Revoke the token in Slack and load a new one from an environment variable.',
  },
  {
    id: 'secret-private-key',
    title: 'Private key stored in the repo',
    severity: 'critical',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
    fix: 'Remove the key from the repo, generate a new one, and keep it in a secret manager.',
  },
  {
    id: 'secret-hardcoded',
    title: 'Password or secret written directly in the code',
    severity: 'high',
    secret: true,
    skipEnvFiles: true,
    pattern: /(?:api[_-]?key|secret|passwd|password|private[_-]?key|access[_-]?token|auth[_-]?token)["']?\s*[:=]\s*["'`]([^"'`\s]{12,})["'`]/i,
    accept: (m) => looksRandom(m[1]),
    fix: 'Move the value to an environment variable and rotate it, because it is already in your git history.',
  },
  {
    id: 'public-env-secret',
    title: 'Secret exposed to the browser through a public env variable',
    severity: 'critical',
    pattern: /\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|PUBLIC)_[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|PASSWD)[A-Z0-9_]*/,
    fix: 'Variables with this prefix are shipped to every visitor. Rename it without the public prefix and use it only in server code.',
  },
  {
    id: 'service-role-in-client',
    title: 'Supabase service-role key used in browser code',
    severity: 'critical',
    exts: JS,
    clientOnly: true,
    pattern: /service_role|SERVICE_ROLE/,
    fix: 'The service-role key bypasses all database rules. Use it only on the server; the browser gets the anon key.',
  },

  // --- injection -------------------------------------------------------------------------------
  {
    id: 'sql-injection',
    title: 'SQL query built by gluing in values',
    severity: 'critical',
    exts: JS,
    skipComments: true,
    pattern: new RegExp(
      '\\b(?:query|execute|raw|all|get|run|prepare|\\$queryRawUnsafe|\\$executeRawUnsafe)\\s*\\(\\s*`[^`]*\\b(?:select|insert|update|delete|where)\\b[^`]*\\$\\{' +
        '|\\b(?:select|insert into|update|delete from)\\b[^;]*["\'`]\\s*\\+\\s*(?:' + USER_INPUT + '|\\w*(?:id|name|input|email|search|term)\\b)',
      'i'
    ),
    fix: 'Use placeholders (?, $1) and pass the values as parameters so user input can never change the query.',
  },
  {
    id: 'sql-injection',
    title: 'SQL query built by gluing in values',
    severity: 'critical',
    exts: PY,
    skipComments: true,
    pattern: /\.execute\(\s*(?:f["']|["'][^"']*["']\s*(?:%|\.format\(|\+))/,
    fix: 'Pass values as the second argument of execute() and use %s or ? placeholders in the query.',
  },
  {
    id: 'command-injection',
    title: 'Shell command built from variables',
    severity: 'critical',
    exts: JS,
    skipComments: true,
    pattern: new RegExp(
      '(?:(?:^|[^.\\w])|(?:child_process|cp)\\.)(?:exec|execSync)\\s*\\(\\s*(?:`[^`]*\\$\\{|[^)]*\\+\\s*\\w|' + USER_INPUT + ')'
    ),
    fix: 'Use execFile or spawn with an argument array, and never pass user input to a shell.',
  },
  {
    id: 'command-injection',
    title: 'Shell command built from variables',
    severity: 'critical',
    exts: PY,
    skipComments: true,
    pattern: /subprocess\.\w+\([^)]*shell\s*=\s*True|os\.system\(\s*(?:f["']|[^)]*(?:\+|%|\.format\())/,
    fix: 'Call subprocess.run with a list of arguments and without shell=True.',
  },
  {
    id: 'eval',
    title: 'Code is executed from a string',
    severity: 'high',
    exts: [...JS, ...PY],
    skipComments: true,
    pattern: /(?:^|[^.\w])eval\s*\(\s*(?!["'`][^"'`]*["'`]\s*\))|new\s+Function\s*\(/,
    fix: 'Remove eval. Parse data with JSON.parse (or ast.literal_eval in Python) and call real functions.',
  },
  {
    id: 'path-traversal',
    title: 'File path comes straight from the request',
    severity: 'high',
    exts: JS,
    skipComments: true,
    pattern: new RegExp('(?:readFile|readFileSync|createReadStream|sendFile|download|unlink|unlinkSync|writeFile|writeFileSync)\\s*\\([^)]*' + USER_INPUT),
    fix: 'Resolve the path, then check it still starts with the folder you intend to serve before touching the file.',
  },
  {
    id: 'ssrf',
    title: 'Server fetches a URL chosen by the visitor',
    severity: 'high',
    exts: JS,
    skipComments: true,
    pattern: new RegExp('(?:fetch|axios(?:\\.\\w+)?|got(?:\\.\\w+)?|request)\\s*\\(\\s*(?:' + USER_INPUT + '|[^)]*searchParams\\.get\\()'),
    fix: 'Check the URL against a list of hosts you allow, and block private/internal addresses.',
  },
  {
    id: 'open-redirect',
    title: 'Redirect target comes straight from the request',
    severity: 'medium',
    exts: JS,
    skipComments: true,
    pattern: new RegExp('redirect\\s*\\(\\s*(?:' + USER_INPUT + '|[^)]*searchParams\\.get\\()'),
    fix: 'Only redirect to paths on your own site, or to a fixed list of allowed URLs.',
  },
  {
    id: 'mass-assignment',
    title: 'Whole request body saved to the database',
    severity: 'medium',
    exts: JS,
    skipComments: true,
    pattern: /\.(?:create|update|updateOne|updateMany|findOneAndUpdate|findByIdAndUpdate|insert|insertOne|upsert)\s*\((?:[^)]*,)?\s*(?:\{\s*(?:data|\$set)\s*:\s*)?(?:req|request)\.body\s*[,)}]/,
    fix: 'Pick the exact fields you accept. Otherwise a visitor can set fields like "role" or "isAdmin".',
  },

  // --- browser / XSS ---------------------------------------------------------------------------
  {
    id: 'xss-raw-html',
    title: 'Raw HTML inserted into the page',
    severity: 'medium',
    exts: JS,
    skipComments: true,
    pattern: /dangerouslySetInnerHTML|\bv-html\s*=|\{@html\s|\.innerHTML\s*\+?=(?!=)(?!\s*["'`][^"'`$]*["'`]\s*;?\s*$)|\.insertAdjacentHTML\s*\(/,
    fix: 'Render text instead of HTML. If you must render HTML, clean it first with a sanitizer such as DOMPurify.',
  },

  // --- configuration ---------------------------------------------------------------------------
  {
    id: 'cors-wildcard',
    title: 'Any website may call this API (CORS is wide open)',
    severity: 'medium',
    skipComments: true,
    pattern: /Access-Control-Allow-Origin["']?\s*[,:]\s*["']\*["']|\borigin\s*:\s*(?:["']\*["']|true)\s*[,}]|\bcors\(\s*\)|allow_origins\s*=\s*\[\s*["']\*["']/,
    fix: 'List the exact origins of your own frontends instead of allowing everyone.',
  },
  {
    id: 'tls-check-disabled',
    title: 'HTTPS certificate checking is turned off',
    severity: 'high',
    skipComments: true,
    pattern: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED["'\]]*\s*=\s*["']?0|\bverify\s*=\s*False/,
    fix: 'Turn certificate checking back on. Without it anyone on the network can read and change the traffic.',
  },
  {
    id: 'jwt-none',
    title: 'Login tokens accepted without a signature',
    severity: 'critical',
    skipComments: true,
    pattern: /algorithms?\s*[:=]\s*\[?\s*["']none["']/i,
    fix: 'Remove "none" and allow only the algorithm you sign with, for example HS256 or RS256.',
  },
  {
    id: 'jwt-hardcoded-secret',
    title: 'Login tokens signed with a secret written in the code',
    severity: 'high',
    exts: JS,
    skipComments: true,
    pattern: /jwt\.(?:sign|verify)\s*\([^)]*,\s*["'`][^"'`]{1,64}["'`]/,
    fix: 'Load a long random secret from an environment variable. Anyone who reads this code can forge logins.',
  },
  {
    id: 'jwt-decode-only',
    title: 'Token is decoded but not verified',
    severity: 'medium',
    exts: JS,
    skipComments: true,
    pattern: /\bjwt\.decode\s*\(|\bjwtDecode\s*\(|\bjwt_decode\s*\(/,
    fix: 'decode() does not check the signature. Use verify() on the server before trusting anything in the token.',
  },
  {
    id: 'cookie-not-httponly',
    title: 'Cookie can be read by scripts in the page',
    severity: 'medium',
    skipComments: true,
    pattern: /httpOnly\s*:\s*false|httponly\s*=\s*False/,
    fix: 'Set httpOnly: true on session cookies so injected scripts cannot steal them.',
  },
  {
    id: 'weak-hash',
    title: 'Weak hash function (MD5 or SHA-1)',
    severity: 'medium',
    skipComments: true,
    pattern: /createHash\(\s*["'](?:md5|sha1)["']\s*\)|hashlib\.(?:md5|sha1)\s*\(/,
    fix: 'For passwords use bcrypt, scrypt or argon2. For everything else use SHA-256.',
  },
  {
    id: 'weak-random',
    title: 'Math.random() used for something secret',
    severity: 'medium',
    exts: JS,
    skipComments: true,
    pattern: /Math\.random\s*\(\)/,
    accept: (m, line) => /token|secret|password|passwd|otp|session|nonce|reset|invite|api[_-]?key|verif/i.test(line),
    fix: 'Math.random() is guessable. Use crypto.randomBytes or crypto.randomUUID.',
  },
  {
    id: 'firebase-open-rules',
    title: 'Firebase rules let anyone read or write',
    severity: 'critical',
    exts: ['rules', 'json'],
    pattern: /allow\s+[\w,\s]+:\s*if\s+true\s*;|"\.(?:read|write)"\s*:\s*(?:true|"true")/,
    fix: 'Require request.auth != null and check that the user owns the document.',
  },

  // --- Python ----------------------------------------------------------------------------------
  {
    id: 'unsafe-deserialization',
    title: 'Untrusted data loaded with pickle or yaml.load',
    severity: 'high',
    exts: PY,
    skipComments: true,
    pattern: /\bpickle\.loads?\s*\(|\byaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader)/,
    fix: 'Use json for data from outside, and yaml.safe_load for YAML.',
  },
  {
    id: 'debug-mode',
    title: 'Debug mode is on',
    severity: 'medium',
    exts: PY,
    skipComments: true,
    pattern: /\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True\b/,
    fix: 'Turn debug off in production. Debug pages show your code and can let visitors run commands.',
  },
];

const AUTH_HINT = /auth|session|getuser|currentuser|gettoken|verify|authorization|jwt|clerk|signature|api[_-]?key|bearer|cookies\(|permission|isadmin|requireuser|protect/i;
const MUTATION = /export\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b|export\s+const\s+(POST|PUT|PATCH|DELETE)\b/;

/** Rules that need the whole file. Each returns an array of {line, snippet} hits. */
export const FILE_RULES = [
  {
    id: 'api-route-no-auth',
    title: 'API route changes data but has no login check',
    severity: 'high',
    fix: 'Check who is calling at the top of the handler and return 401 when nobody is logged in.',
    applies: (file) => /(?:^|\/)app\/(?:.*\/)?api\/.*route\.(?:js|ts)x?$|(?:^|\/)pages\/api\/.*\.(?:js|ts)x?$/.test(file.rel),
    check(file) {
      if (AUTH_HINT.test(file.text)) return [];
      const isPages = /(?:^|\/)pages\/api\//.test(file.rel);
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        if (MUTATION.test(line)) return [{ line: i + 1, snippet: line }];
        if (isPages && /export\s+default\b/.test(line) && /req\.method|req\.body/.test(file.text)) {
          return [{ line: i + 1, snippet: line }];
        }
      }
      return [];
    },
  },
  {
    id: 'supabase-no-rls',
    title: 'Database table without row level security',
    severity: 'high',
    fix: 'Add "alter table <name> enable row level security;" and write policies. Without it anyone with the anon key can read the table.',
    applies: (file) => file.ext === 'sql' && /supabase/i.test(file.rel),
    check(file) {
      const hits = [];
      const lower = file.text.toLowerCase();
      for (let i = 0; i < file.lines.length; i++) {
        const m = /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?"?([a-z_][a-z0-9_]*)"?/i.exec(file.lines[i]);
        if (!m) continue;
        const name = m[1].toLowerCase();
        const enabled = new RegExp(`alter\\s+table\\s+(?:if\\s+exists\\s+)?(?:only\\s+)?(?:public\\.)?"?${name}"?\\s+enable\\s+row\\s+level\\s+security`).test(lower);
        if (!enabled) hits.push({ line: i + 1, snippet: file.lines[i] });
      }
      return hits;
    },
  },
];

const SERVER_FRAMEWORKS = ['express', 'fastify', 'koa', 'hono', 'next', '@nestjs/core'];
const RATE_LIMITERS = /rate-?limit|ratelimit|bottleneck|slow-down|throttl|trapkit/i;

/** Rules about the project as a whole. Each returns an array of {file, line, snippet}. */
export const PROJECT_RULES = [
  {
    id: 'env-file-not-ignored',
    title: '.env file is not ignored by git',
    severity: 'critical',
    fix: 'Add ".env*" to .gitignore. If the file was ever committed, rotate every secret in it.',
    check(project) {
      const tracked = project.envFiles.filter((name) => !/\.(?:example|sample|template)$/.test(name));
      if (tracked.length === 0) return [];
      if (/^\s*(?:\*\*\/)?\.env(?:\*|\..*)?\s*$/m.test(project.gitignore) || /^\s*\*\.env\s*$/m.test(project.gitignore)) return [];
      return tracked.map((file) => ({ file, line: 1, snippet: project.gitignore ? '.gitignore does not list this file' : 'there is no .gitignore' }));
    },
  },
  {
    id: 'no-rate-limit',
    title: 'No rate limiting found',
    severity: 'low',
    fix: 'Add a rate limiter to login and API routes so one client cannot hammer them.',
    check(project) {
      const deps = project.dependencies;
      if (!SERVER_FRAMEWORKS.some((name) => deps.includes(name))) return [];
      if (deps.some((name) => RATE_LIMITERS.test(name)) || project.mentionsRateLimit) return [];
      return [{ file: 'package.json', line: 1, snippet: 'no rate-limit package or code was found' }];
    },
  },
  {
    id: 'no-security-headers',
    title: 'Express app without security headers',
    severity: 'low',
    fix: 'Add the helmet package: app.use(helmet()).',
    check(project) {
      if (!project.dependencies.includes('express') || project.dependencies.includes('helmet')) return [];
      return [{ file: 'package.json', line: 1, snippet: 'express is installed but helmet is not' }];
    },
  },
];

export { RATE_LIMITERS };
