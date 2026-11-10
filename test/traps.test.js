import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createTrapkit, classifyClient } from '../src/core.js';
import { trapkit } from '../src/node.js';
import { webTrap } from '../src/web.js';

const req = (url, extra = {}) => ({ method: 'GET', url, ip: '203.0.113.9', headers: { 'user-agent': 'Mozilla/5.0' }, ...extra });
const make = (options = {}) => createTrapkit({ secret: 'test-secret', tarpitMs: 0, ...options });

test('normal requests pass through', () => {
  const tk = make();
  assert.equal(tk.inspect(req('/')).action, 'pass');
  assert.equal(tk.inspect(req('/products?id=4')).action, 'pass');
  assert.equal(tk.stats().trapsTriggered, 0);
});

test('honeypot path serves fake secrets and bans the client', () => {
  const tk = make();
  const hit = tk.inspect(req('/.env'));
  assert.equal(hit.action, 'respond');
  assert.equal(hit.status, 200);
  assert.match(hit.body, /STRIPE_SECRET_KEY=/);
  assert.ok(hit.body.includes(tk.bait.STRIPE_SECRET_KEY));
  assert.ok(tk.isBanned('203.0.113.9'));

  const next = tk.inspect(req('/pricing'));
  assert.equal(next.action, 'respond');
  assert.match(next.body, /<!doctype html>/);
  assert.match(next.body, /\/__tk\/m\//);

  // other visitors are not affected
  assert.equal(tk.inspect(req('/pricing', { ip: '198.51.100.1' })).action, 'pass');
  assert.equal(tk.events()[0].type, 'honeypot');
});

test('honeypot matching ignores case, query strings and encoding', () => {
  for (const url of ['/.ENV', '/.env?x=1', '/%2Eenv', '//.env', '/wp-admin/setup.php', 'http://site.test/.git/config']) {
    const tk = make();
    assert.equal(tk.inspect(req(url)).action, 'respond', url);
    assert.equal(tk.stats().trapsTriggered, 1, url);
  }
  const tk = make();
  assert.equal(tk.inspect(req('/.environment-docs')).action, 'pass');
});

test('block mode answers 403 after a trap hit', () => {
  const tk = make({ mode: 'block' });
  assert.equal(tk.inspect(req('/wp-login.php')).status, 404);
  assert.equal(tk.inspect(req('/')).status, 403);
});

test('monitor mode records but never bans', () => {
  const tk = make({ mode: 'monitor' });
  tk.inspect(req('/.env'));
  assert.equal(tk.isBanned('203.0.113.9'), false);
  assert.equal(tk.inspect(req('/')).action, 'pass');
  assert.equal(tk.stats().trapsTriggered, 1);
});

test('hidden links and AI bait are caught', () => {
  const tk = make();
  const link = /href="([^"]+)"/.exec(tk.hiddenLinks())[1];
  assert.ok(link.startsWith('/__tk/l/'));
  tk.inspect(req(link));
  assert.equal(tk.events()[0].type, 'hidden-link');

  const bait = /(\/__tk\/ai\/[a-z0-9]+)/.exec(tk.aiBait())[1];
  tk.inspect(req(bait, { ip: '198.51.100.7', headers: { 'user-agent': 'ClaudeBot/1.0' } }));
  assert.equal(tk.events()[0].type, 'ai-bait');
  assert.equal(tk.events()[0].client, 'ai-agent');
});

test('bait is stable for the same secret and differs between secrets', () => {
  assert.equal(make().hiddenLinks(), make().hiddenLinks());
  assert.notEqual(make().hiddenLinks(), make({ secret: 'other' }).hiddenLinks());
  assert.notEqual(make().bait.JWT_SECRET, make({ secret: 'other' }).bait.JWT_SECRET);
});

test('a stolen fake secret is detected wherever it is used', () => {
  const places = [
    (key) => req('/api/charge', { headers: { authorization: `Bearer ${key}` } }),
    (key) => req(`/api/charge?key=${encodeURIComponent(key)}`),
    (key) => req('/api/charge', { method: 'POST', body: JSON.stringify({ apiKey: key }) }),
    (key) => req('/api/charge', { headers: { authorization: 'Basic ' + btoa(`${key}:`) } }),
  ];
  for (const build of places) {
    const tk = make();
    const decision = tk.inspect(build(tk.bait.STRIPE_SECRET_KEY));
    assert.equal(decision.action, 'respond');
    assert.equal(tk.events()[0].type, 'canary');
    assert.equal(tk.events()[0].detail, 'bait:STRIPE_SECRET_KEY');
  }
});

test('custom canaries work and short ones are refused', () => {
  const tk = make({ canaries: ['my-planted-fake-token-123'] });
  tk.inspect(req('/x', { headers: { 'x-api-key': 'my-planted-fake-token-123' } }));
  assert.equal(tk.events()[0].type, 'canary');
  assert.throws(() => tk.addCanary('short'));
});

test('bans expire', () => {
  let clock = 1_000_000;
  const tk = make({ banMinutes: 10, now: () => clock });
  tk.inspect(req('/.env'));
  assert.ok(tk.isBanned('203.0.113.9'));
  clock += 10 * 60_000 + 1;
  assert.equal(tk.isBanned('203.0.113.9'), false);
  assert.equal(tk.inspect(req('/')).action, 'pass');
});

test('allow() lets a request skip the traps', () => {
  const tk = make({ allow: (info) => info.ip === '10.0.0.5' });
  assert.equal(tk.inspect(req('/.env', { ip: '10.0.0.5' })).action, 'pass');
  assert.equal(tk.stats().trapsTriggered, 0);
});

test('tarpit never holds more than maxTarpits responses', () => {
  const tk = make({ tarpitMs: 2000, maxTarpits: 1 });
  const first = tk.inspect(req('/.env'));
  const second = tk.inspect(req('/.env'));
  assert.equal(first.delayMs, 2000);
  assert.equal(second.delayMs, 0);
  first.release();
  first.release();
  assert.equal(tk.inspect(req('/.env')).delayMs, 2000);
});

test('robots.txt is served only when asked for', () => {
  assert.equal(make().inspect(req('/robots.txt')).action, 'pass');
  const served = make({ robots: true }).inspect(req('/robots.txt'));
  assert.match(served.body, /Disallow: \/__tk\//);
  assert.match(make().robotsTxt('User-agent: *\nAllow: /'), /Allow: \/\n\nUser-agent: \*\nDisallow: \/__tk\//);
});

test('dashboard is local-only without a password', () => {
  const tk = make();
  assert.equal(tk.inspect(req('/__trapkit')).status, 404);
  const local = tk.inspect(req('/__trapkit', { ip: '127.0.0.1' }));
  assert.equal(local.status, 200);
  assert.match(local.body, /trapkit/);
  assert.equal(tk.stats().trapsTriggered, 0);
});

test('dashboard password is enforced', () => {
  const tk = make({ dashboard: { password: 'open-sesame' } });
  const denied = tk.inspect(req('/__trapkit'));
  assert.equal(denied.status, 401);
  assert.match(denied.headers['www-authenticate'], /Basic/);
  const wrong = tk.inspect(req('/__trapkit', { headers: { authorization: 'Basic ' + btoa('admin:nope') } }));
  assert.equal(wrong.status, 401);
  const ok = tk.inspect(req('/__trapkit/events.json', { headers: { authorization: 'Basic ' + btoa('admin:open-sesame') } }));
  assert.equal(ok.status, 200);
  assert.deepEqual(Object.keys(JSON.parse(ok.body)), ['stats', 'bans', 'events']);
});

test('dashboard escapes attacker-controlled text', () => {
  const tk = make();
  tk.inspect(req('/.env', { headers: { 'user-agent': '<script>alert(1)</script>' } }));
  tk.inspect(req('/__tk/"><img src=x onerror=alert(2)>', { ip: '198.51.100.3' }));
  const page = tk.inspect(req('/__trapkit', { ip: '::1' })).body;
  assert.ok(!page.includes('<script>alert(1)</script>'));
  assert.ok(!page.includes('<img src=x'));
  assert.ok(page.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
});

test('event list is capped', () => {
  const tk = make({ maxEvents: 10, mode: 'monitor' });
  for (let i = 0; i < 50; i++) tk.inspect(req('/.env'));
  assert.equal(tk.events().length, 10);
  assert.equal(tk.stats().trapsTriggered, 50);
});

test('clients are classified by user agent', () => {
  assert.equal(classifyClient('Mozilla/5.0 (compatible; GPTBot/1.2)'), 'ai-agent');
  assert.equal(classifyClient('sqlmap/1.7'), 'scanner');
  assert.equal(classifyClient('python-requests/2.31'), 'script');
  assert.equal(classifyClient(''), 'no-user-agent');
  assert.equal(classifyClient('Mozilla/5.0 (Windows NT 10.0) Chrome/130'), 'browser-like');
});

test('node middleware works on a real http server', async () => {
  const traps = trapkit({ secret: 'test-secret', tarpitMs: 0 });
  const server = http.createServer((request, response) => {
    traps(request, response, () => {
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end('real page');
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    assert.equal(await (await fetch(base + '/')).text(), 'real page');
    const env = await (await fetch(base + '/.env')).text();
    assert.match(env, /DATABASE_URL=postgres/);
    const after = await fetch(base + '/');
    assert.match(await after.text(), /<!doctype html>/);
    assert.equal(after.headers.get('x-robots-tag'), 'noindex, nofollow');
    assert.equal(traps.stats().activeBans, 1);
    assert.ok(traps.unban('127.0.0.1'));
    assert.equal(await (await fetch(base + '/')).text(), 'real page');
  } finally {
    server.close();
  }
});

test('trustProxy decides whether X-Forwarded-For is believed', async () => {
  for (const [trustProxy, expected] of [[false, '127.0.0.1'], [true, '198.51.100.77']]) {
    const traps = trapkit({ secret: 's', tarpitMs: 0, trustProxy });
    const server = http.createServer((request, response) => traps(request, response, () => response.end('ok')));
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
      await fetch(`http://127.0.0.1:${server.address().port}/.env`, { headers: { 'x-forwarded-for': '198.51.100.77' } }).then((r) => r.text());
      assert.equal(traps.events()[0].ip, expected);
    } finally {
      server.close();
    }
  }
});

test('web adapter returns null for normal requests and a Response for traps', async () => {
  const trap = webTrap({ secret: 'test-secret', tarpitMs: 0 });
  const headers = { 'x-forwarded-for': '203.0.113.50' };
  assert.equal(await trap(new Request('https://site.test/', { headers })), null);
  const response = await trap(new Request('https://site.test/.env', { headers }));
  assert.equal(response.status, 200);
  assert.match(await response.text(), /JWT_SECRET=/);
  assert.ok(trap.isBanned('203.0.113.50'));
  const blocked = await trap(new Request('https://site.test/about', { headers }));
  assert.match(await blocked.text(), /<!doctype html>/);
});
