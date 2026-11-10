// A tiny shop with traps. Run:  npm run demo   then open http://localhost:3000
// No dependencies: plain node:http, with trapkit in front.

import http from 'node:http';
import { trapkit } from '../../src/index.js';

const traps = trapkit({
  secret: process.env.TRAPKIT_SECRET || 'demo-secret',
  robots: true,
  tarpitMs: Number(process.env.TARPIT_MS ?? 1500),
});

const page = (title, body) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>${title}</title>
<style>body{font:16px/1.6 system-ui,sans-serif;max-width:640px;margin:48px auto;padding:0 16px}code{background:#eee;padding:2px 6px;border-radius:4px}</style>
</head><body>
<h1>${title}</h1>
${body}
<p><a href="/">Home</a> · <a href="/products">Products</a> · <a href="/__trapkit">Trap dashboard</a></p>
${traps.hiddenLinks()}
${traps.aiBait()}
</body></html>`;

const server = http.createServer((req, res) => {
  if (traps.handle(req, res)) return; // a trap answered; the app never sees the request

  const path = req.url.split('?')[0];
  res.setHeader('content-type', 'text/html; charset=utf-8');
  if (path === '/') {
    res.end(
      page(
        'Demo shop',
        `<p>This page looks normal to you. It also holds three invisible links and a hidden note for AI agents.</p>
         <p>Try being a bad bot from another terminal:</p>
         <p><code>curl http://localhost:3000/.env</code></p>
         <p>Then reload this page, and open the dashboard.</p>`
      )
    );
  } else if (path === '/products') {
    res.end(page('Products', '<ul><li>Blue mug - $12</li><li>Green mug - $14</li></ul>'));
  } else {
    res.statusCode = 404;
    res.end(page('Not found', '<p>Nothing here.</p>'));
  }
});

const port = Number(process.env.PORT || 3000);
server.listen(port, '127.0.0.1', () => {
  console.log(`Demo shop:       http://localhost:${port}`);
  console.log(`Trap dashboard:  http://localhost:${port}/__trapkit`);
});
