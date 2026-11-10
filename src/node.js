// Node adapter: Express / Connect / Fastify-middie / plain http.

import { appendFile } from 'node:fs';
import { createTrapkit, normalizeIp } from './core.js';

function clientIp(req, trustProxy) {
  if (trustProxy) {
    const forwarded = req.headers['x-forwarded-for'];
    const first = String(Array.isArray(forwarded) ? forwarded[0] : forwarded || '').split(',')[0].trim();
    if (first) return normalizeIp(first);
  }
  return normalizeIp(req.socket?.remoteAddress);
}

function bodyText(req) {
  const body = req.body;
  if (body == null) return undefined;
  if (typeof body === 'string') return body;
  if (Buffer.isBuffer(body)) return body.toString('utf8', 0, 65_536);
  try {
    return JSON.stringify(body);
  } catch {
    return undefined;
  }
}

/**
 * Create trapkit middleware.
 *
 *   app.use(trapkit())                      // Express, Connect
 *   if (traps.handle(req, res)) return;     // plain node:http
 *
 * Extra Node-only options: `logFile` (JSON lines), `trustProxy` (read X-Forwarded-For).
 */
export function trapkit(options = {}) {
  const trustProxy = options.trustProxy === true;
  const logFile = options.logFile || null;
  let logFailed = false;

  const engine = createTrapkit({
    ...options,
    onEvent(event) {
      if (logFile && !logFailed) {
        appendFile(logFile, JSON.stringify(event) + '\n', (error) => {
          if (error && !logFailed) {
            logFailed = true;
            console.error(`[trapkit] could not write to ${logFile}: ${error.message}`);
          }
        });
      }
      if (typeof options.onEvent === 'function') options.onEvent(event);
    },
  });

  function handle(req, res) {
    const decision = engine.inspect({
      method: req.method,
      url: req.originalUrl || req.url,
      headers: req.headers,
      ip: clientIp(req, trustProxy),
      body: bodyText(req),
    });
    if (decision.action === 'pass') return false;

    const send = () => {
      decision.release();
      if (res.destroyed || res.writableEnded) return;
      res.writeHead(decision.status, decision.headers);
      res.end(req.method === 'HEAD' ? undefined : decision.body);
    };
    if (decision.delayMs > 0) {
      const timer = setTimeout(send, decision.delayMs);
      res.on('close', () => {
        clearTimeout(timer);
        decision.release();
      });
    } else {
      send();
    }
    return true;
  }

  function middleware(req, res, next) {
    if (!handle(req, res) && typeof next === 'function') next();
  }

  return Object.assign(middleware, engine, { handle });
}
