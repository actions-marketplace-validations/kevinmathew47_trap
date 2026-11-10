// Web-standard adapter (Request -> Response). For Next.js middleware, Hono, Cloudflare Workers, Deno, Bun.
//
//   // middleware.js (Next.js)
//   import { NextResponse } from 'next/server';
//   import { webTrap } from 'trapkit/web';
//   const trap = webTrap({ secret: process.env.TRAPKIT_SECRET });
//   export async function middleware(request) {
//     return (await trap(request)) ?? NextResponse.next();
//   }
//
// Note: bans live in memory. On serverless/edge each instance has its own memory, so a ban
// holds only on the instance that saw the trap hit. Traps and canaries still fire everywhere.

import { createTrapkit, normalizeIp } from './core.js';

export function webTrap(options = {}) {
  // There is no socket in a web runtime, so the forwarded header is the only source of the IP.
  const trustProxy = options.trustProxy !== false;
  const engine = createTrapkit(options);

  async function trap(request, context = {}) {
    let ip = context.ip;
    if (!ip && trustProxy) {
      ip = (request.headers.get('x-forwarded-for') || '').split(',')[0].trim() || request.headers.get('x-real-ip');
    }
    const decision = engine.inspect({
      method: request.method,
      url: request.url,
      headers: request.headers,
      ip: normalizeIp(ip),
    });
    if (decision.action === 'pass') return null;
    if (decision.delayMs > 0) await new Promise((resolve) => setTimeout(resolve, decision.delayMs));
    decision.release();
    return new Response(request.method === 'HEAD' ? null : decision.body, {
      status: decision.status,
      headers: decision.headers,
    });
  }

  return Object.assign(trap, engine);
}
