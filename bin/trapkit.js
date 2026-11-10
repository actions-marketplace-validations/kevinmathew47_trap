#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { scan } from '../src/scan/scan.js';
import { formatTerminal, formatMarkdown, formatBadge } from '../src/scan/report.js';

const HELP = `
trapkit - landmines for AI scrapers and attackers, plus a security scanner

Usage
  trapkit scan [folder]     Check a project for common security holes and grade it
  trapkit init              Show how to add the traps to your app
  trapkit help              Show this text

Options for scan
  --json                    Print the result as JSON
  --report <file>           Also write a Markdown report
  --badge <file>            Also write an SVG grade badge for your README
  --fail-on <level>         Exit with code 1 at this severity or worse:
                            critical, high (default), medium, low, never
  --ignore <pattern>        Skip matching paths (repeatable). A .trapkitignore file works too.
`;

const INIT = `
Add the traps to your app

  Express
    import express from 'express';
    import { trapkit } from 'trapkit';

    const traps = trapkit({ secret: process.env.TRAPKIT_SECRET, robots: true });
    const app = express();
    app.use(traps);                      // put it before your routes

    // in your HTML layout, anywhere inside <body>:
    //   \${traps.hiddenLinks()} \${traps.aiBait()}

  Next.js 16 (proxy.js; on older versions use middleware.js and name the function middleware)
    import { NextResponse } from 'next/server';
    import { webTrap } from 'trapkit/web';

    const trap = webTrap({ secret: process.env.TRAPKIT_SECRET });
    export async function proxy(request) {
      return (await trap(request)) ?? NextResponse.next();
    }

  Dashboard: open /__trapkit on localhost. To open it from elsewhere set
    dashboard: { password: process.env.TRAPKIT_DASHBOARD_PASSWORD }
`;

function parse(argv) {
  const args = { _: [], ignore: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--json') args.json = true;
    else if (arg === '--help' || arg === '-h') args.help = true;
    else if (arg === '--report' || arg === '--badge' || arg === '--fail-on' || arg === '--ignore') {
      const value = argv[++i];
      if (value === undefined) throw new Error(`${arg} needs a value`);
      if (arg === '--ignore') args.ignore.push(value);
      else args[arg.slice(2)] = value;
    } else if (arg.startsWith('--')) throw new Error(`unknown option ${arg}`);
    else args._.push(arg);
  }
  return args;
}

async function main() {
  const args = parse(process.argv.slice(2));
  const command = args._[0] || 'help';

  if (args.help || command === 'help') {
    console.log(HELP);
    return 0;
  }
  if (command === 'init') {
    console.log(INIT);
    return 0;
  }
  if (command !== 'scan') throw new Error(`unknown command "${command}". Try: trapkit help`);

  const failOn = args['fail-on'] || 'high';
  const levels = ['critical', 'high', 'medium', 'low'];
  if (failOn !== 'never' && !levels.includes(failOn)) throw new Error('--fail-on must be critical, high, medium, low or never');

  const result = await scan(args._[1] || '.', { ignore: args.ignore });
  if (args.report) await writeFile(args.report, formatMarkdown(result));
  if (args.badge) await writeFile(args.badge, formatBadge(result));

  if (args.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    const color = process.stdout.isTTY && !process.env.NO_COLOR;
    console.log(formatTerminal(result, { color }));
    if (args.report) console.log(`  Report written to ${args.report}`);
    if (args.badge) console.log(`  Badge written to ${args.badge}`);
  }

  if (failOn === 'never') return 0;
  const failing = levels.slice(0, levels.indexOf(failOn) + 1);
  return failing.some((level) => result.counts[level] > 0) ? 1 : 0;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (error) => {
    console.error(`trapkit: ${error.message}`);
    process.exitCode = 2;
  }
);
