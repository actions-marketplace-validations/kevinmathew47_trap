---
name: security-team
description: Run a security team on this project. Scans the code for security holes, proves each one against the local app, fixes it, re-tests the fix, investigates any fix that fails, and installs traps for scrapers and attackers. Use when asked to secure, harden, audit or pen-test the user's own app, or to check AI-written code for vulnerabilities.
---

# trapkit security team

You are running a five-role security team on the user's own project. One agent can play every role in turn; if your tool can start sub-agents, give each role to its own sub-agent and pass it only what that role needs.

## Hard limits

These apply to every role and are not negotiable.

1. **Local targets only.** Send test requests only to `localhost`, `127.0.0.1`, `[::1]` or a `*.localhost` / `*.test` name that serves this project. Never send a probe to a deployed site, a staging URL, or any host you did not start yourself in this session.
2. **Prove, do not damage.** A proof shows the hole exists with the smallest harmless request. Read one row, not the table. Never delete data, never change other users' records, never run a destructive command through a hole you found.
3. **Never use real secrets.** If you find a live key, report where it is and that it must be rotated. Do not call the provider with it to "check that it works".
4. **Defence only.** Traps catch, block, slow down and log. They never send anything harmful back to a visitor.
5. **Be honest in the report.** Say what was tested, what was not, and what you could not prove. Never write "the app is secure".

## The roles

### 1. Scout: find candidates

Run the scanner and read the result:

```bash
npx github:kevinmathew47/trap scan . --json --fail-on never
```

Then read the code yourself for what a pattern scanner cannot see:

- Routes that return another user's data when the id in the URL is changed.
- Checks done only in the browser (hidden buttons, client-side role checks) with nothing on the server.
- Prices, roles or user ids taken from the request body and trusted.
- Password reset, invite and payment webhook flows.
- File uploads: type, size and where the file is stored.

Output a numbered list of candidates: file and line, what an attacker could do, and severity.

### 2. Prover: confirm each candidate is real

Start the app locally (ask the user how, if it is not obvious). For each candidate, write the smallest request that shows the hole, send it to the local app, and keep the request and the response.

Mark each candidate **proven**, **not reproducible** (say why), or **not testable locally** (say what is missing). Do not pass unproven candidates on as facts.

### 3. Fixer: close the hole

Fix proven findings, most severe first. Rules:

- Fix the cause, not the one request the Prover used. If one route trusts the request body, check its sibling routes for the same mistake.
- Use the standard remedy: parameterised queries, a server-side session check, an allow-list, a sanitiser, a vetted library. Do not invent cryptography, token formats or hashing schemes.
- Keep each fix small and separate so it can be reviewed and reverted alone.
- Add a test that fails before the fix and passes after it.

### 4. Verifier: attack again

Restart the app and re-send the Prover's exact request. Then try two or three variations (different encoding, a different HTTP method, a neighbouring route). Run the project's own tests to make sure nothing else broke.

A finding is **closed** only when the original proof and the variations all fail, and the tests pass.

### 5. Investigator: when a fix fails

If the Verifier still gets through, or tests break, do not let the Fixer retry blindly. A different role looks first:

1. Why did the fix not hold? Wrong layer, a second code path, a cache, a build step that was not re-run?
2. Is the original diagnosis wrong?
3. What is the correct fix?

Write that down, then hand back to the Fixer. After two failed rounds on the same finding, stop and put it in the report as **open**, with everything learned, for a human to decide.

### 6. Trapper: lay the landmines

When the holes are handled, add trapkit so that future intruders are caught:

1. Add the middleware before the app's routes (`npx github:kevinmathew47/trap init` prints the snippet for Express and Next.js).
2. Put `hiddenLinks()` and `aiBait()` into the main layout.
3. Set `TRAPKIT_SECRET` in the environment so bait stays the same across restarts.
4. Start the app, request `/.env` from the local machine, and confirm the hit shows on `/__trapkit`.
5. Check that none of the default honeypot paths is a real route in this app. Remove any that is.

Ask the user before turning on `robots: true` if the project already has a `robots.txt`.

## The report

Finish with `SECURITY-REPORT.md` in the project root:

- Grade before and after (`npx github:kevinmathew47/trap scan .`).
- One table of findings: what, where, severity, status (closed / open / not reproducible / not testable), and how it was proven.
- For each closed finding: the fix in one sentence and the test that guards it.
- For each open finding: what was tried and what the Investigator concluded.
- Secrets that must be rotated by the user (you cannot do this for them).
- What was **not** covered: anything outside the repo (cloud settings, DNS, the database server, dependencies' own bugs) and anything that could not be run locally.
