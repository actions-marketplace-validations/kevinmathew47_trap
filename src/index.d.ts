export type TrapMode = 'maze' | 'block' | 'monitor';

export interface TrapEvent {
  id: number;
  time: string;
  type: 'honeypot' | 'hidden-link' | 'robots-bait' | 'ai-bait' | 'canary';
  ip: string;
  client: 'ai-agent' | 'scanner' | 'script' | 'crawler' | 'browser-like' | 'no-user-agent';
  userAgent: string;
  method: string;
  path: string;
  detail: string;
}

export interface TrapOptions {
  /** Keeps bait links and fake secrets the same across restarts. Random per process when omitted. */
  secret?: string;
  /** What happens to a caught client. Default 'maze'. */
  mode?: TrapMode;
  /** URL prefix that holds the traps. Default '/__tk'. */
  prefix?: string;
  /** How long a caught client stays banned. Default 60. */
  banMinutes?: number;
  /** Delay before each response to a caught client, in ms (max 10000). Default 1500. */
  tarpitMs?: number;
  /** Most delayed responses held open at once. Default 50. */
  maxTarpits?: number;
  /** Paths that no real user requests. Defaults to a list of commonly probed files. */
  honeypotPaths?: string[];
  /** Extra fake secrets to watch for in incoming requests. */
  canaries?: string[];
  /** Serve a robots.txt that forbids the trap area. Default false. */
  robots?: boolean;
  /** Return true to let a request skip all traps. */
  allow?: (info: { ip: string; path: string; userAgent: string; method: string }) => boolean;
  onEvent?: (event: TrapEvent) => void;
  /** Dashboard location and password, or false to turn it off. Without a password it only opens from localhost. */
  dashboard?: false | { path?: string; password?: string };
  /** Node only: append every trap hit to this file as JSON lines. */
  logFile?: string;
  /** Read the client IP from X-Forwarded-For. Turn on only behind a proxy you control. */
  trustProxy?: boolean;
}

export interface TrapApi {
  hiddenLinks(): string;
  aiBait(): string;
  robotsTxt(existing?: string): string;
  addCanary(value: string): string;
  bait: Record<string, string>;
  events(limit?: number): TrapEvent[];
  bans(): Array<{ ip: string; since: string; until: string; reasons: string[]; wastedResponses: number }>;
  stats(): {
    requests: number;
    trapsTriggered: number;
    wastedResponses: number;
    activeBans: number;
    byType: Record<string, number>;
    byClient: Record<string, number>;
  };
  isBanned(ip: string): boolean;
  unban(ip: string): boolean;
  prefix: string;
  mode: TrapMode;
}

export type TrapMiddleware = ((req: any, res: any, next?: () => void) => void) &
  TrapApi & { handle(req: any, res: any): boolean };

export function trapkit(options?: TrapOptions): TrapMiddleware;
export default trapkit;

export function createTrapkit(options?: TrapOptions): TrapApi & { inspect(request: any): any };
export function classifyClient(userAgent: string): TrapEvent['client'];
export const DEFAULT_HONEYPOTS: string[];

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface Finding {
  rule: string;
  title: string;
  severity: Severity;
  file: string;
  line: number;
  snippet: string;
  fix: string;
}

export interface ScanResult {
  root: string;
  filesScanned: number;
  findings: Finding[];
  counts: Record<Severity, number>;
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
}

export function scan(root: string, options?: { ignore?: string[] }): Promise<ScanResult>;
export function grade(findings: Finding[]): { score: number; grade: ScanResult['grade']; counts: Record<Severity, number> };
