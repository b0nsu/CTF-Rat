export type EventRecord = {
  schema: string;
  stream_id: string;
  seq: number;
  event_id: string;
  at: string;
  actor: string;
  task_id: string;
  type: string;
  payload: Record<string, unknown>;
  caused_by: string[];
};

export type StateView = {
  observations: Record<string, unknown>;
  findings: Record<string, unknown>;
  primitives: Record<string, unknown>;
  hypotheses: Record<string, unknown>;
  ruled_out: Record<string, unknown>;
  unknowns: Record<string, unknown>;
  next_probes: unknown[];
  notes: unknown[];
  alerts: unknown[];
  failures: unknown[];
};

export type Snapshot = {
  schema: string;
  challenge_root: string;
  run: Record<string, unknown> | null;
  cursor: { stream_id: string | null; seq: number };
  event_count: number;
  total_event_count: number;
  historical: boolean;
  view: StateView;
};

export type EventCursor = {
  stream_id: string | null;
  seq: number;
  source_generation?: string;
};

export type Delta = {
  schema: string;
  stream_id: string | null;
  after_seq: number;
  events: EventRecord[];
  cursor: EventCursor;
  has_more: boolean;
  reset: boolean;
  unchanged: boolean;
};

export type LiveUpdate = {
  schema: string;
  delta: Delta;
  snapshot: Snapshot | null;
};

export type Session = {
  schema: string;
  configured: boolean;
  session_id: string | null;
  status: "idle" | "running" | "finished";
  pid: number | null;
  argv: string[];
  started_at: string | null;
  stopped_at: string | null;
  exit_code: number | null;
  elapsed_seconds: number | null;
  log_size: number;
};

export type Artifact = {
  schema: string;
  digest: string;
  size: number;
  kind: string;
  media_type: string;
  logical_name: string;
  created_at: string;
  provenance: Record<string, unknown>;
};

export type ArtifactListing = {
  schema: string;
  generation: string;
  unchanged: boolean;
  artifacts: Artifact[];
  total: number | null;
  has_more: boolean | null;
};

export type ArtifactPreview = {
  schema: string;
  metadata: Artifact;
  encoding: "utf-8" | "base64";
  content: string;
  truncated: boolean;
  preview_bytes: number;
  total_bytes: number;
};

export type SessionMetrics = {
  schema: "rat.session-metrics/v1";
  tool_calls: number;
  duplicate_tool_calls: number;
  cache_requests: number;
  cache_hits: number;
  cache_misses: number;
  cache_hit_ratio: number | null;
  time_to_first_valid_primitive_sec: number | null;
  time_to_verified_solve_sec: number | null;
  time_to_flag_sec: number | null;
  functions_decompiled: number;
  ghidra_runs: number;
  revq_runs: number;
  duration_ms_total: number;
  indexed_artifacts_by_backend: Record<string, number>;
};

export type Telemetry = {
  schema: string;
  event_count: number;
  event_types: Record<string, number>;
  groups: Record<string, number>;
  first_at: string | null;
  last_at: string | null;
  session: SessionMetrics;
};

export type Completion = {
  schema: "rat.desktop.completion/v1";
  verified: boolean;
  reason: string;
  detail?: string;
  primitive_id?: string;
  verification_id?: string;
  report_digest?: string;
  exploit_task_id?: string;
};

export type AnalysisInput = {
  role: string;
  name: string;
  sha256: string;
  size: number;
};

export type AnalysisTarget = {
  run_id: string | null;
  challenge: string | null;
  binary: AnalysisInput;
  libc: AnalysisInput | null;
};

export type AnalysisStatus = {
  schema: "rat.desktop.analysis-status/v1";
  ready: boolean;
  busy: boolean;
  target: AnalysisTarget | null;
  modes: {
    fast: boolean;
    deep: boolean;
    function: boolean;
    oracle: boolean;
    slice: boolean;
    verify_status: boolean;
  };
  reason: string | null;
};

export type BriefCard = {
  schema: "rat.brief-card/v1";
  binary: string;
  binary_sha256?: string | null;
  capabilities: Record<string, unknown>;
  route: Record<string, unknown>;
  track_summary: Record<string, unknown>;
  libc: Record<string, unknown>;
  truncated: unknown[];
  side_effects: unknown[];
};

export type AnalysisRun = {
  schema: "rat.desktop.analysis-run/v1";
  mode: "fast" | "deep";
  status: "ok" | "error" | "timeout";
  target: AnalysisTarget;
  duration_ms: number;
  exit_code: number;
  result: BriefCard | null;
  diagnostic: string | null;
};

export type QueryResult = {
  schema: "rat.query-result/v1";
  query: string;
  status: "ok" | "partial" | "error";
  facts: Record<string, unknown>;
  heuristics: Record<string, unknown>;
  artifacts: unknown[];
  coverage: { complete: boolean; scope: unknown; omitted: unknown };
  diagnostics: Array<Record<string, unknown>>;
  provenance: Record<string, unknown>;
};

export type FunctionQuery = {
  schema: "rat.desktop.function-query/v1";
  name: string;
  status: "ok" | "partial" | "error" | "timeout";
  target: AnalysisTarget;
  duration_ms: number;
  exit_code: number;
  result: QueryResult | null;
  diagnostic: string | null;
};

export type OracleQuery = {
  schema: "rat.desktop.oracle-query/v1";
  status: "ok" | "partial" | "error" | "timeout";
  target: AnalysisTarget;
  duration_ms: number;
  exit_code: number;
  result: QueryResult | null;
  diagnostic: string | null;
};

export type SliceQuery = {
  schema: "rat.desktop.slice-query/v1";
  backward: string;
  status: "ok" | "partial" | "error" | "timeout";
  target: AnalysisTarget;
  duration_ms: number;
  exit_code: number;
  result: QueryResult | null;
  diagnostic: string | null;
};

export type TerminalDelta = {
  schema: string;
  after: number;
  cursor: number;
  has_more: boolean;
  text: string;
};

export const API = import.meta.env.VITE_RATD_URL ?? "http://127.0.0.1:8765";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API}${path}`, { cache: "no-store", ...init });
  if (!response.ok) {
    let detail = `${response.status}`;
    try {
      const body = await response.json();
      detail = body.message ?? body.error ?? detail;
    } catch {
      // Keep HTTP status if the daemon did not return JSON.
    }
    throw new Error(detail);
  }
  return (await response.json()) as T;
}

function cursorParams(cursor: EventCursor | null, limit: number): URLSearchParams {
  const params = new URLSearchParams({
    after_seq: String(cursor?.seq ?? 0),
    limit: String(limit)
  });
  if (cursor?.stream_id) params.set("stream_id", cursor.stream_id);
  if (cursor?.source_generation) params.set("known_generation", cursor.source_generation);
  return params;
}

export function getSnapshot(untilSeq?: number): Promise<Snapshot> {
  const suffix = untilSeq === undefined ? "" : `?until_seq=${untilSeq}`;
  return request(`/api/snapshot${suffix}`);
}

export function getEvents(cursor: EventCursor | null, limit = 500): Promise<Delta> {
  return request(`/api/events?${cursorParams(cursor, limit).toString()}`);
}

export function getLiveUpdate(cursor: EventCursor | null, limit = 500): Promise<LiveUpdate> {
  return request(`/api/live?${cursorParams(cursor, limit).toString()}`);
}

export function getSession(): Promise<Session> {
  return request("/api/session");
}

export function getTerminal(after: number, limit = 65536): Promise<TerminalDelta> {
  return request(`/api/terminal?after=${after}&limit=${limit}`);
}

export function getArtifacts(knownGeneration: string | null = null, limit = 500): Promise<ArtifactListing> {
  const params = new URLSearchParams({ limit: String(limit) });
  if (knownGeneration) params.set("known_generation", knownGeneration);
  return request(`/api/artifacts?${params.toString()}`);
}

export function getArtifactPreview(digest: string): Promise<ArtifactPreview> {
  return request(`/api/artifacts/${encodeURIComponent(digest)}?max_bytes=131072`);
}

export function getTelemetry(): Promise<Telemetry> {
  return request("/api/telemetry");
}

export function getCompletion(): Promise<Completion> {
  return request("/api/completion");
}

export function getAnalysisStatus(): Promise<AnalysisStatus> {
  return request("/api/analysis/status");
}

function control<T>(path: string, body: Record<string, unknown> = {}): Promise<T> {
  return request(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CTF-Rat-Desktop": "1" },
    body: JSON.stringify(body)
  });
}

export function runBrief(mode: "fast" | "deep"): Promise<AnalysisRun> {
  return control("/api/analysis/brief", { mode });
}

export function queryFunction(name: string): Promise<FunctionQuery> {
  return control("/api/analysis/function", { name });
}

export function queryOracle(): Promise<OracleQuery> {
  return control("/api/analysis/oracle");
}

export function querySlice(backward: string): Promise<SliceQuery> {
  return control("/api/analysis/slice", { backward });
}

export function startSession(): Promise<Session> {
  return control("/api/session/start");
}

export function stopSession(): Promise<Session> {
  return control("/api/session/stop");
}

export function sendTerminalInput(data: string): Promise<{ accepted_bytes: number }> {
  return control("/api/session/input", { data });
}
