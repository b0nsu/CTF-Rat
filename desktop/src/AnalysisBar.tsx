import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  AnalysisRun,
  AnalysisStatus,
  Completion,
  FunctionQuery,
  getAnalysisStatus,
  getCompletion,
  queryFunction,
  runBrief
} from "./api";

function text(value: unknown): string | null {
  return typeof value === "string" && value.length ? value : null;
}

function number(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function listPreview(value: unknown): { count: number; text: string } {
  if (!Array.isArray(value)) return { count: 0, text: "—" };
  const items = value.slice(0, 6).map((item) => {
    if (typeof item === "string" || typeof item === "number") return String(item);
    try {
      return JSON.stringify(item);
    } catch {
      return String(item);
    }
  });
  return { count: value.length, text: items.join(" · ") || "—" };
}

export default function AnalysisBar() {
  const [status, setStatus] = useState<AnalysisStatus | null>(null);
  const [run, setRun] = useState<AnalysisRun | null>(null);
  const [completion, setCompletion] = useState<Completion | null>(null);
  const [functionQuery, setFunctionQuery] = useState<FunctionQuery | null>(null);
  const [functionName, setFunctionName] = useState("");
  const [busy, setBusy] = useState<"fast" | "deep" | "function" | "verify" | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refreshStatus = async () => {
    try {
      setStatus(await getAnalysisStatus());
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "analysis status unavailable");
    }
  };

  useEffect(() => {
    void refreshStatus();
  }, []);

  const execute = async (mode: "fast" | "deep") => {
    setBusy(mode);
    setCompletion(null);
    setFunctionQuery(null);
    setError(null);
    try {
      const result = await runBrief(mode);
      setRun(result);
      if (result.status !== "ok") setError(result.diagnostic ?? `${mode} analysis failed`);
      await refreshStatus();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : `${mode} analysis failed`);
    } finally {
      setBusy(null);
    }
  };

  const submitFunction = async (event: FormEvent) => {
    event.preventDefault();
    const name = functionName.trim();
    if (!name) return;
    setBusy("function");
    setRun(null);
    setCompletion(null);
    setError(null);
    try {
      const result = await queryFunction(name);
      setFunctionQuery(result);
      if (result.status === "error" || result.status === "timeout") {
        setError(result.diagnostic ?? "function query failed");
      }
      await refreshStatus();
    } catch (exc) {
      setFunctionQuery(null);
      setError(exc instanceof Error ? exc.message : "function query failed");
    } finally {
      setBusy(null);
    }
  };

  const verifyStatus = async () => {
    setBusy("verify");
    setRun(null);
    setFunctionQuery(null);
    setError(null);
    try {
      setCompletion(await getCompletion());
    } catch (exc) {
      setCompletion(null);
      setError(exc instanceof Error ? exc.message : "verification status unavailable");
    } finally {
      setBusy(null);
    }
  };

  const summary = useMemo(() => {
    const route = run?.result?.route;
    if (!route) return null;
    const track = text(route.track);
    const subroute = text(route.subroute);
    const confidence = number(route.confidence);
    const next = Array.isArray(route.next) ? route.next[0] : null;
    const nextQuery = next && typeof next === "object" ? text((next as Record<string, unknown>).query) : null;
    return {
      route: [track, subroute].filter(Boolean).join(" / ") || "route unavailable",
      confidence: confidence === null ? null : `${Math.round(confidence * 100)}%`,
      next: nextQuery
    };
  }, [run]);

  const functionSummary = useMemo(() => {
    const facts = functionQuery?.result?.facts;
    if (!facts) return null;
    return {
      callers: listPreview(facts.callers),
      callees: listPreview(facts.callees),
      strings: listPreview(facts.strings),
      complete: functionQuery?.result?.coverage.complete === true
    };
  }, [functionQuery]);

  const disabled = busy !== null || status?.busy === true || status?.ready !== true;
  const target = status?.target?.binary;

  return (
    <section className="analysis-bar" aria-label="Bounded analysis controls">
      <div className="analysis-identity">
        <span className="analysis-kicker">V0.3 CONTROL</span>
        <strong>{target?.name ?? "No canonical target"}</strong>
        {target && <code title={target.sha256}>{target.sha256.slice(0, 18)}…</code>}
        {!status?.ready && <span className="analysis-unready" title={status?.reason ?? undefined}>manifest target required</span>}
      </div>

      <div className="analysis-actions" aria-label="Canonical rat actions">
        <button type="button" disabled={disabled || !status?.modes.fast} onClick={() => void execute("fast")}>
          {busy === "fast" ? "FAST…" : "FAST"}
        </button>
        <button type="button" disabled={disabled || !status?.modes.deep} onClick={() => void execute("deep")}>
          {busy === "deep" ? "DEEP…" : "DEEP"}
        </button>
        <form className="function-form" onSubmit={submitFunction}>
          <input
            aria-label="Function name for bounded Function Card"
            disabled={disabled || !status?.modes.function}
            maxLength={256}
            placeholder="function"
            value={functionName}
            onChange={(event) => setFunctionName(event.target.value)}
          />
          <button type="submit" disabled={disabled || !status?.modes.function || !functionName.trim()}>
            {busy === "function" ? "FUNC…" : "FUNC"}
          </button>
        </form>
        <button type="button" className="verify-control" disabled={busy !== null} onClick={() => void verifyStatus()}>
          {busy === "verify" ? "VERIFY…" : "VERIFY STATUS"}
        </button>
      </div>

      <div className="analysis-result" role="status" aria-live="polite">
        {functionQuery && functionSummary ? (
          <>
            <span className={`mode-tag function ${functionQuery.status}`}>FUNC</span>
            <strong>{functionQuery.name}</strong>
            <code>{functionSummary.complete ? "complete" : functionQuery.status}</code>
            <span>{functionQuery.duration_ms} ms</span>
          </>
        ) : run?.status === "ok" && summary ? (
          <>
            <span className={`mode-tag ${run.mode}`}>{run.mode.toUpperCase()}</span>
            <strong>{summary.route}</strong>
            {summary.confidence && <code>{summary.confidence}</code>}
            <span>{run.duration_ms} ms</span>
            {summary.next && <span className="analysis-next" title={summary.next}>next: {summary.next}</span>}
          </>
        ) : completion ? (
          <>
            <span className={`verify-tag ${completion.verified ? "verified" : "open"}`}>{completion.verified ? "VERIFIED" : "OPEN"}</span>
            <strong>{completion.reason}</strong>
            {completion.verification_id && <code>{completion.verification_id}</code>}
          </>
        ) : (
          <span className="analysis-hint">FAST/DEEP and FUNC route through canonical `rat`; VERIFY STATUS only reads the completion gate.</span>
        )}
      </div>

      {functionQuery && functionSummary && (
        <div className="function-card" aria-label={`Function Card for ${functionQuery.name}`}>
          <div><span>CALLERS · {functionSummary.callers.count}</span><code title={functionSummary.callers.text}>{functionSummary.callers.text}</code></div>
          <div><span>CALLEES · {functionSummary.callees.count}</span><code title={functionSummary.callees.text}>{functionSummary.callees.text}</code></div>
          <div><span>STRINGS · {functionSummary.strings.count}</span><code title={functionSummary.strings.text}>{functionSummary.strings.text}</code></div>
        </div>
      )}

      {error && <div className="analysis-error" role="alert" title={error}>{error}</div>}
    </section>
  );
}
