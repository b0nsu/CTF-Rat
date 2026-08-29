import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  API,
  Artifact,
  ArtifactPreview,
  Completion,
  EventCursor,
  EventRecord,
  Session,
  Snapshot,
  Telemetry,
  getArtifactPreview,
  getArtifacts,
  getCompletion,
  getLiveUpdate,
  getSession,
  getSnapshot,
  getTelemetry,
  getTerminal,
  sendTerminalInput,
  startSession,
  stopSession
} from "./api";

type EntityKind = "primitive" | "finding" | "observation";
type EntityKey = { kind: EntityKind; id: string };
type StateEntity = EntityKey & { value: Record<string, unknown> };
type TimelineFilter = "all" | "verify" | "findings" | "primitives" | "evidence" | "failures";

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item.length > 0) : [];
}

function eventLabel(event: EventRecord): string {
  const payload = event.payload ?? {};
  for (const key of [
    "text", "probe", "phase", "status", "state", "failure_class", "class", "reason",
    "hypothesis_id", "finding_id", "primitive_id", "observation_id", "verification_id"
  ]) {
    const value = payload[key];
    if (typeof value === "string" && value.length) return value;
  }
  return event.type.replaceAll(".", " ");
}

function group(type: string): string {
  if (type.startsWith("observation.")) return "OBS";
  if (type.startsWith("hypothesis.")) return "HYP";
  if (type.startsWith("primitive.")) return "PRIM";
  if (type.startsWith("finding.")) return "FIND";
  if (type.startsWith("verification.")) return "VERIFY";
  if (type.startsWith("failure.")) return "FAIL";
  if (type.startsWith("alert.")) return "ALERT";
  if (type.startsWith("evidence.")) return "EVID";
  if (type.startsWith("phase.")) return "PHASE";
  if (type.startsWith("task.")) return "TASK";
  if (type.startsWith("route.")) return "ROUTE";
  return "EVENT";
}

function eventMatchesFilter(event: EventRecord, filter: TimelineFilter): boolean {
  if (filter === "all") return true;
  if (filter === "verify") return event.type.startsWith("verification.");
  if (filter === "findings") return event.type.startsWith("finding.");
  if (filter === "primitives") return event.type.startsWith("primitive.");
  if (filter === "evidence") return event.type.startsWith("observation.") || event.type.startsWith("evidence.");
  return event.type.startsWith("failure.") || event.type.startsWith("alert.");
}

function stateCounters(snapshot: Snapshot | null) {
  const view = snapshot?.view;
  if (!view) return [] as [string, number][];
  return [
    ["Observations", Object.keys(view.observations).length],
    ["Findings", Object.keys(view.findings).length],
    ["Hypotheses", Object.keys(view.hypotheses).length],
    ["Primitives", Object.keys(view.primitives).length],
    ["Unknowns", Object.keys(view.unknowns).length],
    ["Failures", view.failures.length],
    ["Alerts", view.alerts.length],
    ["Next probes", view.next_probes.length]
  ];
}

function objectField(value: unknown, keys: string[]): string | null {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  for (const key of keys) {
    const field = record[key];
    if (typeof field === "string" && field.length) return field;
  }
  return null;
}

function stateSummary(records: Record<string, unknown>, key: string): string {
  const counts = new Map<string, number>();
  for (const value of Object.values(records)) {
    const status = objectField(value, [key]) ?? "unknown";
    counts.set(status, (counts.get(status) ?? 0) + 1);
  }
  if (!counts.size) return "none";
  return [...counts.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([status, count]) => `${count} ${status}`)
    .join(" · ");
}

function entityTitle(entity: StateEntity): string {
  return objectField(entity.value, ["name", "title", "kind", "class"]) ?? entity.id;
}

function entityState(entity: StateEntity): string {
  if (entity.kind === "observation") {
    return objectField(asRecord(entity.value.validity), ["state"])
      ?? objectField(asRecord(entity.value.quality), ["level"])
      ?? "observed";
  }
  return objectField(entity.value, ["status", "state"]) ?? "unknown";
}

function entityMeta(entity: StateEntity): Array<[string, string]> {
  const rows: Array<[string, string]> = [["id", entity.id]];
  rows.push([entity.kind === "observation" ? "validity" : "status", entityState(entity)]);
  const className = objectField(entity.value, ["class", "kind"]);
  if (className) rows.push([entity.kind === "observation" ? "kind" : "class", className]);
  const revision = entity.value.revision;
  if (typeof revision === "number") rows.push(["revision", String(revision)]);
  if (entity.kind === "finding" && typeof entity.value.confidence === "number") {
    rows.push(["confidence", `${Math.round(entity.value.confidence * 100)}%`]);
  }
  if (entity.kind === "observation") {
    const quality = objectField(asRecord(entity.value.quality), ["level"]);
    if (quality) rows.push(["quality", quality]);
  }
  return rows;
}

function boardRank(kind: EntityKind, value: Record<string, unknown>): number {
  const status = objectField(value, ["status", "state"]) ?? "unknown";
  const ranks: Record<string, number> = {
    pass: 0,
    verified: 0,
    consumed: 1,
    confirmed: 1,
    supported: 2,
    candidate: 2,
    blocked: 3,
    proposed: 3,
    stale: 4,
    fail: 5,
    refuted: 5,
    invalidated: 6
  };
  return (ranks[status] ?? 7) * 10 + (kind === "primitive" ? 0 : 1);
}

function resolveEntity(snapshot: Snapshot | null, key: EntityKey | null): StateEntity | null {
  if (!snapshot || !key) return null;
  let value: unknown;
  if (key.kind === "primitive") value = snapshot.view.primitives[key.id];
  else if (key.kind === "finding") value = snapshot.view.findings[key.id];
  else value = snapshot.view.observations[key.id];
  return value ? { ...key, value: asRecord(value) } : null;
}

function percent(value: number | null | undefined): string {
  return typeof value === "number" ? `${Math.round(value * 100)}%` : "—";
}

async function optional<T>(request: Promise<T>): Promise<T | null> {
  try {
    return await request;
  } catch {
    return null;
  }
}

export default function App() {
  const [liveSnapshot, setLiveSnapshot] = useState<Snapshot | null>(null);
  const [displaySnapshot, setDisplaySnapshot] = useState<Snapshot | null>(null);
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<EventRecord | null>(null);
  const [selectedEntityKey, setSelectedEntityKey] = useState<EntityKey | null>(null);
  const [timelineFilter, setTimelineFilter] = useState<TimelineFilter>("all");
  const [session, setSession] = useState<Session | null>(null);
  const [completion, setCompletion] = useState<Completion | null>(null);
  const [telemetry, setTelemetry] = useState<Telemetry | null>(null);
  const [terminal, setTerminal] = useState("");
  const [terminalInput, setTerminalInput] = useState("");
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [selectedArtifact, setSelectedArtifact] = useState<ArtifactPreview | null>(null);
  const [connection, setConnection] = useState<"connecting" | "live" | "offline">("connecting");
  const [error, setError] = useState<string | null>(null);
  const [replaySeq, setReplaySeq] = useState<number | null>(null);
  const eventCursor = useRef<EventCursor | null>(null);
  const artifactGeneration = useRef<string | null>(null);
  const terminalCursor = useRef(0);
  const replaySeqRef = useRef<number | null>(null);
  const replayRequest = useRef(0);
  const terminalRef = useRef<HTMLPreElement | null>(null);

  useEffect(() => {
    let mounted = true;
    let polling = false;
    let timer: number | undefined;

    const initial = async () => {
      try {
        const [live, currentSession, listing, log, currentCompletion, currentTelemetry] = await Promise.all([
          getLiveUpdate(null, 1000),
          getSession(),
          getArtifacts(),
          getTerminal(0),
          optional(getCompletion()),
          optional(getTelemetry())
        ]);
        if (!mounted) return;
        if (!live.snapshot) throw new Error("initial live projection omitted snapshot");
        const delta = live.delta;
        const snapshot = live.snapshot;
        setLiveSnapshot(snapshot);
        setDisplaySnapshot(snapshot);
        setEvents(delta.events);
        setSelectedEvent(delta.events.at(-1) ?? null);
        eventCursor.current = delta.cursor;
        setSession(currentSession);
        setCompletion(currentCompletion);
        setTelemetry(currentTelemetry);
        artifactGeneration.current = listing.generation;
        setArtifacts(listing.artifacts);
        setTerminal(log.text);
        terminalCursor.current = log.cursor;
        setConnection("live");
      } catch (exc) {
        if (mounted) {
          setConnection("offline");
          setError(exc instanceof Error ? exc.message : "Unable to connect to ratd");
        }
      }
    };

    const poll = async () => {
      if (polling) return;
      polling = true;
      try {
        const [live, currentSession, log] = await Promise.all([
          getLiveUpdate(eventCursor.current), getSession(), getTerminal(terminalCursor.current)
        ]);
        if (!mounted) return;
        const delta = live.delta;
        let stateChanged = false;
        eventCursor.current = delta.cursor;
        if (delta.reset) {
          setEvents(delta.events.slice(-3000));
          setSelectedEvent(delta.events.at(-1) ?? null);
          setSelectedEntityKey(null);
          setSelectedArtifact(null);
          replaySeqRef.current = null;
          setReplaySeq(null);
          setTerminal("");
          terminalCursor.current = 0;
          stateChanged = true;
        } else if (delta.events.length) {
          setEvents((current) => [...current, ...delta.events].slice(-3000));
          setSelectedEvent((current) => current ?? delta.events.at(-1) ?? null);
          stateChanged = true;
        }
        if (!delta.reset && log.text) {
          setTerminal((current) => (current + log.text).slice(-300000));
          terminalCursor.current = log.cursor;
        }
        setSession(currentSession);
        if (stateChanged) {
          if (!live.snapshot) throw new Error("changed live projection omitted snapshot");
          const completionRelevant = delta.reset || delta.events.some((event) =>
            event.type.startsWith("verification.") ||
            event.type.startsWith("primitive.") ||
            event.type === "evidence.invalidated"
          );
          const [listing, nextCompletion] = await Promise.all([
            getArtifacts(artifactGeneration.current),
            completionRelevant ? optional(getCompletion()) : Promise.resolve(null)
          ]);
          if (!mounted) return;
          setLiveSnapshot(live.snapshot);
          if (replaySeqRef.current === null) setDisplaySnapshot(live.snapshot);
          artifactGeneration.current = listing.generation;
          if (nextCompletion) setCompletion(nextCompletion);
          if (!listing.unchanged) {
            setArtifacts(listing.artifacts);
            const nextTelemetry = await optional(getTelemetry());
            if (mounted && nextTelemetry) setTelemetry(nextTelemetry);
          }
        }
        setConnection("live");
        setError(null);
      } catch (exc) {
        if (mounted) {
          setConnection("offline");
          setError(exc instanceof Error ? exc.message : "poll failed");
        }
      } finally {
        polling = false;
      }
    };

    void initial().finally(() => {
      if (mounted) timer = window.setInterval(() => void poll(), 500);
    });
    return () => {
      mounted = false;
      if (timer !== undefined) window.clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    const element = terminalRef.current;
    if (element) element.scrollTop = element.scrollHeight;
  }, [terminal]);

  const counters = useMemo(() => stateCounters(displaySnapshot), [displaySnapshot]);
  const focus = useMemo(() => {
    const view = displaySnapshot?.view;
    if (!view) return { nextProbe: "waiting for STATE", primitives: "none", findings: "none", failure: "none" };
    const nextProbe = objectField(view.next_probes.at(-1), ["probe", "text"]) ?? "no next probe recorded";
    const failure = objectField(view.failures.at(-1), ["failure_class", "class", "reason"]) ?? "none";
    return {
      nextProbe,
      primitives: stateSummary(view.primitives, "status"),
      findings: stateSummary(view.findings, "state"),
      failure
    };
  }, [displaySnapshot]);

  const boardEntities = useMemo(() => {
    const view = displaySnapshot?.view;
    if (!view) return [] as StateEntity[];
    const primitives = Object.entries(view.primitives).map(([id, value]) => ({ kind: "primitive" as const, id, value: asRecord(value) }));
    const findings = Object.entries(view.findings).map(([id, value]) => ({ kind: "finding" as const, id, value: asRecord(value) }));
    return [...primitives, ...findings]
      .sort((a, b) => boardRank(a.kind, a.value) - boardRank(b.kind, b.value) || a.id.localeCompare(b.id))
      .slice(0, 24);
  }, [displaySnapshot]);

  const selectedEntity = useMemo(
    () => resolveEntity(displaySnapshot, selectedEntityKey),
    [displaySnapshot, selectedEntityKey]
  );
  const visibleEvents = useMemo(() => events.filter((event) => eventMatchesFilter(event, timelineFilter)), [events, timelineFilter]);
  const challengeName = liveSnapshot?.challenge_root.split(/[\\/]/).filter(Boolean).at(-1) ?? "No challenge";
  const metrics = telemetry?.session;
  const completionLabel = completion === null ? "UNKNOWN" : completion.verified ? "VERIFIED" : "NOT VERIFIED";

  const runControl = async (action: "start" | "stop") => {
    try {
      setError(null);
      const next = action === "start" ? await startSession() : await stopSession();
      if (action === "start") {
        setTerminal("");
        terminalCursor.current = 0;
      }
      setSession(next);
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "session control failed");
    }
  };

  const submitTerminal = async (event: FormEvent) => {
    event.preventDefault();
    if (!terminalInput) return;
    try {
      await sendTerminalInput(terminalInput.endsWith("\n") ? terminalInput : terminalInput + "\n");
      setTerminalInput("");
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "terminal input failed");
    }
  };

  const selectArtifactDigest = async (digest: string) => {
    try {
      setSelectedEntityKey(null);
      setSelectedArtifact(await getArtifactPreview(digest));
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "artifact preview failed");
    }
  };

  const selectArtifact = async (artifact: Artifact) => {
    await selectArtifactDigest(artifact.digest);
  };

  const selectTimelineEvent = (event: EventRecord) => {
    setSelectedEvent(event);
    setSelectedEntityKey(null);
    setSelectedArtifact(null);
  };

  const selectStateEntity = (kind: EntityKind, id: string) => {
    setSelectedEntityKey({ kind, id });
    setSelectedArtifact(null);
  };

  const selectObservation = (id: string) => {
    if (displaySnapshot?.view.observations[id]) selectStateEntity("observation", id);
  };

  const selectFinding = (id: string) => {
    if (displaySnapshot?.view.findings[id]) selectStateEntity("finding", id);
  };

  const selectCausedBy = (eventId: string) => {
    const target = events.find((event) => event.event_id === eventId);
    if (target) selectTimelineEvent(target);
  };

  const changeReplay = async (value: number) => {
    const request = ++replayRequest.current;
    const max = liveSnapshot?.total_event_count ?? 0;
    setSelectedEntityKey(null);
    if (value >= max) {
      replaySeqRef.current = null;
      setReplaySeq(null);
      setDisplaySnapshot(liveSnapshot);
      return;
    }
    replaySeqRef.current = value;
    setReplaySeq(value);
    try {
      const snapshot = await getSnapshot(value);
      if (request === replayRequest.current && replaySeqRef.current === value) {
        setDisplaySnapshot(snapshot);
      }
    } catch (exc) {
      if (request === replayRequest.current) {
        setError(exc instanceof Error ? exc.message : "replay failed");
      }
    }
  };

  const entityObservationIds = selectedEntity?.kind === "finding"
    ? stringList(selectedEntity.value.evidence_observation_ids)
    : selectedEntity?.kind === "primitive"
      ? stringList(selectedEntity.value.self_evidence)
      : [];
  const entityArtifactDigests = selectedEntity?.kind === "observation" ? stringList(selectedEntity.value.evidence) : [];
  const relatedFindings = selectedEntity?.kind === "finding" ? stringList(selectedEntity.value.related_findings) : [];
  const eventObservationIds = selectedEvent
    ? [...new Set([...stringList(selectedEvent.payload.evidence_observation_ids), ...stringList(selectedEvent.payload.self_evidence)])]
    : [];

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-block">
          <div className="eyebrow">CTF-RAT WORKBENCH</div>
          <div className="brand-line">
            <h1>{challengeName}</h1>
            <span className="root-inline" title={liveSnapshot?.challenge_root ?? API}>{liveSnapshot?.challenge_root ?? API}</span>
          </div>
        </div>
        <div className="top-actions">
          <div
            className={`completion-pill ${completion?.verified ? "verified" : completion ? "unverified" : "unknown"}`}
            aria-label={`Challenge completion ${completionLabel.toLowerCase()}`}
            title={completion?.reason ?? "completion gate unavailable"}
          >
            {completionLabel}
          </div>
          <div className={`session-pill ${session?.status ?? "idle"}`} aria-label={`Solver session ${session?.status ?? "idle"}`}>{session?.status?.toUpperCase() ?? "IDLE"}</div>
          <button type="button" className="primary" disabled={!session?.configured || session?.status === "running"} onClick={() => void runControl("start")}>Start Solver</button>
          <button type="button" className="danger" disabled={session?.status !== "running"} onClick={() => void runControl("stop")}>Stop</button>
          <div className={`connection ${connection}`} role="status" aria-live="polite" aria-label={`ratd connection ${connection}`}><span className="dot" aria-hidden="true" />{connection.toUpperCase()}</div>
        </div>
      </header>

      {error && <div className="error-banner" role="alert">{error}</div>}

      <section className="replay-bar" aria-label="STATE replay controls">
        <span id="replay-label">REPLAY</span>
        <input
          type="range"
          min={0}
          max={liveSnapshot?.total_event_count ?? 0}
          value={replaySeq ?? liveSnapshot?.total_event_count ?? 0}
          aria-labelledby="replay-label"
          aria-valuetext={replaySeq === null ? "Live state" : `Historical state at event ${replaySeq}`}
          onChange={(event) => void changeReplay(Number(event.target.value))}
        />
        <code>{replaySeq === null ? "LIVE" : `#${replaySeq}`}</code>
        <span className="telemetry-inline">
          events {liveSnapshot?.total_event_count ?? 0} · tools {metrics ? metrics.tool_calls : "—"} · dup {metrics ? metrics.duplicate_tool_calls : "—"} · cache {percent(metrics?.cache_hit_ratio)}
        </span>
      </section>

      <section className={`focus-bar ${displaySnapshot?.historical ? "historical" : ""}`} aria-label="Solver focus summary">
        <div className="focus-main"><span>NEXT PROBE</span><strong title={focus.nextProbe}>{focus.nextProbe}</strong></div>
        <div className="focus-stat"><span>PRIMITIVES</span><code>{focus.primitives}</code></div>
        <div className="focus-stat"><span>FINDINGS</span><code>{focus.findings}</code></div>
        <div className={`focus-stat ${focus.failure !== "none" ? "attention" : ""}`}><span>LAST FAILURE</span><code>{focus.failure}</code></div>
      </section>

      <main className="workspace">
        <aside className="state-panel panel" aria-labelledby="state-title">
          <div className="panel-title" id="state-title" role="heading" aria-level={2}>STATE {displaySnapshot?.historical ? "· HISTORICAL" : "· LIVE"}</div>
          <div className="counter-grid">
            {counters.map(([label, value]) => <div className="counter" key={label}><span>{label}</span><strong>{value}</strong></div>)}
          </div>
          <div className="meta-block">
            <span>Cursor</span><strong>#{displaySnapshot?.cursor.seq ?? 0}</strong>
            <span>Total</span><strong>{liveSnapshot?.total_event_count ?? 0}</strong>
            <span>PID</span><strong>{session?.pid ?? "—"}</strong>
            <span>Exit</span><strong>{session?.exit_code ?? "—"}</strong>
            <span>Solve</span><strong className={completion?.verified ? "metric-good" : ""}>{completion === null ? "—" : completion.verified ? "VERIFIED" : "not verified"}</strong>
          </div>

          <div className="panel-title subsection" id="board-title" role="heading" aria-level={3}>PRIMITIVE / FINDING BOARD · {boardEntities.length}</div>
          <div className="state-entity-list" aria-labelledby="board-title">
            {boardEntities.map((entity) => {
              const status = entityState(entity);
              const selected = selectedEntityKey?.kind === entity.kind && selectedEntityKey.id === entity.id;
              return (
                <button
                  type="button"
                  className={`state-entity-row ${entity.kind}`}
                  data-status={status}
                  aria-pressed={selected}
                  key={`${entity.kind}:${entity.id}`}
                  onClick={() => selectStateEntity(entity.kind, entity.id)}
                >
                  <span className="entity-kind">{entity.kind === "primitive" ? "PRIM" : "FIND"}</span>
                  <span className="entity-main"><strong title={entityTitle(entity)}>{entityTitle(entity)}</strong><small title={entity.id}>{entity.id}</small></span>
                  <code>{status}</code>
                </button>
              );
            })}
            {!boardEntities.length && <div className="empty compact">No primitives or findings.</div>}
          </div>

          <div className="panel-title subsection" id="metrics-title" role="heading" aria-level={3}>RUN METRICS</div>
          <div className="metric-grid" aria-labelledby="metrics-title">
            <div><span>tools</span><strong>{metrics?.tool_calls ?? "—"}</strong></div>
            <div><span>duplicates</span><strong className={(metrics?.duplicate_tool_calls ?? 0) > 0 ? "metric-warn" : ""}>{metrics?.duplicate_tool_calls ?? "—"}</strong></div>
            <div><span>cache hit</span><strong>{percent(metrics?.cache_hit_ratio)}</strong></div>
            <div><span>decompiled</span><strong>{metrics?.functions_decompiled ?? "—"}</strong></div>
          </div>
          <div className="panel-title subsection" id="artifacts-title" role="heading" aria-level={3}>ARTIFACTS · {artifacts.length}</div>
          <div className="artifact-list" aria-labelledby="artifacts-title">
            {artifacts.slice(0, 80).map((artifact) => (
              <button
                type="button"
                key={artifact.digest}
                className="artifact-row"
                aria-pressed={selectedArtifact?.metadata.digest === artifact.digest}
                onClick={() => void selectArtifact(artifact)}
              >
                <strong>{artifact.logical_name}</strong>
                <span>{artifact.kind}</span>
                <code>{artifact.digest.slice(0, 19)}…</code>
              </button>
            ))}
            {!artifacts.length && <div className="empty compact">No artifacts yet.</div>}
          </div>
        </aside>

        <section className="center-stack">
          <section className="timeline panel" aria-labelledby="timeline-title">
            <div className="timeline-head">
              <div className="panel-title" id="timeline-title" role="heading" aria-level={2}>ACTIVITY TIMELINE · {visibleEvents.length}/{events.length}</div>
              <div className="timeline-filters" aria-label="Timeline filters">
                {([
                  ["all", "ALL"], ["verify", "VERIFY"], ["findings", "FIND"], ["primitives", "PRIM"], ["evidence", "EVID"], ["failures", "FAIL"]
                ] as Array<[TimelineFilter, string]>).map(([value, label]) => (
                  <button type="button" key={value} aria-pressed={timelineFilter === value} onClick={() => setTimelineFilter(value)}>{label}</button>
                ))}
              </div>
            </div>
            <div className="event-list">
              {!visibleEvents.length && <div className="empty">No STATE events match this filter.</div>}
              {visibleEvents.map((event) => {
                const future = replaySeq !== null && event.seq > replaySeq;
                const selected = selectedEvent?.event_id === event.event_id && !selectedArtifact && !selectedEntity;
                return (
                  <button
                    type="button"
                    className={`event-row ${selected ? "selected" : ""} ${future ? "future" : ""}`}
                    key={event.event_id}
                    aria-pressed={selected}
                    onClick={() => selectTimelineEvent(event)}
                  >
                    <span className="seq">#{event.seq}</span>
                    <span className="kind">{group(event.type)}</span>
                    <span className="event-main"><strong>{event.type}</strong><small>{eventLabel(event)}</small></span>
                    <time dateTime={event.at} title={new Date(event.at).toLocaleString()}>{new Date(event.at).toLocaleTimeString()}</time>
                  </button>
                );
              })}
            </div>
          </section>

          <section className="terminal-panel panel" aria-labelledby="terminal-title">
            <div className="terminal-head"><span className="panel-title" id="terminal-title" role="heading" aria-level={2}>LIVE TERMINAL</span><code title={session?.argv?.join(" ")}>{session?.argv?.join(" ") || "ratd started without --solver-command"}</code></div>
            <pre className="terminal" ref={terminalRef} tabIndex={0} aria-label="Solver terminal output">{terminal || "No terminal output yet."}</pre>
            <form className="terminal-input" onSubmit={submitTerminal} aria-label="Solver terminal input">
              <span aria-hidden="true">›</span>
              <input
                aria-label="Send input to solver PTY"
                disabled={session?.status !== "running"}
                value={terminalInput}
                onChange={(event) => setTerminalInput(event.target.value)}
                placeholder={session?.status === "running" ? "send input to solver PTY" : "solver is not running"}
              />
            </form>
          </section>
        </section>

        <aside className="inspector panel" aria-labelledby="inspector-title">
          <div className="panel-title" id="inspector-title" role="heading" aria-level={2}>INSPECTOR</div>
          {selectedArtifact ? (
            <>
              <div className="inspector-head"><span>ARTIFACT</span><strong>{selectedArtifact.metadata.kind}</strong></div>
              <h2>{selectedArtifact.metadata.logical_name}</h2>
              <div className="inspector-meta">
                <span>digest</span><code title={selectedArtifact.metadata.digest}>{selectedArtifact.metadata.digest}</code>
                <span>media</span><code>{selectedArtifact.metadata.media_type}</code>
                <span>size</span><code>{selectedArtifact.total_bytes} B</code>
              </div>
              {selectedEvent && <button type="button" className="link-button" onClick={() => setSelectedArtifact(null)}>Show selected event</button>}
              <pre tabIndex={0}>{selectedArtifact.encoding === "utf-8" ? selectedArtifact.content : `[base64 preview]\n${selectedArtifact.content}`}</pre>
            </>
          ) : selectedEntity ? (
            <>
              <div className="inspector-head"><span>{selectedEntity.kind.toUpperCase()}</span><strong>{entityState(selectedEntity)}</strong></div>
              <h2>{entityTitle(selectedEntity)}</h2>
              <div className="inspector-meta">
                {entityMeta(selectedEntity).flatMap(([label, value]) => [
                  <span key={`${label}-label`}>{label}</span>,
                  <code key={`${label}-value`} title={value}>{value}</code>
                ])}
              </div>
              {entityObservationIds.length > 0 && (
                <div className="relation-block">
                  <span>EVIDENCE OBSERVATIONS</span>
                  <div>{entityObservationIds.map((id) => <button type="button" className="relation-chip" key={id} disabled={!displaySnapshot?.view.observations[id]} onClick={() => selectObservation(id)}>{id}</button>)}</div>
                </div>
              )}
              {entityArtifactDigests.length > 0 && (
                <div className="relation-block">
                  <span>EVIDENCE ARTIFACTS</span>
                  <div>{entityArtifactDigests.map((digest) => <button type="button" className="relation-chip" key={digest} title={digest} onClick={() => void selectArtifactDigest(digest)}>{digest.slice(0, 19)}…</button>)}</div>
                </div>
              )}
              {relatedFindings.length > 0 && (
                <div className="relation-block">
                  <span>RELATED FINDINGS</span>
                  <div>{relatedFindings.map((id) => <button type="button" className="relation-chip" key={id} disabled={!displaySnapshot?.view.findings[id]} onClick={() => selectFinding(id)}>{id}</button>)}</div>
                </div>
              )}
              {selectedEvent && <button type="button" className="link-button" onClick={() => setSelectedEntityKey(null)}>Show selected event</button>}
              <pre tabIndex={0}>{JSON.stringify(selectedEntity.value, null, 2)}</pre>
            </>
          ) : selectedEvent ? (
            <>
              <div className="inspector-head"><span>{group(selectedEvent.type)}</span><strong>#{selectedEvent.seq}</strong></div>
              <h2>{selectedEvent.type}</h2>
              <div className="inspector-meta">
                <span>actor</span><code>{selectedEvent.actor}</code>
                <span>task</span><code>{selectedEvent.task_id}</code>
                <span>event</span><code title={selectedEvent.event_id}>{selectedEvent.event_id}</code>
              </div>
              {selectedEvent.caused_by.length > 0 && (
                <div className="relation-block">
                  <span>CAUSED BY</span>
                  <div>{selectedEvent.caused_by.map((id) => <button type="button" className="relation-chip" key={id} disabled={!events.some((event) => event.event_id === id)} onClick={() => selectCausedBy(id)}>{id}</button>)}</div>
                </div>
              )}
              {eventObservationIds.length > 0 && (
                <div className="relation-block">
                  <span>OBSERVATIONS</span>
                  <div>{eventObservationIds.map((id) => <button type="button" className="relation-chip" key={id} disabled={!displaySnapshot?.view.observations[id]} onClick={() => selectObservation(id)}>{id}</button>)}</div>
                </div>
              )}
              <pre tabIndex={0}>{JSON.stringify(selectedEvent.payload, null, 2)}</pre>
            </>
          ) : <div className="empty">Select an event, primitive, finding, observation, or artifact.</div>}
        </aside>
      </main>
    </div>
  );
}
