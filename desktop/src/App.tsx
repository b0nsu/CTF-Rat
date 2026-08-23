import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  API,
  Artifact,
  ArtifactPreview,
  EventRecord,
  Session,
  Snapshot,
  Telemetry,
  getArtifactPreview,
  getArtifacts,
  getEvents,
  getSession,
  getSnapshot,
  getTelemetry,
  getTerminal,
  sendTerminalInput,
  startSession,
  stopSession
} from "./api";

function eventLabel(event: EventRecord): string {
  const payload = event.payload ?? {};
  for (const key of ["text", "probe", "phase", "status", "state", "hypothesis_id", "finding_id", "primitive_id", "observation_id"]) {
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
  if (type.startsWith("phase.")) return "PHASE";
  if (type.startsWith("task.")) return "TASK";
  if (type.startsWith("route.")) return "ROUTE";
  return "EVENT";
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
    ["Next probes", view.next_probes.length]
  ];
}

export default function App() {
  const [liveSnapshot, setLiveSnapshot] = useState<Snapshot | null>(null);
  const [displaySnapshot, setDisplaySnapshot] = useState<Snapshot | null>(null);
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<EventRecord | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [terminal, setTerminal] = useState("");
  const [terminalInput, setTerminalInput] = useState("");
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [selectedArtifact, setSelectedArtifact] = useState<ArtifactPreview | null>(null);
  const [telemetry, setTelemetry] = useState<Telemetry | null>(null);
  const [connection, setConnection] = useState<"connecting" | "live" | "offline">("connecting");
  const [error, setError] = useState<string | null>(null);
  const [replaySeq, setReplaySeq] = useState<number | null>(null);
  const eventCursor = useRef(0);
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
        const [snapshot, delta, currentSession, listing, stats, log] = await Promise.all([
          getSnapshot(), getEvents(0, 1000), getSession(), getArtifacts(), getTelemetry(), getTerminal(0)
        ]);
        if (!mounted) return;
        setLiveSnapshot(snapshot);
        setDisplaySnapshot(snapshot);
        setEvents(delta.events);
        setSelectedEvent(delta.events.at(-1) ?? null);
        eventCursor.current = delta.cursor.seq;
        setSession(currentSession);
        setArtifacts(listing.artifacts);
        setTelemetry(stats);
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
        const [delta, currentSession, log] = await Promise.all([
          getEvents(eventCursor.current), getSession(), getTerminal(terminalCursor.current)
        ]);
        if (!mounted) return;
        let stateChanged = false;
        if (delta.events.length) {
          setEvents((current) => [...current, ...delta.events].slice(-3000));
          setSelectedEvent((current) => current ?? delta.events.at(-1) ?? null);
          eventCursor.current = delta.cursor.seq;
          stateChanged = true;
        }
        if (log.text) {
          setTerminal((current) => (current + log.text).slice(-300000));
          terminalCursor.current = log.cursor;
        }
        setSession(currentSession);
        if (stateChanged) {
          const [snapshot, listing, stats] = await Promise.all([getSnapshot(), getArtifacts(), getTelemetry()]);
          if (!mounted) return;
          setLiveSnapshot(snapshot);
          if (replaySeqRef.current === null) setDisplaySnapshot(snapshot);
          setArtifacts(listing.artifacts);
          setTelemetry(stats);
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
  const challengeName = liveSnapshot?.challenge_root.split(/[\\/]/).filter(Boolean).at(-1) ?? "No challenge";

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

  const selectArtifact = async (artifact: Artifact) => {
    try {
      setSelectedArtifact(await getArtifactPreview(artifact.digest));
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "artifact preview failed");
    }
  };

  const changeReplay = async (value: number) => {
    const request = ++replayRequest.current;
    const max = liveSnapshot?.total_event_count ?? 0;
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

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-block">
          <div className="eyebrow">CTF-RAT WORKBENCH</div>
          <h1>{challengeName}</h1>
          <span className="root-inline">{liveSnapshot?.challenge_root ?? API}</span>
        </div>
        <div className="top-actions">
          <div className={`session-pill ${session?.status ?? "idle"}`}>{session?.status?.toUpperCase() ?? "IDLE"}</div>
          <button className="primary" disabled={!session?.configured || session?.status === "running"} onClick={() => void runControl("start")}>Start Solver</button>
          <button className="danger" disabled={session?.status !== "running"} onClick={() => void runControl("stop")}>Stop</button>
          <div className={`connection ${connection}`}><span className="dot" />{connection.toUpperCase()}</div>
        </div>
      </header>

      {error && <div className="error-banner">{error}</div>}

      <section className="replay-bar">
        <span>REPLAY</span>
        <input
          type="range"
          min={0}
          max={liveSnapshot?.total_event_count ?? 0}
          value={replaySeq ?? liveSnapshot?.total_event_count ?? 0}
          onChange={(event) => void changeReplay(Number(event.target.value))}
        />
        <code>{replaySeq === null ? "LIVE" : `#${replaySeq}`}</code>
        <span className="telemetry-inline">events {telemetry?.event_count ?? 0} · terminal {session?.log_size ?? 0} B</span>
      </section>

      <main className="workspace">
        <aside className="state-panel panel">
          <div className="panel-title">STATE {displaySnapshot?.historical ? "· HISTORICAL" : "· LIVE"}</div>
          <div className="counter-grid">
            {counters.map(([label, value]) => <div className="counter" key={label}><span>{label}</span><strong>{value}</strong></div>)}
          </div>
          <div className="meta-block">
            <span>Cursor</span><strong>#{displaySnapshot?.cursor.seq ?? 0}</strong>
            <span>Total</span><strong>{liveSnapshot?.total_event_count ?? 0}</strong>
            <span>PID</span><strong>{session?.pid ?? "—"}</strong>
            <span>Exit</span><strong>{session?.exit_code ?? "—"}</strong>
          </div>
          <div className="panel-title subsection">ARTIFACTS · {artifacts.length}</div>
          <div className="artifact-list">
            {artifacts.slice(0, 80).map((artifact) => (
              <button key={artifact.digest} className="artifact-row" onClick={() => void selectArtifact(artifact)}>
                <strong>{artifact.logical_name}</strong>
                <span>{artifact.kind}</span>
                <code>{artifact.digest.slice(0, 19)}…</code>
              </button>
            ))}
            {!artifacts.length && <div className="empty compact">No artifacts yet.</div>}
          </div>
        </aside>

        <section className="center-stack">
          <section className="timeline panel">
            <div className="panel-title">ACTIVITY TIMELINE</div>
            <div className="event-list">
              {!events.length && <div className="empty">Waiting for STATE v2 events…</div>}
              {events.map((event) => {
                const future = replaySeq !== null && event.seq > replaySeq;
                return (
                  <button className={`event-row ${selectedEvent?.event_id === event.event_id ? "selected" : ""} ${future ? "future" : ""}`} key={event.event_id} onClick={() => setSelectedEvent(event)}>
                    <span className="seq">#{event.seq}</span>
                    <span className="kind">{group(event.type)}</span>
                    <span className="event-main"><strong>{event.type}</strong><small>{eventLabel(event)}</small></span>
                    <time>{new Date(event.at).toLocaleTimeString()}</time>
                  </button>
                );
              })}
            </div>
          </section>

          <section className="terminal-panel panel">
            <div className="terminal-head"><span className="panel-title">LIVE TERMINAL</span><code>{session?.argv?.join(" ") || "ratd started without --solver-command"}</code></div>
            <pre className="terminal" ref={terminalRef}>{terminal || "No terminal output yet."}</pre>
            <form className="terminal-input" onSubmit={submitTerminal}>
              <span>›</span>
              <input disabled={session?.status !== "running"} value={terminalInput} onChange={(event) => setTerminalInput(event.target.value)} placeholder={session?.status === "running" ? "send input to solver PTY" : "solver is not running"} />
            </form>
          </section>
        </section>

        <aside className="inspector panel">
          <div className="panel-title">INSPECTOR</div>
          {selectedArtifact ? (
            <>
              <div className="inspector-head"><span>ARTIFACT</span><strong>{selectedArtifact.metadata.kind}</strong></div>
              <h2>{selectedArtifact.metadata.logical_name}</h2>
              <div className="inspector-meta">
                <span>digest</span><code>{selectedArtifact.metadata.digest}</code>
                <span>media</span><code>{selectedArtifact.metadata.media_type}</code>
                <span>size</span><code>{selectedArtifact.total_bytes} B</code>
              </div>
              <button className="link-button" onClick={() => setSelectedArtifact(null)}>Show selected event</button>
              <pre>{selectedArtifact.encoding === "utf-8" ? selectedArtifact.content : `[base64 preview]\n${selectedArtifact.content}`}</pre>
            </>
          ) : selectedEvent ? (
            <>
              <div className="inspector-head"><span>{group(selectedEvent.type)}</span><strong>#{selectedEvent.seq}</strong></div>
              <h2>{selectedEvent.type}</h2>
              <div className="inspector-meta">
                <span>actor</span><code>{selectedEvent.actor}</code>
                <span>task</span><code>{selectedEvent.task_id}</code>
                <span>event</span><code>{selectedEvent.event_id}</code>
              </div>
              <pre>{JSON.stringify(selectedEvent.payload, null, 2)}</pre>
            </>
          ) : <div className="empty">Select an event or artifact.</div>}
        </aside>
      </main>
    </div>
  );
}
