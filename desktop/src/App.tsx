import { useEffect, useMemo, useRef, useState } from "react";

type EventRecord = {
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

type Snapshot = {
  schema: string;
  challenge_root: string;
  run: Record<string, unknown> | null;
  cursor: { stream_id: string | null; seq: number };
  event_count: number;
  view: {
    observations: Record<string, unknown>;
    findings: Record<string, unknown>;
    primitives: Record<string, unknown>;
    hypotheses: Record<string, unknown>;
    ruled_out: Record<string, unknown>;
    unknowns: Record<string, unknown>;
    next_probes: unknown[];
  };
};

type Delta = {
  schema: string;
  stream_id: string | null;
  after_seq: number;
  events: EventRecord[];
  cursor: { stream_id: string | null; seq: number };
  has_more: boolean;
};

const API = import.meta.env.VITE_RATD_URL ?? "http://127.0.0.1:8765";

function eventLabel(event: EventRecord): string {
  const payload = event.payload ?? {};
  const preferred = [
    "text",
    "probe",
    "phase",
    "status",
    "state",
    "hypothesis_id",
    "finding_id",
    "primitive_id",
    "observation_id"
  ];
  for (const key of preferred) {
    const value = payload[key];
    if (typeof value === "string" && value.length) return value;
  }
  return event.type.replaceAll(".", " ");
}

function group(type: string): string {
  if (type.startsWith("observation.")) return "OBSERVATION";
  if (type.startsWith("hypothesis.")) return "HYPOTHESIS";
  if (type.startsWith("primitive.")) return "PRIMITIVE";
  if (type.startsWith("finding.")) return "FINDING";
  if (type.startsWith("verification.")) return "VERIFY";
  if (type.startsWith("phase.")) return "PHASE";
  if (type.startsWith("task.")) return "TASK";
  if (type.startsWith("route.")) return "ROUTE";
  return "EVENT";
}

export default function App() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [selected, setSelected] = useState<EventRecord | null>(null);
  const [status, setStatus] = useState<"connecting" | "live" | "offline">("connecting");
  const cursor = useRef(0);

  useEffect(() => {
    let mounted = true;

    const refreshSnapshot = async () => {
      const response = await fetch(`${API}/api/snapshot`, { cache: "no-store" });
      if (!response.ok) throw new Error(`snapshot ${response.status}`);
      const next = (await response.json()) as Snapshot;
      if (mounted) setSnapshot(next);
    };

    const loadInitial = async () => {
      try {
        await refreshSnapshot();
        const response = await fetch(`${API}/api/events?after_seq=0&limit=1000`, { cache: "no-store" });
        if (!response.ok) throw new Error(`events ${response.status}`);
        const delta = (await response.json()) as Delta;
        if (!mounted) return;
        setEvents(delta.events);
        cursor.current = delta.cursor.seq;
        setSelected(delta.events.at(-1) ?? null);
        setStatus("live");
      } catch {
        if (mounted) setStatus("offline");
      }
    };

    const poll = async () => {
      try {
        const response = await fetch(`${API}/api/events?after_seq=${cursor.current}&limit=500`, { cache: "no-store" });
        if (!response.ok) throw new Error(`events ${response.status}`);
        const delta = (await response.json()) as Delta;
        if (!mounted) return;
        if (delta.events.length) {
          setEvents((current) => [...current, ...delta.events].slice(-2000));
          setSelected(delta.events.at(-1) ?? null);
          cursor.current = delta.cursor.seq;
          await refreshSnapshot();
        }
        setStatus("live");
      } catch {
        if (mounted) setStatus("offline");
      }
    };

    void loadInitial();
    const timer = window.setInterval(() => void poll(), 500);
    return () => {
      mounted = false;
      window.clearInterval(timer);
    };
  }, []);

  const counters = useMemo(() => {
    const view = snapshot?.view;
    if (!view) return [];
    return [
      ["Observations", Object.keys(view.observations).length],
      ["Findings", Object.keys(view.findings).length],
      ["Hypotheses", Object.keys(view.hypotheses).length],
      ["Primitives", Object.keys(view.primitives).length],
      ["Unknowns", Object.keys(view.unknowns).length],
      ["Next probes", view.next_probes.length]
    ] as const;
  }, [snapshot]);

  const challengeName = snapshot?.challenge_root.split(/[\\/]/).filter(Boolean).at(-1) ?? "No challenge";

  return (
    <div className="app-shell">
      <header className="topbar">
        <div>
          <div className="eyebrow">CTF-RAT DESKTOP</div>
          <h1>{challengeName}</h1>
        </div>
        <div className={`connection ${status}`}>
          <span className="dot" /> {status.toUpperCase()}
        </div>
      </header>

      <main className="workspace">
        <aside className="summary panel">
          <div className="panel-title">STATE</div>
          <div className="root-path">{snapshot?.challenge_root ?? `Waiting for ${API}`}</div>
          <div className="counter-grid">
            {counters.map(([label, value]) => (
              <div className="counter" key={label}>
                <span>{label}</span>
                <strong>{value}</strong>
              </div>
            ))}
          </div>
          <div className="meta-block">
            <span>Events</span><strong>{snapshot?.event_count ?? 0}</strong>
            <span>Cursor</span><strong>#{snapshot?.cursor.seq ?? 0}</strong>
          </div>
        </aside>

        <section className="timeline panel">
          <div className="panel-title">ACTIVITY TIMELINE</div>
          <div className="event-list">
            {events.length === 0 && <div className="empty">Waiting for STATE v2 events...</div>}
            {events.map((event) => (
              <button
                className={`event-row ${selected?.event_id === event.event_id ? "selected" : ""}`}
                key={event.event_id}
                onClick={() => setSelected(event)}
              >
                <span className="seq">#{event.seq}</span>
                <span className="kind">{group(event.type)}</span>
                <span className="event-main">
                  <strong>{event.type}</strong>
                  <small>{eventLabel(event)}</small>
                </span>
                <time>{new Date(event.at).toLocaleTimeString()}</time>
              </button>
            ))}
          </div>
        </section>

        <aside className="inspector panel">
          <div className="panel-title">INSPECTOR</div>
          {selected ? (
            <>
              <div className="inspector-head">
                <span>{group(selected.type)}</span>
                <strong>#{selected.seq}</strong>
              </div>
              <h2>{selected.type}</h2>
              <div className="inspector-meta">
                <span>actor</span><code>{selected.actor}</code>
                <span>task</span><code>{selected.task_id}</code>
                <span>event</span><code>{selected.event_id}</code>
              </div>
              <pre>{JSON.stringify(selected.payload, null, 2)}</pre>
            </>
          ) : (
            <div className="empty">Select an event.</div>
          )}
        </aside>
      </main>
    </div>
  );
}
