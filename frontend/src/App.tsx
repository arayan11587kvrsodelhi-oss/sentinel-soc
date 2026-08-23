import { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Brain,
  Database,
  Shield,
  Wifi,
} from "lucide-react";

const API = "http://localhost:8000";

type Event = {
  id: string;
  type: string;
  severity: string;
  source: string;
  timestamp: string;
};

export default function App() {
  const [events, setEvents] = useState<Event[]>([]);
  const [vulns, setVulns] = useState<any[]>([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    // Load NVD vulnerabilities
    fetch(`${API}/api/vulnerabilities`)
      .then((response) => {
        console.log("NVD API status:", response.status);

        if (!response.ok) {
          throw new Error(`API error: ${response.status}`);
        }

        return response.json();
      })
      .then((data) => {
        console.log("✅ NVD data received:", data);
        setVulns(data);
      })
      .catch((error) => {
        console.error("❌ NVD API failed:", error);
        setVulns([]);
      });

    // WebSocket
    let ws: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let disposed = false;

    const connect = () => {
      if (disposed) return;

      console.log("🔌 Connecting to WebSocket...");

      ws = new WebSocket("ws://localhost:8000/ws/events");

      ws.onopen = () => {
        console.log("✅ WebSocket connected");
        setConnected(true);
      };

      ws.onmessage = (e) => {
        try {
          const event: Event = JSON.parse(e.data);

          console.log("📡 Event received:", event);

          setEvents((prev) => [event, ...prev].slice(0, 20));
        } catch (error) {
          console.error("❌ Invalid WebSocket message:", error);
        }
      };

      ws.onerror = (error) => {
        console.error("❌ WebSocket error:", error);
      };

      ws.onclose = () => {
        console.log("🔌 WebSocket disconnected");
        setConnected(false);

        if (!disposed) {
          reconnectTimer = setTimeout(connect, 2000);
        }
      };
    };

    connect();

    return () => {
      disposed = true;

      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
      }

      if (ws) {
        ws.onclose = null;
        ws.onerror = null;

        if (
          ws.readyState === WebSocket.OPEN ||
          ws.readyState === WebSocket.CONNECTING
        ) {
          ws.close();
        }
      }
    };
  }, []);

  const critical = events.filter(
    (event) => event.severity === "CRITICAL"
  ).length;

  const high = events.filter(
    (event) => event.severity === "HIGH"
  ).length;

  return (
    <main className="shell">
      <header className="topbar">
        <div className="brand">
          <Shield />
          SENTINEL <span>SOC</span>
        </div>

        <div className="live">
          <i className={connected ? "dot on" : "dot"} />
          {connected ? "LIVE" : "OFFLINE"}
        </div>
      </header>

      <section className="hero">
        <p className="eyebrow">SECURITY OPERATIONS CENTER</p>

        <h1>
          Threat intelligence.
          <br />
          <em>Under control.</em>
        </h1>

        <p className="sub">
          Current vulnerability intelligence + controlled real-time
          simulation + AI-assisted defensive analysis.
        </p>
      </section>

      <section className="stats">
        <Stat
          icon={<AlertTriangle />}
          label="Critical Events"
          value={critical}
        />

        <Stat
          icon={<Activity />}
          label="High Events"
          value={high}
        />

        <Stat
          icon={<Database />}
          label="NVD Records"
          value={vulns.length}
        />

        <Stat
          icon={<Wifi />}
          label="WebSocket"
          value={connected ? "ONLINE" : "OFFLINE"}
        />
      </section>

      <section className="grid">
        <div className="panel">
          <div className="panel-head">
            <h2>LIVE EVENT STREAM</h2>
            <span>SIMULATION</span>
          </div>

          <div>
            {events.length === 0 ? (
              <p className="muted">Waiting for events…</p>
            ) : (
              events.map((event) => (
                <div className="log" key={event.id}>
                  <time>
                    {new Date(
                      event.timestamp
                    ).toLocaleTimeString()}
                  </time>

                  <b className={event.severity.toLowerCase()}>
                    {event.severity}
                  </b>

                  <strong>{event.type}</strong>

                  <small>{event.source}</small>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="panel">
          <div className="panel-head">
            <h2>AI ANALYST</h2>
            <Brain size={18} />
          </div>

          <div className="ai-card">
            <p className="eyebrow">DEFENSIVE ANALYSIS</p>

            <h3>Sentinel AI is ready.</h3>

            <p>
              Send an event to{" "}
              <code>POST /api/ai/analyze</code> for risk
              assessment, classification, summary and defensive
              recommendations.
            </p>
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>CURRENT NVD VULNERABILITIES</h2>
          <span>PUBLIC INTELLIGENCE</span>
        </div>

        <div className="vulns">
          {vulns.slice(0, 10).map((vulnerability) => (
            <article
              className="vuln"
              key={vulnerability.id}
            >
              <strong>
                {vulnerability.id || "Unavailable"}
              </strong>

              <span>
                {vulnerability.cvss ?? "—"} CVSS
              </span>

              <p>
                {vulnerability.description ||
                  vulnerability.error ||
                  "No description available."}
              </p>
            </article>
          ))}

          {!vulns.length && (
            <p className="muted">
              No vulnerability data loaded yet.
            </p>
          )}
        </div>
      </section>

      <footer>
        <span>SENTINEL SOC · EDUCATIONAL PROJECT</span>

        <span>
          Simulation events are synthetic. Intelligence is
          sourced from public feeds.
        </span>
      </footer>
    </main>
  );
}

function Stat({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: React.ReactNode;
}) {
  return (
    <div className="stat">
      <div className="icon">{icon}</div>

      <div>
        <small>{label}</small>
        <strong>{value}</strong>
      </div>
    </div>
  );
}