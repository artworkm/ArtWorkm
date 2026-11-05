
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  CartesianGrid,
} from "recharts";
import api from "./api";

const COLORS = {
  critical: "#fb7185",
  high: "#fb923c",
  medium: "#facc15",
  low: "#38bdf8",
  other: "#94a3b8",
};

function formatDate(value) {
  if (!value) return "—";

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";

  return date.toLocaleString([], {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function severityClass(severity) {
  return String(severity || "other").toLowerCase();
}

export default function Dashboard({ onLogout }) {
  const [stats, setStats] = useState(null);
  const [detections, setDetections] = useState([]);
  const [me, setMe] = useState(null);
  const [newKey, setNewKey] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [keyLoading, setKeyLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);

  const loadDashboard = useCallback(async () => {
    try {
      const [statsResponse, detectionsResponse] = await Promise.all([
        api.get("/stats"),
        api.get("/detections"),
      ]);

      setStats(statsResponse.data);
      setDetections(detectionsResponse.data);
      setLastUpdated(new Date());
      setError("");
    } catch (err) {
      console.error("Dashboard loading failed:", err);
      setError(
        err.response?.data?.detail ||
        "Could not load dashboard data. Check that the backend is running."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    api.get("/auth/me")
      .then((response) => setMe(response.data))
      .catch((err) => {
        console.error("Could not load account information:", err);
      });

    loadDashboard();

    const intervalId = setInterval(loadDashboard, 5000);

    return () => clearInterval(intervalId);
  }, [loadDashboard]);

  const typeData = useMemo(() => {
    return Object.entries(stats?.detections_by_type || {})
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count);
  }, [stats]);

  const severityData = useMemo(() => {
    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      other: 0,
    };

    detections.forEach((detection) => {
      const severity = severityClass(detection.severity);
      if (Object.hasOwn(counts, severity)) {
        counts[severity] += 1;
      } else {
        counts.other += 1;
      }
    });

    return Object.entries(counts)
      .filter(([, count]) => count > 0)
      .map(([name, value]) => ({
        name: name.charAt(0).toUpperCase() + name.slice(1),
        value,
        color: COLORS[name],
      }));
  }, [detections]);

  const urgentCount = useMemo(() => {
    return detections.filter((detection) =>
      ["critical", "high"].includes(severityClass(detection.severity))
    ).length;
  }, [detections]);

  async function createApiKey() {
    setKeyLoading(true);
    setNewKey("");

    try {
      const response = await api.post("/api-keys", {
        name: "SentinelAI Dashboard Key",
      });

      setNewKey(response.data.api_key);
    } catch (err) {
      setError(
        err.response?.data?.detail ||
        "Could not create an API key. Administrator access may be required."
      );
    } finally {
      setKeyLoading(false);
    }
  }

  async function copyApiKey() {
    try {
      await navigator.clipboard.writeText(newKey);
    } catch {
      setError("Clipboard access failed. Select and copy the key manually.");
    }
  }

  if (loading) {
    return (
      <div className="loading-screen">
        <div className="loading-orbit" />
        <h2>SentinelAI</h2>
        <p>Initializing security dashboard...</p>
      </div>
    );
  }

  return (
    <main className="dashboard-shell">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />

      <div className="dashboard-content">
        <header className="topbar">
          <div className="brand">
            <div className="brand-mark">
              <span>✦</span>
            </div>
            <div>
              <h1>Sentinel<span>AI</span></h1>
              <p>INTELLIGENT THREAT MONITORING</p>
            </div>
          </div>

          <div className="topbar-right">
            <div className="system-status">
              <span className="status-dot" />
              <span>Monitoring</span>
            </div>

            <div className="account-info">
              <div className="avatar">
                {(me?.email || "U").charAt(0).toUpperCase()}
              </div>
              <div className="account-text">
                <strong>{me?.email || "Account"}</strong>
                <span>Organization #{me?.org_id ?? "—"}</span>
              </div>
            </div>

            <button className="logout-button" onClick={onLogout}>
              Log out
            </button>
          </div>
        </header>

        <section className="welcome-section">
          <div>
            <p className="eyebrow">SECURITY OVERVIEW</p>
            <h2>Your security command center.</h2>
            <p className="welcome-description">
              Monitor incoming events, understand detected threats, and keep
              your organization informed.
            </p>
          </div>

          <div className="refresh-info">
            <span className="refresh-indicator" />
            <div>
              <strong>Live updates</strong>
              <span>
                {lastUpdated
                  ? `Updated ${lastUpdated.toLocaleTimeString()}`
                  : "Waiting for data"}
              </span>
            </div>
          </div>
        </section>

        {error && (
          <div className="notice error-notice">
            <span>!</span>
            <p>{error}</p>
            <button onClick={() => setError("")}>Dismiss</button>
          </div>
        )}

        <section className="metrics-grid">
          <article className="metric-card metric-cyan">
            <div className="metric-top">
              <span className="metric-label">TOTAL EVENTS</span>
              <span className="metric-icon">⌁</span>
            </div>
            <strong className="metric-value">
              {(stats?.total_events ?? 0).toLocaleString()}
            </strong>
            <span className="metric-caption">Security events received</span>
            <div className="metric-decoration" />
          </article>

          <article className="metric-card metric-violet">
            <div className="metric-top">
              <span className="metric-label">TOTAL DETECTIONS</span>
              <span className="metric-icon">◎</span>
            </div>
            <strong className="metric-value">
              {(stats?.total_detections ?? 0).toLocaleString()}
            </strong>
            <span className="metric-caption">Threats identified by SentinelAI</span>
            <div className="metric-decoration" />
          </article>

          <article className="metric-card metric-orange">
            <div className="metric-top">
              <span className="metric-label">HIGH / CRITICAL</span>
              <span className="metric-icon">⚠</span>
            </div>
            <strong className="metric-value">
              {urgentCount.toLocaleString()}
            </strong>
            <span className="metric-caption">
              In the detections currently loaded
            </span>
            <div className="metric-decoration" />
          </article>
        </section>

        <section className="charts-grid">
          <article className="panel chart-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">THREAT CLASSIFICATION</p>
                <h3>Detections by attack type</h3>
              </div>
              <span className="panel-symbol">▥</span>
            </div>

            {typeData.length > 0 ? (
              <ResponsiveContainer width="100%" height={280}>
                <BarChart
                  data={typeData}
                  margin={{ top: 12, right: 8, left: -18, bottom: 8 }}
                >
                  <CartesianGrid
                    stroke="#243449"
                    strokeDasharray="3 5"
                    vertical={false}
                  />
                  <XAxis
                    dataKey="label"
                    tick={{ fill: "#9aabc0", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                    interval={0}
                    angle={-18}
                    textAnchor="end"
                    height={55}
                  />
                  <YAxis
                    allowDecimals={false}
                    tick={{ fill: "#9aabc0", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    cursor={{ fill: "rgba(56,189,248,0.07)" }}
                    contentStyle={{
                      background: "#101d30",
                      border: "1px solid #2b4058",
                      borderRadius: 10,
                      color: "#e5edf7",
                    }}
                  />
                  <Bar
                    dataKey="count"
                    name="Detections"
                    fill="#38bdf8"
                    radius={[6, 6, 0, 0]}
                    maxBarSize={42}
                    animationDuration={900}
                  />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="empty-chart">
                <span>◌</span>
                <p>No attack detections yet</p>
                <small>Detection data will appear here when available.</small>
              </div>
            )}
          </article>

          <article className="panel chart-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">RISK DISTRIBUTION</p>
                <h3>Detections by severity</h3>
              </div>
              <span className="panel-symbol">◉</span>
            </div>

            {severityData.length > 0 ? (
              <div className="severity-chart">
                <div className="donut-wrap">
                  <ResponsiveContainer width="100%" height={230}>
                    <PieChart>
                      <Pie
                        data={severityData}
                        dataKey="value"
                        nameKey="name"
                        innerRadius={66}
                        outerRadius={92}
                        paddingAngle={4}
                        stroke="none"
                        animationDuration={900}
                      >
                        {severityData.map((entry) => (
                          <Cell key={entry.name} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          background: "#101d30",
                          border: "1px solid #2b4058",
                          borderRadius: 10,
                          color: "#e5edf7",
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="donut-center">
                    <strong>{detections.length}</strong>
                    <span>Loaded</span>
                  </div>
                </div>

                <div className="severity-legend">
                  {severityData.map((item) => (
                    <div className="legend-row" key={item.name}>
                      <span
                        className="legend-dot"
                        style={{ background: item.color }}
                      />
                      <span>{item.name}</span>
                      <strong>{item.value}</strong>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="empty-chart">
                <span>◌</span>
                <p>No severity data yet</p>
                <small>Severity distribution will appear here.</small>
              </div>
            )}
          </article>
        </section>

        <section className="panel detections-panel">
          <div className="panel-heading detections-heading">
            <div>
              <p className="eyebrow">RECENT ACTIVITY</p>
              <h3>Latest detections</h3>
              <p className="panel-subtitle">
                Security threats identified by your detection engine
              </p>
            </div>
            <span className="live-pill">
              <span className="status-dot" />
              LIVE
            </span>
          </div>

          <div className="table-scroll">
            <table className="detections-table">
              <thead>
                <tr>
                  <th>DETECTION</th>
                  <th>TIME</th>
                  <th>SEVERITY</th>
                  <th>CONFIDENCE</th>
                  <th>DETECTION ENGINE</th>
                </tr>
              </thead>
              <tbody>
                {detections.slice(0, 15).map((detection) => (
                  <tr key={detection.id}>
                    <td>
                      <div className="attack-name">
                        <span className="attack-indicator" />
                        <strong>{detection.predicted_label}</strong>
                      </div>
                    </td>
                    <td className="time-cell">
                      {formatDate(detection.created_at)}
                    </td>
                    <td>
                      <span
                        className={`severity-badge ${severityClass(
                          detection.severity
                        )}`}
                      >
                        {detection.severity || "Unknown"}
                      </span>
                    </td>
                    <td>
                      <div className="confidence-cell">
                        <div className="confidence-track">
                          <div
                            className="confidence-fill"
                            style={{
                              width: `${Math.max(
                                0,
                                Math.min(100, Number(detection.confidence) * 100)
                              )}%`,
                            }}
                          />
                        </div>
                        <span>
                          {(
                            Number(detection.confidence || 0) * 100
                          ).toFixed(0)}
                          %
                        </span>
                      </div>
                    </td>
                    <td className="engine-cell">
                      {detection.model_name || "Unknown"}
                    </td>
                  </tr>
                ))}

                {detections.length === 0 && (
                  <tr>
                    <td colSpan="5" className="empty-table">
                      No detections recorded yet. Your dashboard is ready
                      and waiting for security events.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          <div className="table-footer">
            Showing {Math.min(detections.length, 15)} of{" "}
            {detections.length} loaded detections
          </div>
        </section>

        <section className="panel integration-panel">
          <div className="integration-copy">
            <p className="eyebrow">CONNECT YOUR SYSTEMS</p>
            <h3>Integrate with SentinelAI</h3>
            <p>
              Generate an organization API key to authenticate security
              events sent to your SentinelAI backend.
            </p>
          </div>

          <button
            className="primary-button"
            onClick={createApiKey}
            disabled={keyLoading}
          >
            {keyLoading ? "Generating..." : "+ Create API key"}
          </button>

          {newKey && (
            <div className="api-key-result">
              <div>
                <strong>Your new API key</strong>
                <p>Copy it now. It will not be displayed again.</p>
                <code>{newKey}</code>
              </div>
              <button className="copy-button" onClick={copyApiKey}>
                Copy key
              </button>
            </div>
          )}
        </section>

        <footer className="dashboard-footer">
          <span>✦ SentinelAI</span>
          <span>Intelligent security. Clear visibility.</span>
        </footer>
      </div>
    </main>
  );
}
