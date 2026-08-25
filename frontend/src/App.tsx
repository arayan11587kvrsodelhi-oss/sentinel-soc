import React, { useEffect, useState, useCallback } from "react";
import { Header } from "./components/Header";
import { StatsBar } from "./components/StatsBar";
import { LiveEventStream } from "./components/LiveEventStream";
import { IncidentList } from "./components/IncidentList";
import { AiAnalystPanel } from "./components/AiAnalystPanel";
import { VulnerabilityExplorer } from "./components/VulnerabilityExplorer";
import { EventDetailDrawer } from "./components/EventDetailDrawer";
import { IncidentDetailDrawer } from "./components/IncidentDetailDrawer";
import { VulnerabilityModal } from "./components/VulnerabilityModal";
import { MitreMatrix } from "./components/MitreMatrix";

import { useSentinelWebSocket } from "./hooks/useSentinelWebSocket";
import { api } from "./services/api";
import {
  SecurityEvent,
  Incident,
  IncidentStatus,
  Vulnerability,
  AiAnalysisResult,
  MitreMatrixItem,
} from "./types";

export default function App() {
  const {
    status: wsStatus,
    events,
    incidents,
    latencyMs,
    triggerScenario,
    setIncidents,
    clearEvents,
    reconnect,
  } = useSentinelWebSocket();

  // Vulnerability Intelligence State
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [vulnTotal, setVulnTotal] = useState<number>(0);
  const [vulnLastUpdated, setVulnLastUpdated] = useState<string>(new Date().toISOString());
  const [vulnCached, setVulnCached] = useState<boolean>(false);
  const [vulnDataSource, setVulnDataSource] = useState<string>("CACHED_NVD");
  const [kevCatalogTotal, setKevCatalogTotal] = useState<number>(0);
  const [kevDataSource, setKevDataSource] = useState<string>("CACHED_CISA_KEV");
  const [vulnLoading, setVulnLoading] = useState<boolean>(true);

  // AI Analyst State
  const [aiAnalysis, setAiAnalysis] = useState<AiAnalysisResult | null>(null);
  const [aiLoading, setAiLoading] = useState<boolean>(false);
  const [aiContext, setAiContext] = useState<{
    type: "EVENT" | "INCIDENT" | "MANUAL" | null;
    event?: SecurityEvent | null;
    incident?: Incident | null;
  }>({ type: null });

  // View Switcher State
  const [activeView, setActiveView] = useState<"DASHBOARD" | "MATRIX">("DASHBOARD");
  const [mitreMatrix, setMitreMatrix] = useState<MitreMatrixItem[]>([]);
  const [matrixLoading, setMatrixLoading] = useState<boolean>(false);

  // Detail Panels / Modals State
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);

  // Initial Load: Fetch NVD vulnerabilities, KEV catalog size & active incidents
  const loadIntelligence = useCallback(async (forceRefresh = false) => {
    setVulnLoading(true);
    try {
      const [nvdData, kevData] = await Promise.allSettled([
        api.getVulnerabilities({ limit: 40, force_refresh: forceRefresh }),
        api.getKevCatalog({ limit: 5, force_refresh: forceRefresh }),
      ]);

      if (nvdData.status === "fulfilled" && nvdData.value?.vulnerabilities) {
        const data = nvdData.value;
        setVulnerabilities(data.vulnerabilities);
        setVulnTotal(data.total || data.vulnerabilities.length);
        setVulnLastUpdated(data.last_updated || new Date().toISOString());
        setVulnCached(data.cached ?? true);
        setVulnDataSource(data.data_source || (data.cached ? "CACHED_NVD" : "LIVE_NVD"));
      }

      if (kevData.status === "fulfilled" && kevData.value) {
        const data = kevData.value;
        setKevCatalogTotal(data.catalog_size || data.total || 0);
        setKevDataSource(data.data_source || (data.cached ? "CACHED_CISA_KEV" : "LIVE_CISA_KEV"));
      }
    } catch (err) {
      console.error("Failed to load vulnerability intelligence:", err);
    } finally {
      setVulnLoading(false);
    }
  }, []);

  const loadIncidents = useCallback(async () => {
    try {
      const data = await api.getIncidents();
      if (Array.isArray(data) && data.length > 0) {
        setIncidents(data);
      }
    } catch (err) {
      console.warn("Failed to load incidents:", err);
    }
  }, [setIncidents]);

  const loadMitreMatrix = useCallback(async () => {
    setMatrixLoading(true);
    try {
      const data = await api.getMitreAttackMatrix();
      if (Array.isArray(data)) {
        setMitreMatrix(data);
      }
    } catch (err) {
      console.warn("Failed to load MITRE matrix:", err);
    } finally {
      setMatrixLoading(false);
    }
  }, []);

  useEffect(() => {
    loadIntelligence();
    loadIncidents();
    loadMitreMatrix();
  }, [loadIntelligence, loadIncidents, loadMitreMatrix]);

  // AI Triage Handlers
  const handleAnalyzeEvent = async (event: SecurityEvent) => {
    setAiLoading(true);
    setAiContext({ type: "EVENT", event });
    try {
      const result = await api.analyzeTelemetry({
        event_id: event.event_id || event.id,
        event_type: event.event_type || event.type,
        severity: event.severity,
        source_ip: event.source_ip,
        target: event.target,
        details: event.message,
      });
      setAiAnalysis(result);
    } catch (err) {
      console.error("AI Analysis failed:", err);
    } finally {
      setAiLoading(false);
    }
  };

  const handleAiTriageIncident = async (incident: Incident) => {
    setAiLoading(true);
    setAiContext({ type: "INCIDENT", incident });
    try {
      const result = await api.aiTriageIncident(incident.incident_id || incident.id || "");
      setAiAnalysis(result);

      // Cache analysis on incident object locally
      setIncidents((prev) =>
        prev.map((i) =>
          (i.incident_id || i.id) === (incident.incident_id || incident.id)
            ? { ...i, ai_analysis: result }
            : i
        )
      );
    } catch (err) {
      console.error("Incident AI triage failed:", err);
    } finally {
      setAiLoading(false);
    }
  };

  const handleRunLiveTriage = async () => {
    if (aiContext.type === "INCIDENT" && aiContext.incident) {
      return handleAiTriageIncident(aiContext.incident);
    }
    if (aiContext.type === "EVENT" && aiContext.event) {
      return handleAnalyzeEvent(aiContext.event);
    }

    // Default: Analyze top active incident or most recent critical event
    const criticalEvent = events.find((e) => e.severity === "CRITICAL") || events[0];
    if (criticalEvent) {
      return handleAnalyzeEvent(criticalEvent);
    }
    const activeInc = incidents[0];
    if (activeInc) {
      return handleAiTriageIncident(activeInc);
    }
  };

  // Status Lifecycle Update Handler
  const handleUpdateIncidentStatus = async (incidentId: string, status: IncidentStatus) => {
    // Optimistic update
    setIncidents((prev) =>
      prev.map((inc) =>
        (inc.incident_id || inc.id) === incidentId ? { ...inc, status } : inc
      )
    );
    if (selectedIncident && (selectedIncident.incident_id || selectedIncident.id) === incidentId) {
      setSelectedIncident((prev) => (prev ? { ...prev, status } : null));
    }

    try {
      await api.updateIncidentStatus(incidentId, status);
    } catch (err) {
      console.error(`Failed to update incident status for ${incidentId}:`, err);
    }
  };

  // Metrics calculation
  const criticalCount = events.filter((e) => e.severity === "CRITICAL").length;
  const highCount = events.filter((e) => e.severity === "HIGH").length;
  const activeIncidentsCount = incidents.filter(
    (i) => i.status === "OPEN" || i.status === "INVESTIGATING"
  ).length;
  const kevCount = vulnerabilities.filter((v) => v.is_kev).length;

  return (
    <main className="shell">
      {/* Top Header */}
      <Header
        wsStatus={wsStatus}
        latencyMs={latencyMs}
        onTriggerScenario={triggerScenario}
        onRefreshData={() => loadIntelligence(true)}
        onReconnect={reconnect}
      />

      {/* Hero Mission Statement */}
      <section className="hero">
        <p className="eyebrow">DEFENSIVE SECURITY OPERATIONS CENTER</p>
        <h1>
          Threat intelligence.
          <br />
          <em>Under control.</em>
        </h1>
        <p className="sub">
          Current vulnerability intelligence + controlled real-time simulation + AI-assisted defensive analysis.
        </p>
      </section>

      {/* Top Metrics Grid */}
      <StatsBar
        criticalCount={criticalCount}
        highCount={highCount}
        activeIncidentsCount={activeIncidentsCount}
        nvdCount={vulnTotal}
        kevCount={kevCatalogTotal || vulnerabilities.filter((v) => v.is_kev).length}
        wsStatus={wsStatus}
        nvdDataSource={vulnDataSource}
        kevDataSource={kevDataSource}
      />

      {/* Workspace View Switcher Tabs */}
      <div className="flex items-center justify-between mb-4 border-b border-slate-800 pb-2">
        <div className="flex items-center gap-2">
          <button
            className={`tab-btn ${activeView === "DASHBOARD" ? "active" : ""}`}
            onClick={() => setActiveView("DASHBOARD")}
          >
            SOC Operations Workspace
          </button>
          <button
            className={`tab-btn ${activeView === "MATRIX" ? "active" : ""}`}
            onClick={() => {
              setActiveView("MATRIX");
              loadMitreMatrix();
            }}
          >
            MITRE ATT&CK Matrix Navigator
          </button>
        </div>

        <span className="text-xs text-slate-400 font-mono hidden md:inline-block">
          {activeView === "DASHBOARD" ? "LIVE STREAM & CORRELATED INCIDENTS" : "ENTERPRISE COVERAGE MATRIX"}
        </span>
      </div>

      {/* Main Content Area Based on Active View */}
      {activeView === "DASHBOARD" ? (
        <>
          {/* Primary SOC Workspace Grid: Stream + Incidents */}
          <section className="layout-grid">
            <LiveEventStream
              events={events}
              selectedEventId={selectedEvent?.event_id || selectedEvent?.id}
              onSelectEvent={(ev) => setSelectedEvent(ev)}
              onAnalyzeEvent={(ev) => handleAnalyzeEvent(ev)}
              onClearEvents={clearEvents}
            />

            <IncidentList
              incidents={incidents}
              selectedIncidentId={selectedIncident?.incident_id || selectedIncident?.id}
              onSelectIncident={(inc) => setSelectedIncident(inc)}
              onAiTriageIncident={(inc) => handleAiTriageIncident(inc)}
              onUpdateStatus={handleUpdateIncidentStatus}
            />
          </section>

          {/* Secondary Workspace Grid: Sentinel AI + Vulnerabilities */}
          <section className="layout-grid">
            <AiAnalystPanel
              analysis={aiAnalysis}
              loading={aiLoading}
              selectedContext={aiContext}
              onRunLiveTriage={handleRunLiveTriage}
            />

            <VulnerabilityExplorer
              vulnerabilities={vulnerabilities}
              loading={vulnLoading}
              totalCount={vulnTotal}
              lastUpdated={vulnLastUpdated}
              isCached={vulnCached}
              dataSource={vulnDataSource}
              onSelectVulnerability={(vuln) => setSelectedVuln(vuln)}
              onForceRefresh={() => loadIntelligence(true)}
            />
          </section>
        </>
      ) : (
        <section className="mb-6">
          <MitreMatrix matrixData={mitreMatrix} loading={matrixLoading} />
        </section>
      )}

      {/* Forensic Detail Drawers & Modals */}
      <EventDetailDrawer
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
        onAnalyzeEvent={handleAnalyzeEvent}
      />

      <IncidentDetailDrawer
        incident={selectedIncident}
        recentEvents={events}
        onClose={() => setSelectedIncident(null)}
        onUpdateStatus={handleUpdateIncidentStatus}
        onAiTriageIncident={handleAiTriageIncident}
        onSelectEvent={(ev) => setSelectedEvent(ev)}
      />

      <VulnerabilityModal
        vulnerability={selectedVuln}
        onClose={() => setSelectedVuln(null)}
      />

      {/* SOC Footer */}
      <footer>
        <span>SENTINEL SOC · EDUCATIONAL CYBERSECURITY OPERATIONS PLATFORM</span>
        <span>
          Simulation events are synthetic and clearly labeled. Public threat intelligence is sourced from NIST NVD & CISA KEV feeds.
        </span>
      </footer>
    </main>
  );
}
