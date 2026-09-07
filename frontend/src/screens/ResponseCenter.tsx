import { useEffect, useState } from "react"
import {
  SimulatedActionRecord,
  simulateResponseAction,
  getResponseAuditLog,
} from "../lib/sentinel-api"

interface ActionDef {
  id: string
  title: string
  desc: string
  target: string
  icon: string
  color: string
  detail: string
}

const actions: ActionDef[] = [
  {
    id: "HOST_ISOLATION",
    title: "Isolate Host",
    desc: "Simulated network isolation — removes host from all network segments",
    target: "auth-01",
    icon: "⊘",
    color: "#FF4D5E",
    detail:
      "Simulates blocking all inbound/outbound traffic to the target host at the network switch level.",
  },
  {
    id: "IP_BAN",
    title: "Block IP",
    desc: "Simulated firewall rule — blocks source IP at perimeter",
    target: "192.168.1.42",
    icon: "⊗",
    color: "#FF8A4C",
    detail:
      "Simulates adding a deny rule for 192.168.1.42 across all perimeter firewall devices.",
  },
  {
    id: "CREDENTIAL_REVOCATION",
    title: "Disable Account",
    desc: "Simulated account containment — disables compromised user account",
    target: "admin",
    icon: "⊘",
    color: "#F4C95D",
    detail:
      "Simulates disabling the affected account in the identity provider and invalidating active sessions.",
  },
  {
    id: "FORCE_PASSWORD_RESET",
    title: "Force Password Reset",
    desc: "Simulated credential rotation for targeted accounts",
    target: "admin, root, svc_backup",
    icon: "↺",
    color: "#7C8CFF",
    detail:
      "Simulates forcing an immediate password change for all accounts targeted in the attack.",
  },
  {
    id: "CAPTURE_MEMORY",
    title: "Capture Memory Dump",
    desc: "Simulated forensic memory capture for analysis",
    target: "auth-01",
    icon: "⊡",
    color: "#56B4FF",
    detail:
      "Simulates initiating a live memory dump from the affected system for forensic analysis.",
  },
  {
    id: "SNAPSHOT",
    title: "Create System Snapshot",
    desc: "Simulated disk snapshot for forensic preservation",
    target: "auth-01",
    icon: "◉",
    color: "#42D392",
    detail:
      "Simulates creating a point-in-time disk snapshot to preserve evidence.",
  },
]

export default function ResponseCenter() {
  const [simulating, setSimulating] = useState<string | null>(null)
  const [results, setResults] = useState<SimulatedActionRecord[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setIsLoading(true)
    setError(null)
    getResponseAuditLog(50)
      .then((data) => {
        if (cancelled) return
        setResults(data)
      })
      .catch((err) => {
        if (cancelled) return
        setError(err instanceof Error ? err.message : "Failed to load audit log")
      })
      .finally(() => {
        if (cancelled) return
        setIsLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  const runSimulation = async (actionId: string, target: string) => {
    setSimulating(actionId)
    setError(null)
    try {
      const record = await simulateResponseAction({
        action_type: actionId,
        target,
        triggered_by: "SOC Analyst",
        reason: `Manual response action from Response Center`,
      })
      setResults((prev) => [record, ...prev])
    } catch (err) {
      setError(err instanceof Error ? err.message : "Response action failed")
    } finally {
      setSimulating(null)
    }
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold" style={{ color: "#F4F7FA" }}>
            Response Center
          </h1>
          <p className="text-sm mt-0.5" style={{ color: "#9AA8B8" }}>
            Defensive response playbooks — simulated containment actions
          </p>
        </div>
      </div>

      {/* Simulation Banner */}
      <div
        className="rounded-xl p-4 flex items-start gap-4"
        style={{
          background: "#F4C95D08",
          border: "2px solid #F4C95D40",
        }}
      >
        <div
          className="w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0"
          style={{ background: "#F4C95D20" }}
        >
          <span className="text-xl">⚠</span>
        </div>
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="font-semibold" style={{ color: "#F4C95D" }}>
              SIMULATION ENVIRONMENT
            </span>
            <span
              className="text-[10px] px-1.5 py-0.5 rounded font-semibold"
              style={{ background: "#F4C95D20", color: "#F4C95D" }}
            >
              ◆ SIMULATED
            </span>
          </div>
          <p className="text-sm" style={{ color: "#9AA8B8" }}>
            All response actions in this environment are{" "}
            <span className="font-semibold" style={{ color: "#F4C95D" }}>
              simulated
            </span>
            . No real infrastructure will be modified, no accounts will be
            disabled, and no firewall rules will be created. This is a safe
            learning and testing environment.
          </p>
        </div>
      </div>

      {error && (
        <div
          className="rounded-xl p-4"
          style={{
            background: "#FF4D5E08",
            border: "1px solid #FF4D5E40",
            color: "#FF4D5E",
          }}
        >
          <p className="text-sm font-medium">Action failed</p>
          <p className="text-xs mt-1" style={{ color: "#FF8A8F" }}>
            {error}
          </p>
        </div>
      )}

      <div className="grid grid-cols-5 gap-5">
        {/* Actions */}
        <div className="col-span-3 space-y-3">
          <span
            className="text-xs font-semibold tracking-widest uppercase"
            style={{ color: "#627083" }}
          >
            AVAILABLE RESPONSE ACTIONS
          </span>
          {actions.map((action) => {
            const isRunning = simulating === action.id
            const hasDone = results.some((r) => r.action_type === action.id)

            return (
              <div
                key={action.id}
                className="rounded-xl p-4"
                style={{ background: "#111925", border: "1px solid #1D2938" }}
              >
                <div className="flex items-start gap-4">
                  <div
                    className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 text-lg"
                    style={{
                      background: action.color + "15",
                      color: action.color,
                    }}
                  >
                    {action.icon}
                  </div>

                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span
                        className="text-sm font-semibold"
                        style={{ color: "#F4F7FA" }}
                      >
                        {action.title}
                      </span>
                      {hasDone && !isRunning && (
                        <span
                          className="text-[10px] px-1.5 py-0.5 rounded font-medium"
                          style={{ background: "#42D39215", color: "#42D392" }}
                        >
                          ✓ SIMULATED
                        </span>
                      )}
                    </div>
                    <p className="text-xs mb-1" style={{ color: "#9AA8B8" }}>
                      {action.desc}
                    </p>
                    <p className="text-xs mb-2" style={{ color: "#627083" }}>
                      {action.detail}
                    </p>
                    <div className="flex items-center gap-2">
                      <span
                        className="text-[10px]"
                        style={{ color: "#627083" }}
                      >
                        Target:
                      </span>
                      <span
                        className="font-mono text-[11px] font-medium"
                        style={{ color: "#9AA8B8" }}
                      >
                        {action.target}
                      </span>
                    </div>
                  </div>

                  <button
                    onClick={() => runSimulation(action.id, action.target)}
                    disabled={isRunning || simulating !== null}
                    className="flex-shrink-0 px-4 py-2 rounded-lg text-xs font-semibold transition-all"
                    style={{
                      background: isRunning
                        ? action.color + "20"
                        : hasDone
                          ? "#42D39215"
                          : action.color + "15",

                      color: isRunning
                        ? action.color
                        : hasDone
                          ? "#42D392"
                          : action.color,

                      border: `1px solid ${
                        isRunning
                          ? action.color + "40"
                          : hasDone
                            ? "#42D39230"
                            : action.color + "30"
                      }`,

                      opacity: simulating !== null && !isRunning ? 0.5 : 1,

                      cursor:
                        simulating !== null && !isRunning
                          ? "not-allowed"
                          : "pointer",
                    }}
                  >
                    {isRunning ? (
                      <span className="flex items-center gap-1.5">
                        <span
                          className="w-2 h-2 rounded-full animate-pulse"
                          style={{ background: "currentColor" }}
                        />
                        Running...
                      </span>
                    ) : hasDone ? (
                      "Re-simulate"
                    ) : (
                      "SIMULATE"
                    )}
                  </button>
                </div>
              </div>
            )
          })}
        </div>

        {/* Results panel */}
        <div className="col-span-2 space-y-4">
          <div
            className="rounded-xl p-4 sticky top-0"
            style={{ background: "#111925", border: "1px solid #1D2938" }}
          >
            <span
              className="text-xs font-semibold tracking-widest uppercase block mb-3"
              style={{ color: "#627083" }}
            >
              SIMULATION LOG
            </span>

            {isLoading ? (
              <div
                className="rounded-lg p-6 text-center"
                style={{ background: "#0D131D", border: "1px solid #1D2938" }}
              >
                <p className="text-xs" style={{ color: "#627083" }}>
                  Loading audit log…
                </p>
              </div>
            ) : results.length === 0 ? (
              <div
                className="rounded-lg p-6 text-center"
                style={{ background: "#0D131D", border: "1px solid #1D2938" }}
              >
                <div className="text-2xl mb-2" style={{ color: "#1D2938" }}>
                  ◌
                </div>
                <p className="text-xs" style={{ color: "#627083" }}>
                  No simulations run yet. Execute a response action to see
                  results here.
                </p>
              </div>
            ) : (
              <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
                {results.map((res, i) => (
                  <div
                    key={`${res.action_id}-${i}`}
                    className="rounded-lg p-3"
                    style={{
                      background: "#0D131D",
                      border: "1px solid #42D39230",
                    }}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <div
                        className="w-2 h-2 rounded-full"
                        style={{ background: "#42D392" }}
                      />
                      <span
                        className="text-xs font-semibold"
                        style={{ color: "#42D392" }}
                      >
                        ✓ {res.status}
                      </span>
                    </div>
                    <div className="space-y-1 text-xs">
                      <div className="flex items-center justify-between">
                        <span style={{ color: "#627083" }}>Action</span>
                        <span
                          className="font-mono font-medium"
                          style={{ color: "#F4F7FA" }}
                        >
                          {res.action_label}
                        </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span style={{ color: "#627083" }}>Target</span>
                        <span
                          className="font-mono font-medium"
                          style={{ color: "#9AA8B8" }}
                        >
                          {res.target}
                        </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span style={{ color: "#627083" }}>Time</span>
                        <span
                          className="font-mono text-[10px]"
                          style={{ color: "#627083" }}
                        >
                          {new Date(res.timestamp).toLocaleTimeString([], {
                            hour: "2-digit",
                            minute: "2-digit",
                            second: "2-digit",
                          })}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {results.length > 0 && (
              <div
                className="mt-3 p-2.5 rounded-lg text-center text-xs"
                style={{
                  background: "#F4C95D08",
                  border: "1px solid #F4C95D20",
                  color: "#F4C95D",
                }}
              >
                ◆ All actions above are simulated · No real changes were made
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
