"use client"

import { useEffect, useState, useCallback } from "react"
import { useParams, useRouter } from "next/navigation"
import Link from "next/link"
import {
  ArrowLeft,
  FileCode,
  Shield,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Info,
  ExternalLink,
  Zap,
  Loader2,
  Check,
} from "lucide-react"
import { useNow } from "@/hooks/use-now"
import { formatLocalDateTime, formatRelativeTime, getUserTimeZone } from "@/lib/time"

interface ScanMeta {
  id: number
  repo_full_name: string
  pr_number: number
  head_sha: string
  status: string
  verdict: string | null
  summary: string | null
  created_at: string
  analysis_mode: "ai_enhanced" | "deterministic" | "degraded" | "error"
  retryable: boolean
}

interface Finding {
  id: number
  file: string
  line: number | null
  severity: string
  rule: string
  explanation: string
  raw_evidence: string
  proposed_patch: string | null
  patch_verified: string | null
  fix_applied: boolean
  fix_commit_sha: string | null
  source: "deterministic" | "ai_confirmed"
  confidence: "high" | "medium"
  fix_eligible: boolean
  validation_notes: string[]
  remediation: string | null
  reference: string | null
}

type ApplyState = "idle" | "loading" | "applied" | "error"

const severityConfig: Record<string, { label: string; className: string; icon: typeof Shield }> = {
  critical: { label: "Critical", className: "bg-red-50 text-red-700 border-red-200", icon: Shield },
  high: { label: "High", className: "bg-orange-50 text-orange-700 border-orange-200", icon: AlertTriangle },
  medium: { label: "Medium", className: "bg-amber-50 text-amber-700 border-amber-200", icon: AlertTriangle },
  low: { label: "Low", className: "bg-blue-50 text-blue-700 border-blue-200", icon: Info },
  info: { label: "Info", className: "bg-muted/50 text-muted-foreground border-border", icon: Info },
}

function SeverityBadge({ severity }: { severity: string }) {
  const config = severityConfig[severity] || severityConfig.info
  const Icon = config.icon
  return (
    <span className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-medium ${config.className}`}>
      <Icon className="h-3 w-3" /> {config.label}
    </span>
  )
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    completed: "bg-emerald-50 text-emerald-700",
    running: "bg-blue-50 text-blue-700",
    pending: "bg-muted/50 text-muted-foreground",
    failed: "bg-red-50 text-red-700",
  }

  return (
    <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${styles[status] || styles.pending}`}>
      {status}
    </span>
  )
}

function VerificationBadge({ status }: { status: string | null }) {
  if (!status) return null
  const configs: Record<string, { label: string; className: string; icon: typeof CheckCircle }> = {
    approve: { label: "Verified", className: "text-emerald-600", icon: CheckCircle },
    valid: { label: "Verified", className: "text-emerald-600", icon: CheckCircle },
    revise: { label: "Needs revision", className: "text-amber-600", icon: AlertTriangle },
    reject: { label: "Rejected", className: "text-red-600", icon: XCircle },
    invalid: { label: "Invalid", className: "text-red-600", icon: XCircle },
  }
  const config = configs[status] || { label: status, className: "text-muted-foreground", icon: Info }
  const Icon = config.icon
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-medium ${config.className}`}>
      <Icon className="h-3 w-3" /> {config.label}
    </span>
  )
}

function ApplyFixButton({
  scanId,
  findingId,
  state,
  onApply,
}: {
  scanId: string
  findingId: number
  state: ApplyState
  onApply: (findingId: number) => void
}) {
  if (state === "applied") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-md bg-emerald-50 border border-emerald-200 px-3 py-1.5 text-xs font-medium text-emerald-700">
        <Check className="h-3.5 w-3.5" /> Fix committed
      </span>
    )
  }

  if (state === "error") {
    return (
      <button
        onClick={() => onApply(findingId)}
        className="inline-flex items-center gap-1.5 rounded-md bg-red-50 border border-red-200 px-3 py-1.5 text-xs font-medium text-red-700 transition-colors hover:bg-red-100"
      >
        <XCircle className="h-3.5 w-3.5" /> Failed — retry
      </button>
    )
  }

  return (
    <button
      onClick={() => onApply(findingId)}
      disabled={state === "loading"}
      className="inline-flex items-center gap-1.5 rounded-md bg-foreground px-3 py-1.5 text-xs font-medium text-background transition-opacity hover:opacity-90 disabled:opacity-50"
    >
      {state === "loading" ? (
        <>
          <Loader2 className="h-3.5 w-3.5 animate-spin" /> Applying...
        </>
      ) : (
        <>
          <Zap className="h-3.5 w-3.5" /> Apply Fix
        </>
      )}
    </button>
  )
}

export default function ScanDetailPage() {
  const params = useParams()
  const router = useRouter()
  const scanId = params.id as string
  const [meta, setMeta] = useState<ScanMeta | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [retrying, setRetrying] = useState(false)
  const [applyStates, setApplyStates] = useState<Record<number, ApplyState>>({})
  const now = useNow(30_000)
  const userTimeZone = getUserTimeZone()

  useEffect(() => {
    let cancelled = false

    async function fetchData(showLoader = false) {
      if (showLoader) setLoading(true)

      try {
        const [metaRes, findingsRes] = await Promise.all([
          fetch(`/api/scans/${scanId}/meta`),
          fetch(`/api/scans/${scanId}/findings`),
        ])

        if (metaRes.ok) {
          if (!cancelled) {
            setMeta(await metaRes.json())
            setError(null)
          }
        }

        if (findingsRes.ok) {
          const data = await findingsRes.json()
          const findingsList = Array.isArray(data) ? data : []
          if (!cancelled) {
            setFindings(findingsList)
            setApplyStates((prev) => {
              const next = { ...prev }
              for (const f of findingsList) {
                if (f.fix_applied) next[f.id] = "applied"
              }
              return next
            })
          }
        } else if (findingsRes.status === 404) {
          if (!cancelled) setFindings([])
        } else {
          if (!cancelled) setError("Failed to load findings")
        }
      } catch {
        if (!cancelled) setError("Could not connect to backend")
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    fetchData(true)

    const pollTimer = window.setInterval(() => {
      if (document.visibilityState === "visible") {
        fetchData(false)
      }
    }, 8_000)

    return () => {
      cancelled = true
      window.clearInterval(pollTimer)
    }
  }, [scanId])

  const handleApplyFix = useCallback(async (findingId: number) => {
    setApplyStates((prev) => ({ ...prev, [findingId]: "loading" }))
    try {
      const res = await fetch(`/api/scans/${scanId}/findings/${findingId}/apply`, {
        method: "POST",
      })
      if (res.ok) {
        setApplyStates((prev) => ({ ...prev, [findingId]: "applied" }))
      } else {
        setApplyStates((prev) => ({ ...prev, [findingId]: "error" }))
      }
    } catch {
      setApplyStates((prev) => ({ ...prev, [findingId]: "error" }))
    }
  }, [scanId])

  const handleRetry = useCallback(async () => {
    setRetrying(true)
    try {
      const response = await fetch(`/api/scans/${scanId}/retry`, { method: "POST" })
      if (!response.ok) throw new Error("Retry failed")
      const result = await response.json()
      router.push(`/dashboard/scans/${result.scan_id}`)
    } catch {
      setError("Could not queue a new scan")
      setRetrying(false)
    }
  }, [router, scanId])

  const criticalCount = findings.filter((f) => f.severity === "critical" || f.severity === "high").length
  const mediumCount = findings.filter((f) => f.severity === "medium").length
  const lowCount = findings.filter((f) => f.severity === "low" || f.severity === "info").length

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <Link
          href="/dashboard/scans"
          className="inline-flex items-center gap-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          <ArrowLeft className="h-3.5 w-3.5" /> Back to scans
        </Link>

        <div className="mt-3 flex items-start justify-between">
          <div>
            {meta ? (
              <h1 className="text-2xl font-semibold tracking-tight text-foreground">
                {meta.repo_full_name} PR #{meta.pr_number}
              </h1>
            ) : (
              <h1 className="text-2xl font-semibold tracking-tight text-foreground">
                Scan #{scanId}
              </h1>
            )}
            {meta && (
              <div className="mt-1.5 flex items-center gap-3 text-sm text-muted-foreground">
                <code className="rounded bg-muted/50 px-1.5 py-0.5 font-mono text-xs">
                  {meta.head_sha.slice(0, 7)}
                </code>
                <StatusBadge status={meta.status} />
                <span title={`${formatLocalDateTime(meta.created_at)} (${userTimeZone})`}>
                  {formatLocalDateTime(meta.created_at)} ({formatRelativeTime(meta.created_at, now)})
                </span>
              </div>
            )}
            <p className="mt-1 text-sm text-muted-foreground">
              {findings.length} finding{findings.length !== 1 ? "s" : ""} detected
            </p>
          </div>

          {meta && (
            <div className="flex items-center gap-2">
              {meta.retryable && (
                <button
                  onClick={handleRetry}
                  disabled={retrying}
                  className="inline-flex items-center gap-1.5 rounded-md bg-foreground px-3 py-1.5 text-xs font-medium text-background disabled:opacity-50"
                >
                  {retrying ? <Loader2 className="h-3 w-3 animate-spin" /> : <Zap className="h-3 w-3" />}
                  {retrying ? "Queueing..." : "Retry scan"}
                </button>
              )}
              <a
                href={`https://github.com/${meta.repo_full_name}/pull/${meta.pr_number}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 rounded-md border border-border/60 px-3 py-1.5 text-xs font-medium text-muted-foreground transition-colors hover:bg-muted/50 hover:text-foreground"
              >
                View PR <ExternalLink className="h-3 w-3" />
              </a>
            </div>
          )}
        </div>
      </div>

      {/* Scan summary */}
      {meta?.summary && (
        <div className={`mb-6 rounded-lg border p-4 ${meta.analysis_mode === "degraded" ? "border-amber-200 bg-amber-50/40" : meta.analysis_mode === "error" ? "border-red-200 bg-red-50/40" : "border-border/60 bg-card"}`}>
          <div className="mb-1.5 flex items-center justify-between">
            <p className="text-xs font-medium text-muted-foreground">Scan Summary</p>
            <span className="rounded-full border border-border/60 bg-background/70 px-2 py-0.5 text-[11px] font-medium text-muted-foreground">
              {meta.analysis_mode === "ai_enhanced" ? "AI enhanced" : meta.analysis_mode === "degraded" ? "Deterministic fallback" : meta.analysis_mode === "error" ? "Scanner error" : "Deterministic"}
            </span>
          </div>
          <p className="text-sm leading-relaxed text-foreground">{meta.summary}</p>
        </div>
      )}

      {/* Severity stats */}
      {findings.length > 0 && (
        <div className="mb-6 flex items-center gap-3">
          {criticalCount > 0 && (
            <span className="inline-flex items-center gap-1 rounded-full border border-red-200 bg-red-50 px-3 py-1 text-xs font-medium text-red-700">
              {criticalCount} Critical/High
            </span>
          )}
          {mediumCount > 0 && (
            <span className="inline-flex items-center gap-1 rounded-full border border-amber-200 bg-amber-50 px-3 py-1 text-xs font-medium text-amber-700">
              {mediumCount} Medium
            </span>
          )}
          {lowCount > 0 && (
            <span className="inline-flex items-center gap-1 rounded-full border border-blue-200 bg-blue-50 px-3 py-1 text-xs font-medium text-blue-700">
              {lowCount} Low/Info
            </span>
          )}
        </div>
      )}

      {/* Findings */}
      {loading ? (
        <div className="flex items-center justify-center py-20">
          <div className="flex items-center gap-3 text-muted-foreground">
            <div className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
            <span className="text-sm">Loading findings...</span>
          </div>
        </div>
      ) : error ? (
        <div className="rounded-lg border border-border/60 bg-card px-5 py-16 text-center">
          <AlertTriangle className="mx-auto h-8 w-8 text-red-500" />
          <p className="mt-3 text-sm font-medium text-foreground">{error}</p>
        </div>
      ) : findings.length === 0 ? (
        meta?.status === "failed" ? (
          <div className="rounded-lg border border-red-200 bg-red-50/40 px-5 py-16 text-center">
            <XCircle className="mx-auto h-8 w-8 text-red-500" />
            <p className="mt-3 text-sm font-medium text-foreground">Scan failed</p>
            <p className="mt-1 text-xs text-muted-foreground">
              {meta.summary || "Gemini was unavailable for this scan. Please retry."}
            </p>
          </div>
        ) : (
          <div className="rounded-lg border border-border/60 bg-card px-5 py-16 text-center">
            <CheckCircle className="mx-auto h-8 w-8 text-emerald-500" />
            <p className="mt-3 text-sm font-medium text-foreground">No findings</p>
            <p className="mt-1 text-xs text-muted-foreground">
              This scan completed without detecting any issues.
            </p>
          </div>
        )
      ) : (
        <div className="space-y-4">
          {findings.map((finding) => (
            <div
              key={finding.id}
              className="rounded-lg border border-border/60 bg-card overflow-hidden"
            >
              {/* Finding header */}
              <div className="flex items-center justify-between border-b border-border/60 px-5 py-3">
                <div className="flex items-center gap-3">
                  <FileCode className="h-4 w-4 text-muted-foreground" />
                  <span className="font-mono text-sm text-foreground">{finding.file}</span>
                  {finding.line && (
                    <span className="rounded bg-muted/50 px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
                      L{finding.line}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <span className="rounded bg-muted/50 px-2 py-0.5 text-xs text-muted-foreground">
                    {finding.source === "ai_confirmed" ? "AI confirmed" : "Detector backed"} · {finding.confidence} confidence
                  </span>
                  <SeverityBadge severity={finding.severity} />
                  <span className="rounded bg-muted/50 px-2 py-0.5 font-mono text-xs text-muted-foreground">
                    {finding.rule}
                  </span>
                </div>
              </div>

              {/* Finding body */}
              <div className="px-5 py-4">
                <p className="text-sm leading-relaxed text-foreground">
                  {finding.explanation}
                </p>

                {finding.raw_evidence && (
                  <div className="mt-3">
                    <p className="mb-1.5 text-xs font-medium text-muted-foreground">Evidence</p>
                    <pre className="overflow-x-auto rounded-md bg-muted/30 p-3 font-mono text-xs leading-relaxed text-foreground">
                      {finding.raw_evidence}
                    </pre>
                  </div>
                )}

                {finding.remediation && (
                  <div className="mt-3 rounded-md border border-border/60 bg-muted/20 p-3">
                    <p className="mb-1 text-xs font-medium text-muted-foreground">Recommended remediation</p>
                    <p className="text-sm text-foreground">{finding.remediation}</p>
                    {finding.reference && (
                      <a href={finding.reference} target="_blank" rel="noopener noreferrer" className="mt-2 inline-flex items-center gap-1 text-xs text-muted-foreground underline underline-offset-2">
                        Authoritative guidance <ExternalLink className="h-3 w-3" />
                      </a>
                    )}
                  </div>
                )}

                {finding.proposed_patch && (
                  <div className="mt-3">
                    <div className="mb-1.5 flex items-center justify-between">
                      <p className="text-xs font-medium text-muted-foreground">Suggested Fix</p>
                      <VerificationBadge status={finding.patch_verified} />
                    </div>
                    <pre className="overflow-x-auto rounded-md bg-emerald-50/50 border border-emerald-100 p-3 font-mono text-xs leading-relaxed text-foreground">
                      {finding.proposed_patch}
                    </pre>

                    {/* Apply Fix button */}
                    <div className="mt-3 flex items-center justify-between">
                      <p className="text-xs text-muted-foreground">
                        {finding.fix_eligible ? "Mechanically verified against the current file." : "Suggestion only — this patch did not pass every mechanical gate."}
                      </p>
                      {finding.fix_eligible && (
                        <ApplyFixButton
                          scanId={scanId}
                          findingId={finding.id}
                          state={applyStates[finding.id] || "idle"}
                          onApply={handleApplyFix}
                        />
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
