"use client"

import { useSession } from "next-auth/react"
import { useEffect, useState } from "react"
import Link from "next/link"
import { Shield, AlertTriangle, CheckCircle, Clock, GitPullRequest, ExternalLink, Search } from "lucide-react"

interface ScanRun {
  id: number
  pr_number: number
  head_sha: string
  status: string
  verdict: string | null
  summary: string | null
  created_at: string
  repo_full_name?: string
}

const verdictConfig: Record<string, { label: string; className: string; icon: typeof CheckCircle }> = {
  pass: { label: "Pass", className: "bg-emerald-50 text-emerald-700 border-emerald-200", icon: CheckCircle },
  warning: { label: "Warning", className: "bg-amber-50 text-amber-700 border-amber-200", icon: AlertTriangle },
  fail: { label: "Fail", className: "bg-red-50 text-red-700 border-red-200", icon: Shield },
}

function VerdictBadge({ verdict }: { verdict: string | null }) {
  if (!verdict) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-border bg-muted/50 px-2.5 py-0.5 text-xs font-medium text-muted-foreground">
        <Clock className="h-3 w-3" /> Pending
      </span>
    )
  }
  const config = verdictConfig[verdict] || verdictConfig.warning
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

type FilterVerdict = "all" | "pass" | "warning" | "fail"
type FilterStatus = "all" | "completed" | "failed" | "running" | "pending"

export default function ScansPage() {
  const { data: session } = useSession()
  const [scans, setScans] = useState<ScanRun[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [verdictFilter, setVerdictFilter] = useState<FilterVerdict>("all")
  const [statusFilter, setStatusFilter] = useState<FilterStatus>("all")

  useEffect(() => {
    async function fetchScans() {
      if (!session?.user) return
      const login = (session.user as { login?: string }).login
      if (!login) return
      try {
        const res = await fetch(`/api/scans?owner=${encodeURIComponent(login)}`)
        if (res.ok) {
          const data = await res.json()
          setScans(Array.isArray(data) ? data : [])
        } else {
          setScans([])
        }
      } catch {
        setError("Could not connect to backend")
      } finally {
        setLoading(false)
      }
    }
    fetchScans()
  }, [session])

  const filtered = scans.filter((s) => {
    if (verdictFilter !== "all" && s.verdict !== verdictFilter) return false
    if (statusFilter !== "all" && s.status !== statusFilter) return false
    return true
  })

  const filterButtonClass = (active: boolean) =>
    `rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
      active
        ? "bg-foreground text-background"
        : "text-muted-foreground hover:bg-muted/50 hover:text-foreground"
    }`

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">
          Scans
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          All security scans across your repositories.
        </p>
      </div>

      {/* Filters */}
      <div className="mb-5 flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-muted-foreground mr-1">Verdict:</span>
          {(["all", "pass", "warning", "fail"] as FilterVerdict[]).map((v) => (
            <button
              key={v}
              onClick={() => setVerdictFilter(v)}
              className={filterButtonClass(verdictFilter === v)}
            >
              {v === "all" ? "All" : v.charAt(0).toUpperCase() + v.slice(1)}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-muted-foreground mr-1">Status:</span>
          {(["all", "completed", "failed", "running"] as FilterStatus[]).map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={filterButtonClass(statusFilter === s)}
            >
              {s === "all" ? "All" : s.charAt(0).toUpperCase() + s.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Scan List */}
      <div className="rounded-lg border border-border/60 bg-card">
        {loading ? (
          <div className="flex items-center justify-center py-16">
            <div className="flex items-center gap-3 text-muted-foreground">
              <div className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
              <span className="text-sm">Loading scans...</span>
            </div>
          </div>
        ) : error ? (
          <div className="px-5 py-16 text-center">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-red-50">
              <AlertTriangle className="h-6 w-6 text-red-500" />
            </div>
            <p className="mt-4 text-sm font-medium text-foreground">Backend unavailable</p>
            <p className="mt-1 text-xs text-muted-foreground">{error}</p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="px-5 py-16 text-center">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-muted/50">
              <Search className="h-6 w-6 text-muted-foreground" />
            </div>
            <p className="mt-4 text-sm font-medium text-foreground">
              {scans.length === 0 ? "No scans yet" : "No scans match filters"}
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              {scans.length === 0
                ? "Open a PR in a repo with the Polaris app installed to trigger a scan."
                : "Try adjusting your filters to see more results."}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-border/60">
            {filtered.map((scan) => (
              <div
                key={scan.id}
                className="flex items-center justify-between px-5 py-4 transition-colors hover:bg-muted/30"
              >
                <Link
                  href={`/dashboard/scans/${scan.id}`}
                  className="flex flex-1 items-center gap-4"
                >
                  <div className="flex h-9 w-9 items-center justify-center rounded-md bg-muted/50">
                    <GitPullRequest className="h-4 w-4 text-muted-foreground" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-foreground">
                        {scan.repo_full_name} PR #{scan.pr_number}
                      </span>
                      <StatusBadge status={scan.status} />
                    </div>
                    <div className="mt-0.5 flex items-center gap-2 text-xs text-muted-foreground">
                      <code className="rounded bg-muted/50 px-1 py-0.5 font-mono text-[11px]">
                        {scan.head_sha.slice(0, 7)}
                      </code>
                      <span>{new Date(scan.created_at).toLocaleDateString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}</span>
                    </div>
                  </div>
                </Link>
                <div className="flex items-center gap-3">
                  <VerdictBadge verdict={scan.verdict} />
                  <a
                    href={`https://github.com/${scan.repo_full_name}/pull/${scan.pr_number}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="rounded p-1 text-muted-foreground/50 transition-colors hover:bg-muted/50 hover:text-foreground"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <ExternalLink className="h-3.5 w-3.5" />
                  </a>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
