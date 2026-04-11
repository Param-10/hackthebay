"use client"

import { useSession } from "next-auth/react"
import { useEffect, useState } from "react"
import Link from "next/link"
import { Shield, AlertTriangle, CheckCircle, Clock, GitPullRequest, ExternalLink, Search, ArrowRight } from "lucide-react"

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

export default function DashboardPage() {
  const { data: session } = useSession()
  const [scans, setScans] = useState<ScanRun[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

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

  const totalScans = scans.length
  const totalFindings = scans.filter((s) => s.verdict === "warning" || s.verdict === "fail").length
  const passRate = totalScans > 0 ? Math.round((scans.filter((s) => s.verdict === "pass").length / totalScans) * 100) : 0

  return (
    <div>
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">
          Welcome back{session?.user?.name ? `, ${session.user.name}` : ""}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Here&apos;s an overview of your security scans.
        </p>
      </div>

      {/* Stats */}
      <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="rounded-lg border border-border/60 bg-card p-5">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-md bg-muted/50">
              <Search className="h-5 w-5 text-muted-foreground" />
            </div>
            <div>
              <p className="text-2xl font-semibold text-foreground">{totalScans}</p>
              <p className="text-xs text-muted-foreground">Total Scans</p>
            </div>
          </div>
        </div>
        <div className="rounded-lg border border-border/60 bg-card p-5">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-md bg-amber-50">
              <AlertTriangle className="h-5 w-5 text-amber-600" />
            </div>
            <div>
              <p className="text-2xl font-semibold text-foreground">{totalFindings}</p>
              <p className="text-xs text-muted-foreground">Issues Found</p>
            </div>
          </div>
        </div>
        <div className="rounded-lg border border-border/60 bg-card p-5">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-md bg-emerald-50">
              <CheckCircle className="h-5 w-5 text-emerald-600" />
            </div>
            <div>
              <p className="text-2xl font-semibold text-foreground">{passRate}%</p>
              <p className="text-xs text-muted-foreground">Pass Rate</p>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Scans */}
      <div className="rounded-lg border border-border/60 bg-card">
        <div className="flex items-center justify-between border-b border-border/60 px-5 py-4">
          <h2 className="text-sm font-semibold text-foreground">Recent Scans</h2>
          {scans.length > 0 && (
            <Link
              href="/dashboard/scans"
              className="inline-flex items-center gap-1 text-xs font-medium text-muted-foreground transition-colors hover:text-foreground"
            >
              View all <ArrowRight className="h-3 w-3" />
            </Link>
          )}
        </div>

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
        ) : scans.length === 0 ? (
          <div className="px-5 py-12">
            <div className="mx-auto max-w-md text-center">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-muted/50">
                <GitPullRequest className="h-6 w-6 text-muted-foreground" />
              </div>
              <p className="mt-4 text-base font-medium text-foreground">Get started with Polaris</p>
              <p className="mt-1 text-sm text-muted-foreground">
                Follow these steps to trigger your first security scan.
              </p>
            </div>

            <div className="mx-auto mt-8 max-w-lg space-y-4">
              <div className="flex items-start gap-4 rounded-lg border border-border/60 bg-background p-4">
                <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-foreground text-xs font-bold text-background">1</div>
                <div>
                  <p className="text-sm font-medium text-foreground">Install the Polaris GitHub App</p>
                  <p className="mt-0.5 text-xs text-muted-foreground">Grant Polaris access to the repos you want scanned.</p>
                  <a
                    href="https://github.com/apps/iac-scanner-dev/installations/new"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="mt-2 inline-flex items-center gap-1 text-xs font-medium text-foreground underline underline-offset-2 hover:no-underline"
                  >
                    Install on GitHub <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
              </div>

              <div className="flex items-start gap-4 rounded-lg border border-border/60 bg-background p-4">
                <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-foreground text-xs font-bold text-background">2</div>
                <div>
                  <p className="text-sm font-medium text-foreground">Open a Pull Request</p>
                  <p className="mt-0.5 text-xs text-muted-foreground">Push infrastructure code (Terraform, Kubernetes, Dockerfile, or GitHub Actions) and open a PR.</p>
                </div>
              </div>

              <div className="flex items-start gap-4 rounded-lg border border-border/60 bg-background p-4">
                <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-foreground text-xs font-bold text-background">3</div>
                <div>
                  <p className="text-sm font-medium text-foreground">Polaris scans automatically</p>
                  <p className="mt-0.5 text-xs text-muted-foreground">Gemini analyzes your code, posts inline findings on the PR, and results appear here.</p>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="divide-y divide-border/60">
            {scans.slice(0, 3).map((scan) => (
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
