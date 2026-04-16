import { NextRequest, NextResponse } from "next/server"
import { getServerSession } from "next-auth"
import { authOptions } from "@/lib/auth"

const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:8000"
const API_SECRET = process.env.API_SECRET || ""

function backendHeaders(): Record<string, string> {
  const h: Record<string, string> = { "Content-Type": "application/json" }
  if (API_SECRET) h["X-API-Secret"] = API_SECRET
  return h
}

function extractOwner(repoFullName?: string): string | null {
  if (!repoFullName || !repoFullName.includes("/")) return null
  return repoFullName.split("/", 1)[0] ?? null
}

async function authorizeScanAccess(scanId: string, login: string): Promise<NextResponse | null> {
  try {
    const metaRes = await fetch(`${BACKEND_URL}/scans/${scanId}/meta`, {
      headers: backendHeaders(),
      cache: "no-store",
    })

    if (metaRes.status === 404) {
      return NextResponse.json({ error: "Scan not found" }, { status: 404 })
    }
    if (!metaRes.ok) {
      return NextResponse.json({ error: "Backend unavailable" }, { status: 502 })
    }

    const meta = (await metaRes.json()) as { repo_full_name?: string }
    const scanOwner = extractOwner(meta.repo_full_name)
    if (!scanOwner || scanOwner.toLowerCase() !== login.toLowerCase()) {
      return NextResponse.json({ error: "Forbidden" }, { status: 403 })
    }
    return null
  } catch {
    return NextResponse.json({ error: "Backend unavailable" }, { status: 502 })
  }
}

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const session = await getServerSession(authOptions)
  const login = session?.user?.login
  if (!login) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  const { path } = await params
  const scanId = path[0]
  if (!scanId || !/^\d+$/.test(scanId)) {
    return NextResponse.json({ error: "Invalid scan ID" }, { status: 400 })
  }

  const accessError = await authorizeScanAccess(scanId, login)
  if (accessError) return accessError

  const backendPath = path.join("/")
  const url = `${BACKEND_URL}/scans/${backendPath}`

  try {
    const res = await fetch(url, {
      headers: backendHeaders(),
      cache: "no-store",
    })
    const data = await res.json()
    return NextResponse.json(data, { status: res.status })
  } catch {
    return NextResponse.json(
      { error: "Backend unavailable" },
      { status: 502 }
    )
  }
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const session = await getServerSession(authOptions)
  const login = session?.user?.login
  if (!login) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  const { path } = await params
  const scanId = path[0]
  if (!scanId || !/^\d+$/.test(scanId)) {
    return NextResponse.json({ error: "Invalid scan ID" }, { status: 400 })
  }

  const accessError = await authorizeScanAccess(scanId, login)
  if (accessError) return accessError

  const backendPath = path.join("/")
  const url = `${BACKEND_URL}/scans/${backendPath}`

  try {
    const body = await request.text()
    const res = await fetch(url, {
      method: "POST",
      headers: backendHeaders(),
      body: body || undefined,
    })
    const data = await res.json()
    return NextResponse.json(data, { status: res.status })
  } catch {
    return NextResponse.json(
      { error: "Backend unavailable" },
      { status: 502 }
    )
  }
}
