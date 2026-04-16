import { NextRequest, NextResponse } from "next/server"
import { getServerSession } from "next-auth"
import { authOptions } from "@/lib/auth"

const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:8000"
const API_SECRET = process.env.API_SECRET || ""

export async function GET(_request: NextRequest) {
  const session = await getServerSession(authOptions)
  const login = session?.user?.login
  if (!login) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  const url = new URL(`${BACKEND_URL}/scans`)
  url.searchParams.set("owner", login)

  try {
    const res = await fetch(url.toString(), {
      headers: {
        "Content-Type": "application/json",
        ...(API_SECRET && { "X-API-Secret": API_SECRET }),
      },
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
