import { NextRequest, NextResponse } from "next/server"

const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:8000"
const API_SECRET = process.env.API_SECRET || ""

export async function GET(request: NextRequest) {
  const owner = request.nextUrl.searchParams.get("owner")
  const url = new URL(`${BACKEND_URL}/scans`)
  if (owner) url.searchParams.set("owner", owner)

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
