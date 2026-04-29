import { NextRequest, NextResponse } from "next/server"
import { getToken } from "next-auth/jwt"

interface GitHubInstallation {
  id: number
  app_id: number
  account: {
    login: string
    avatar_url: string
    type: string
    html_url?: string
  } | null
}

interface InstallationsResponse {
  total_count: number
  installations: GitHubInstallation[]
}

const POLARIS_APP_ID = process.env.GITHUB_APP_ID
  ? Number(process.env.GITHUB_APP_ID)
  : null

export async function GET(request: NextRequest) {
  const token = await getToken({ req: request })
  const accessToken = token?.accessToken
  if (!accessToken) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  try {
    const res = await fetch(
      "https://api.github.com/user/installations?per_page=100",
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
        },
        cache: "no-store",
      }
    )

    if (!res.ok) {
      return NextResponse.json(
        { error: "Failed to fetch installations", status: res.status },
        { status: res.status }
      )
    }

    const data = (await res.json()) as InstallationsResponse
    const installations = (data.installations || [])
      .filter((i) => POLARIS_APP_ID == null || i.app_id === POLARIS_APP_ID)
      .map((i) => ({
        id: i.id,
        account: i.account
          ? {
              login: i.account.login,
              avatar_url: i.account.avatar_url,
              type: i.account.type,
              html_url: i.account.html_url,
            }
          : null,
      }))

    return NextResponse.json({ installations })
  } catch {
    return NextResponse.json(
      { error: "GitHub API unavailable" },
      { status: 502 }
    )
  }
}
