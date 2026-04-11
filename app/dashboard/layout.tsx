"use client"

import { useSession, signOut } from "next-auth/react"
import { useRouter, usePathname } from "next/navigation"
import { useEffect } from "react"
import Image from "next/image"
import Link from "next/link"
import { LayoutDashboard, Search, LogOut, Shield } from "lucide-react"

const navItems = [
  { label: "Overview", href: "/dashboard", icon: LayoutDashboard, exact: true },
  { label: "Scans", href: "/dashboard/scans", icon: Search, exact: false },
]

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const { data: session, status } = useSession()
  const router = useRouter()
  const pathname = usePathname()

  useEffect(() => {
    if (status === "unauthenticated") {
      router.push("/login")
    }
  }, [status, router])

  if (status === "loading") {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="flex items-center gap-3 text-muted-foreground">
          <div className="h-5 w-5 animate-spin rounded-full border-2 border-current border-t-transparent" />
          <span className="text-sm">Loading...</span>
        </div>
      </div>
    )
  }

  if (!session) return null

  return (
    <div className="flex min-h-screen bg-background">
      {/* Sidebar */}
      <aside className="sticky top-0 flex h-screen w-60 shrink-0 flex-col border-r border-border/60 bg-card">
        {/* Logo */}
        <div className="flex h-16 items-center gap-2.5 border-b border-border/60 px-5">
          <Link href="/" className="flex items-center gap-2.5">
            <Image
              src="/polaris-icon.png"
              alt="Polaris"
              width={28}
              height={28}
              className="h-7 w-7"
            />
            <span className="text-base font-semibold tracking-tight text-foreground">
              Polaris
            </span>
          </Link>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-4">
          <div className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon
              const isActive = item.exact
                ? pathname === item.href
                : pathname.startsWith(item.href)
              return (
                <Link
                  key={item.label}
                  href={item.href}
                  className={`flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors ${
                    isActive
                      ? "bg-muted/70 font-medium text-foreground"
                      : "text-muted-foreground hover:bg-muted/50 hover:text-foreground"
                  }`}
                >
                  <Icon className="h-4 w-4" />
                  {item.label}
                </Link>
              )
            })}
          </div>
        </nav>

        {/* User */}
        <div className="border-t border-border/60 p-4">
          <div className="flex items-center gap-3">
            {session.user?.image ? (
              <img
                src={session.user.image}
                alt={session.user.name || ""}
                className="h-8 w-8 rounded-full"
              />
            ) : (
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-muted">
                <Shield className="h-4 w-4 text-muted-foreground" />
              </div>
            )}
            <div className="flex-1 overflow-hidden">
              <p className="truncate text-sm font-medium text-foreground">
                {session.user?.name || "User"}
              </p>
              <p className="truncate text-xs text-muted-foreground">
                {session.user?.email || ""}
              </p>
            </div>
          </div>
          <button
            onClick={() => signOut({ callbackUrl: "/" })}
            className="mt-3 flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm text-muted-foreground transition-colors hover:bg-muted/50 hover:text-foreground"
          >
            <LogOut className="h-4 w-4" />
            Sign out
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main
        className="relative flex-1 overflow-auto"
        style={{
          backgroundImage: `linear-gradient(to right, rgb(0 0 0 / 0.04) 1px, transparent 1px), 
                           linear-gradient(to bottom, rgb(0 0 0 / 0.04) 1px, transparent 1px)`,
          backgroundSize: "24px 24px",
        }}
      >
        <div className="mx-auto max-w-5xl px-6 py-8 lg:px-8">
          {children}
        </div>
      </main>
    </div>
  )
}
