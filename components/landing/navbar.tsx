"use client"

import Link from "next/link"
import Image from "next/image"
import { useSession } from "next-auth/react"
import { Button } from "@/components/ui/button"

export function Navbar() {
  const { data: session } = useSession()

  return (
    <header className="sticky top-0 z-50 w-full border-b border-border/60 bg-background/98 backdrop-blur-sm">
      <nav className="mx-auto flex h-16 max-w-6xl items-center justify-between px-5 lg:px-6">
        <div className="flex items-center gap-3">
          <Link href="/" className="flex items-center gap-2.5">
            <Image
              src="/polaris-icon.png"
              alt="Polaris"
              width={36}
              height={36}
              className="h-9 w-9"
            />
            <span className="text-lg font-semibold tracking-tight text-foreground">
              Polaris
            </span>
          </Link>
        </div>

        {session?.user ? (
          <Link href="/dashboard" className="flex items-center gap-2.5">
            <span className="text-sm text-muted-foreground transition-colors hover:text-foreground">
              Dashboard
            </span>
            {session.user.image ? (
              <img
                src={session.user.image}
                alt={session.user.name || ""}
                className="h-8 w-8 rounded-full border border-border/60"
              />
            ) : (
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-muted text-xs font-medium text-muted-foreground">
                {session.user.name?.charAt(0) || "U"}
              </div>
            )}
          </Link>
        ) : (
          <Link href="/login">
            <Button size="sm" className="h-9 px-5 text-sm">
              Sign Up
            </Button>
          </Link>
        )}
      </nav>
    </header>
  )
}
