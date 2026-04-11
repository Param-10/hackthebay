"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"
import Image from "next/image"
import Link from "next/link"
import { signIn, useSession } from "next-auth/react"
import { Github } from "lucide-react"
import { Button } from "@/components/ui/button"

export default function LoginPage() {
  const { data: session, status } = useSession()
  const router = useRouter()

  useEffect(() => {
    if (status === "authenticated") {
      router.push("/dashboard")
    }
  }, [status, router])

  if (status === "loading" || session) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="flex items-center gap-3 text-muted-foreground">
          <div className="h-5 w-5 animate-spin rounded-full border-2 border-current border-t-transparent" />
          <span className="text-sm">Loading...</span>
        </div>
      </div>
    )
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center bg-background">
      {/* Grid background */}
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          backgroundImage: `linear-gradient(to right, rgb(0 0 0 / 0.04) 1px, transparent 1px), 
                           linear-gradient(to bottom, rgb(0 0 0 / 0.04) 1px, transparent 1px)`,
          backgroundSize: "48px 48px",
        }}
      />

      <div className="relative z-10 w-full max-w-sm px-5">
        <div className="flex flex-col items-center rounded-xl border border-border/60 bg-white/95 px-8 py-10 shadow-sm backdrop-blur-sm">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-2.5">
            <Image
              src="/polaris-icon.png"
              alt="Polaris"
              width={44}
              height={44}
              className="h-11 w-11"
            />
            <span className="text-2xl font-semibold tracking-tight text-foreground">
              Polaris
            </span>
          </Link>

          {/* Heading */}
          <h1 className="mt-8 text-center text-xl font-medium tracking-tight text-foreground">
            Sign in to your account
          </h1>
          <p className="mt-2 text-center text-sm text-muted-foreground">
            Connect your GitHub to start scanning PRs and fixing vulnerabilities.
          </p>

          {/* Sign in button */}
          <Button
            onClick={() => signIn("github", { callbackUrl: "/dashboard" })}
            className="mt-8 flex h-11 w-full items-center justify-center gap-2.5 text-sm"
          >
            <Github className="h-5 w-5" />
            Continue with GitHub
          </Button>

          {/* Divider */}
          <div className="mt-8 flex w-full items-center gap-3">
            <div className="h-px flex-1 bg-border" />
            <span className="text-xs text-muted-foreground">or</span>
            <div className="h-px flex-1 bg-border" />
          </div>

          {/* Back to home */}
          <Link
            href="/"
            className="mt-6 text-sm text-muted-foreground transition-colors hover:text-foreground"
          >
            Back to homepage
          </Link>
        </div>

        {/* Footer */}
        <p className="mt-12 text-center text-xs text-muted-foreground/60">
          By signing in, you agree to our Terms of Service and Privacy Policy.
        </p>
      </div>
    </div>
  )
}
