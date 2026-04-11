import Link from "next/link"
import Image from "next/image"
import { Github } from "lucide-react"

export function Footer() {
  return (
    <footer className="border-t border-border bg-foreground text-background">
      <div className="mx-auto max-w-6xl px-5 py-10 lg:px-6 lg:py-12">
        <div className="flex flex-col items-center gap-5 text-center">
          <Link href="/" className="flex items-center gap-2">
            <Image
              src="/polaris-icon.png"
              alt="Polaris"
              width={24}
              height={24}
              className="h-6 w-6 invert"
            />
            <span className="text-[15px] font-semibold">Polaris</span>
          </Link>
          <p className="max-w-xs text-sm text-muted/60">
            The AI-powered DevOps agent for engineering teams.
          </p>
          <a
            href="https://github.com/Param-10/hackthebay/tree/main"
            target="_blank"
            rel="noopener noreferrer"
            className="flex h-8 w-8 items-center justify-center rounded-sm bg-muted/15 text-muted/70 transition-colors hover:bg-muted/25 hover:text-background"
            aria-label="GitHub"
          >
            <Github className="h-4 w-4" />
          </a>
        </div>

        <div className="mt-8 border-t border-muted/15 pt-5">
          <p className="text-center text-xs text-muted/50">
            &copy; {new Date().getFullYear()} Polaris. All rights reserved.
          </p>
        </div>
      </div>
    </footer>
  )
}
