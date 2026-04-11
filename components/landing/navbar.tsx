import Link from "next/link"
import Image from "next/image"
import { Button } from "@/components/ui/button"

export function Navbar() {

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

        <Link href="/login">
          <Button size="sm" className="h-9 px-5 text-sm">
            Sign Up
          </Button>
        </Link>
      </nav>

    </header>
  )
}
