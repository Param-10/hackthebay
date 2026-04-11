import Link from "next/link"
import { Button } from "@/components/ui/button"
import { ArrowRight } from "lucide-react"
import { HeroFlow } from "./hero-flow"

export function Hero() {
  return (
    <section className="relative overflow-hidden">
      {/* Subtle grid background */}
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          backgroundImage: `linear-gradient(to right, rgb(0 0 0 / 0.04) 1px, transparent 1px), 
                           linear-gradient(to bottom, rgb(0 0 0 / 0.04) 1px, transparent 1px)`,
          backgroundSize: "48px 48px",
        }}
      />

      <div className="relative mx-auto max-w-6xl px-5 pb-16 pt-16 sm:pt-20 lg:px-6 lg:pb-20 lg:pt-24">
        <div className="max-w-2xl">
          <h1 className="text-[2.5rem] font-medium leading-[1.1] tracking-[-0.02em] text-foreground sm:text-5xl lg:text-[3.25rem]">
            <span className="text-balance">
              Scan, Fix &amp; Merge Secure Code on <span className="text-muted-foreground/60">Autopilot.</span>
            </span>
          </h1>
          <p className="mt-5 max-w-xl text-base leading-relaxed text-muted-foreground sm:text-[17px]">
            The AI-powered DevOps agent for engineering teams. Detect vulnerabilities, generate fixes, and automate PR reviews with Gemini precision.
          </p>
          <div className="mt-7 flex flex-wrap items-center gap-3">
            <Link href="/login">
              <Button className="h-10 gap-2 px-5 text-sm">
                Connect to GitHub <ArrowRight className="h-3.5 w-3.5" />
              </Button>
            </Link>
          </div>
        </div>

        {/* How Polaris works flow */}
        <div className="mt-14 sm:mt-16">
          <HeroFlow />
        </div>
      </div>
    </section>
  )
}
