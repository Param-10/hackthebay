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
        </div>

        {/* How Polaris works flow */}
        <div className="mt-12 sm:mt-14">
          <HeroFlow />
        </div>
      </div>
    </section>
  )
}
