import { ArrowUpRight } from "lucide-react"

const integrations = Array.from({ length: 15 }, (_, i) => `Int ${i + 1}`)

export function IntegrationsGrid() {
  return (
    <section className="relative border-t border-dashed border-border/60">
      {/* Subtle lime glow */}
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse 80% 50% at 50% 0%, oklch(0.92 0.12 105 / 0.25) 0%, transparent 70%)",
        }}
      />

      {/* Subtle grid background */}
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          backgroundImage: `linear-gradient(to right, rgb(0 0 0 / 0.025) 1px, transparent 1px), 
                           linear-gradient(to bottom, rgb(0 0 0 / 0.025) 1px, transparent 1px)`,
          backgroundSize: "48px 48px",
        }}
      />

      <div className="relative mx-auto max-w-6xl px-5 py-16 sm:py-20 lg:px-6 lg:py-24">
        {/* Header */}
        <div className="mx-auto max-w-xl text-center">
          <h2 className="text-[1.75rem] font-medium leading-[1.15] tracking-[-0.01em] text-foreground sm:text-3xl">
            <span className="text-balance">
              We&apos;ve got your back, no matter your stack.
            </span>
          </h2>
          <p className="mt-3 text-[15px] text-muted-foreground">
            Use Polaris to manage configurations in your favorite cloud
            providers, infrastructure tools, frameworks, and more.
          </p>
          <a
            href="#"
            className="mt-4 inline-flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground"
          >
            Explore all integrations <ArrowUpRight className="h-3.5 w-3.5" />
          </a>
        </div>

        {/* Integrations grid */}
        <div className="mx-auto mt-12 max-w-3xl">
          <div className="grid grid-cols-3 overflow-hidden rounded-sm border border-border/70 bg-card sm:grid-cols-5">
            {integrations.map((integration, index) => {
              const isLastRow = index >= 10
              const isLastCol = (index + 1) % 5 === 0
              const isLastColMobile = (index + 1) % 3 === 0

              return (
                <div
                  key={integration}
                  className={`flex aspect-square items-center justify-center p-3 transition-colors hover:bg-muted/40 ${
                    !isLastCol ? "sm:border-r sm:border-border/50" : ""
                  } ${!isLastColMobile ? "border-r border-border/50 sm:border-r-0" : ""} ${
                    !isLastRow ? "border-b border-border/50" : ""
                  } ${index < 12 ? "border-b border-border/50 sm:border-b-0" : ""} ${
                    index < 10 ? "sm:border-b sm:border-border/50" : ""
                  }`}
                >
                  <div className="flex h-8 w-8 items-center justify-center rounded-sm bg-muted/60">
                    <span className="text-[10px] text-muted-foreground/60">
                      {index + 1}
                    </span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </section>
  )
}
