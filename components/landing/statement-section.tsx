import { ArrowUpRight } from "lucide-react"

const features = [
  {
    title: "Management Across Infrastructure",
    description:
      "Manage configurations across all of your infrastructure — from containers and orchestrators to CI/CD pipelines and local development.",
  },
  {
    title: "Dynamic Credentials & Rotation",
    description:
      "Eliminate long-lasting credentials to reduce risk of breach. Generate credentials dynamically on-demand, unique to every client.",
  },
  {
    title: "Intelligent Monitoring",
    description:
      "Govern how services access tools and external systems. Centralize authentication, policy enforcement, and visibility.",
  },
]

export function StatementSection() {
  return (
    <section className="relative border-t border-dashed border-border/60">
      {/* Subtle grid background */}
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          backgroundImage: `linear-gradient(to right, rgb(0 0 0 / 0.025) 1px, transparent 1px), 
                           linear-gradient(to bottom, rgb(0 0 0 / 0.025) 1px, transparent 1px)`,
          backgroundSize: "48px 48px",
        }}
      />

      {/* Vertical dashed line accent */}
      <div className="pointer-events-none absolute left-1/2 top-0 h-8 w-px -translate-x-1/2 border-l border-dashed border-border/60" />

      <div className="relative mx-auto max-w-6xl px-5 py-16 sm:py-20 lg:px-6 lg:py-24">
        {/* Centered statement */}
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-[1.75rem] font-medium leading-[1.15] tracking-[-0.01em] text-foreground sm:text-3xl lg:text-4xl">
            <span className="text-balance">
              Everyone needs security. We protect over 500 million assets every
              day.
            </span>
          </h2>
          <a
            href="#"
            className="mt-4 inline-flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground"
          >
            Explore product features <ArrowUpRight className="h-3.5 w-3.5" />
          </a>
        </div>

        {/* Feature cards */}
        <div className="mt-14 grid gap-5 sm:grid-cols-2 lg:grid-cols-3 lg:gap-6">
          {features.map((feature) => (
            <div
              key={feature.title}
              className="group rounded-sm border border-border/70 bg-card p-5 transition-colors hover:border-muted-foreground/25"
            >
              {/* Icon placeholder */}
              <div className="mb-5 flex h-16 w-full items-center justify-center rounded-sm border border-dashed border-border/60 bg-muted/30">
                <div className="flex items-center gap-2">
                  <div className="h-6 w-6 rounded-full border border-border/60 bg-background" />
                  <div className="h-5 w-5 rounded-sm border border-border/60 bg-background" />
                </div>
              </div>
              <h3 className="text-[15px] font-medium text-foreground">
                {feature.title}
              </h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">
                {feature.description}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
