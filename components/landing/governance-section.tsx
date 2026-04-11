import { ArrowUpRight, FileText, Users, ShieldCheck } from "lucide-react"

const features = [
  {
    icon: FileText,
    title: "Audit Logs",
    description:
      "Track everything. Be aware of every action happening to your configurations and sensitive data.",
  },
  {
    icon: Users,
    title: "Role-Based Access",
    description:
      "Define granular permissions and access controls for teams, environments, and individual resources.",
  },
  {
    icon: ShieldCheck,
    title: "Policy Enforcement",
    description:
      "Set up automated policy checks and enforcement rules to maintain security standards.",
  },
]

export function GovernanceSection() {
  return (
    <section className="relative border-t border-dashed border-border/60">
      {/* Subtle dotted background */}
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          backgroundImage: `radial-gradient(circle, rgb(0 0 0 / 0.06) 1px, transparent 1px)`,
          backgroundSize: "20px 20px",
        }}
      />

      {/* Vertical dashed line accents */}
      <div className="pointer-events-none absolute left-1/2 top-0 h-6 w-px -translate-x-1/2 border-l border-dashed border-border/60" />

      <div className="relative mx-auto max-w-6xl px-5 py-16 sm:py-20 lg:px-6 lg:py-24">
        {/* Header */}
        <div className="mx-auto max-w-xl text-center">
          <h2 className="text-[1.75rem] font-medium leading-[1.15] tracking-[-0.01em] text-foreground sm:text-3xl">
            Enterprise-level governance.
          </h2>
          <p className="mt-3 text-[15px] text-muted-foreground">
            Polaris lets you set up tight authorization policies, and provides
            access control tools to embrace &quot;security shift left&quot;.
          </p>
        </div>

        {/* Features list */}
        <div className="mx-auto mt-12 max-w-2xl space-y-4">
          {features.map((feature) => {
            const Icon = feature.icon
            return (
              <div
                key={feature.title}
                className="group flex items-start gap-4 rounded-sm border border-border/70 bg-card p-4 transition-colors hover:border-muted-foreground/25 sm:p-5"
              >
                {/* Icon */}
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-sm bg-muted/60">
                  <Icon className="h-4 w-4 text-muted-foreground" />
                </div>
                <div className="min-w-0 flex-1">
                  <h3 className="text-[15px] font-medium text-foreground">
                    {feature.title}
                  </h3>
                  <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
                    {feature.description}
                  </p>
                  <a
                    href="#"
                    className="mt-2 inline-flex items-center gap-1 text-xs text-muted-foreground transition-colors hover:text-foreground"
                  >
                    Learn more <ArrowUpRight className="h-3 w-3" />
                  </a>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </section>
  )
}
