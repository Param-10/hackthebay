import { Button } from "@/components/ui/button"

const stats = [
  {
    value: "3,000+",
    label: "Community Members",
    cta: "Join Slack",
  },
  {
    value: "12,000+",
    label: "Organizations on Polaris",
    cta: "Get Started",
  },
  {
    value: "99.99%",
    label: "Uptime Guarantee",
    cta: "Learn more",
  },
]

export function StatsStrip() {
  return (
    <section className="relative border-t border-dashed border-border/60">
      {/* Subtle lime glow */}
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse 80% 60% at 50% 100%, oklch(0.92 0.12 105 / 0.18) 0%, transparent 70%)",
        }}
      />

      <div className="relative mx-auto max-w-6xl px-5 py-12 sm:py-14 lg:px-6 lg:py-16">
        <div className="overflow-hidden rounded-sm border border-border/70 bg-card">
          <div className="grid divide-y divide-border/50 sm:grid-cols-3 sm:divide-x sm:divide-y-0">
            {stats.map((stat) => (
              <div
                key={stat.label}
                className="px-6 py-8 text-center sm:px-8 sm:py-10"
              >
                <div className="text-3xl font-medium tracking-tight text-foreground sm:text-4xl">
                  {stat.value}
                </div>
                <div className="mt-1.5 text-sm text-muted-foreground">
                  {stat.label}
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  className="mt-5 h-8 px-4 text-xs"
                >
                  {stat.cta}
                </Button>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}
