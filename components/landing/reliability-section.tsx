import { ArrowUpRight, Shield, Cpu, Lock, Cloud } from "lucide-react"

const features = [
  {
    icon: Shield,
    title: "Compliant",
    description:
      "SOC 2, HIPAA, and FIPS 140-3 compliant with continuous penetration testing.",
  },
  {
    icon: Cpu,
    title: "Reliable",
    description:
      "Powering mission-critical infrastructures of all sizes with support SLAs.",
  },
  {
    icon: Lock,
    title: "Secure",
    description:
      "AES-GCM-256 encryption with tight authentication policies enforced.",
  },
  {
    icon: Cloud,
    title: "Self-hostable",
    description:
      "Deploy on your own infrastructure or use Polaris Cloud with zero overhead.",
  },
]

export function ReliabilitySection() {
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

      <div className="relative mx-auto max-w-6xl px-5 py-16 sm:py-20 lg:px-6 lg:py-24">
        {/* Header */}
        <div className="mx-auto max-w-xl text-center">
          <h2 className="text-[1.75rem] font-medium leading-[1.15] tracking-[-0.01em] text-foreground sm:text-3xl">
            Reliability you can count on.
          </h2>
          <p className="mt-3 text-[15px] text-muted-foreground">
            Polaris leads the industry with its reliability and security
            initiatives.
          </p>
        </div>

        {/* Feature columns */}
        <div className="mx-auto mt-12 grid max-w-4xl gap-8 sm:grid-cols-2 lg:grid-cols-4 lg:gap-6">
          {features.map((feature) => {
            const Icon = feature.icon
            return (
              <div key={feature.title} className="text-left">
                <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-sm border border-border/70 bg-card">
                  <Icon className="h-4 w-4 text-muted-foreground" />
                </div>
                <h3 className="text-[15px] font-medium text-foreground">
                  {feature.title}
                </h3>
                <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">
                  {feature.description}
                </p>
                <a
                  href="#"
                  className="mt-3 inline-flex items-center gap-1 text-xs text-muted-foreground transition-colors hover:text-foreground"
                >
                  Learn more <ArrowUpRight className="h-3 w-3" />
                </a>
              </div>
            )
          })}
        </div>
      </div>
    </section>
  )
}
