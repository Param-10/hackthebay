const logos = [
  "cid",
  "MarshMcLennan",
  "NVIDIA",
  "HeyGen",
  "UPS",
  "Fortescue",
  "Health",
  "SolarWinds",
  "Writer",
]

export function LogoStrip() {
  return (
    <section className="border-y border-dashed border-border/60 bg-background py-6">
      <div className="mx-auto max-w-6xl px-5 lg:px-6">
        <div className="flex flex-wrap items-center justify-center gap-x-8 gap-y-4 sm:gap-x-12">
          {logos.map((logo) => (
            <div
              key={logo}
              className="flex h-6 items-center justify-center text-xs font-medium tracking-wide text-muted-foreground/70"
            >
              {logo}
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
