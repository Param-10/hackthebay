import { Button } from "@/components/ui/button"
import { ArrowRight } from "lucide-react"

export function FinalCTA() {
  return (
    <section className="relative border-t border-dashed border-border/60">
      <div className="mx-auto max-w-6xl px-5 py-12 sm:py-14 lg:px-6 lg:py-16">
        {/* CTA Banner */}
        <div className="overflow-hidden rounded-sm bg-accent px-6 py-12 text-center sm:px-12 sm:py-14">
          <h2 className="text-2xl font-medium tracking-[-0.01em] text-accent-foreground sm:text-3xl">
            Starting with Polaris is simple, fast, and free.
          </h2>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
            <Button className="h-10 gap-2 px-5 text-sm">
              Get Started <ArrowRight className="h-3.5 w-3.5" />
            </Button>
            <Button
              variant="outline"
              className="h-10 border-accent-foreground/20 bg-transparent px-5 text-sm text-accent-foreground hover:bg-accent-foreground/10 hover:text-accent-foreground"
            >
              Get a demo
            </Button>
          </div>
        </div>
      </div>
    </section>
  )
}
