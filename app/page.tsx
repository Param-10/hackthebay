import { Navbar } from "@/components/landing/navbar"
import { Hero } from "@/components/landing/hero"
import { FeatureSection } from "@/components/landing/feature-section"
import { Footer } from "@/components/landing/footer"

export default function Home() {
  return (
    <div className="min-h-screen bg-background">
      <Navbar />

      <main>
        <Hero />

        {/* Alternating feature sections */}
        <FeatureSection
          title="PR Security Reviews"
          description="Scan every Pull Request automatically across all your repositories. Detect misconfigurations, policy violations, and compliance gaps before they ever reach production."
          image="/feature-1.png"
        />

        <FeatureSection
          title="AI-Generated Fixes"
          description="Stop manually patching vulnerabilities. Gemini 3 Flash reasons through your code, writes the exact corrected IaC, and stages it for one-click commit approval."
          image="/feature-2.png"
          reversed
        />

        <FeatureSection
          title="One-Click Auto-Fix"
          description="Approve Gemini's suggested fix from your dashboard. Polaris commits directly to your PR branch with a full audit trail — no copy-paste, no context switching."
          image="/feature-3.png"
        />

      </main>

      <Footer />
    </div>
  )
}
