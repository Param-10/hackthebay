"use client"

import { useRef, useState } from "react"
import Image from "next/image"
import { cn } from "@/lib/utils"

interface FeatureSectionProps {
  title: string
  description: string
  image?: string
  reversed?: boolean
}

export function FeatureSection({
  title,
  description,
  image,
  reversed = false,
}: FeatureSectionProps) {
  const cardRef = useRef<HTMLDivElement>(null)
  const [transform, setTransform] = useState("")
  const [glare, setGlare] = useState({ x: 50, y: 50, opacity: 0 })

  function handleMouseMove(e: React.MouseEvent<HTMLDivElement>) {
    const card = cardRef.current
    if (!card) return
    const rect = card.getBoundingClientRect()
    const x = (e.clientX - rect.left) / rect.width
    const y = (e.clientY - rect.top) / rect.height
    const rotateX = (y - 0.5) * -12
    const rotateY = (x - 0.5) * 12
    setTransform(`perspective(800px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) scale3d(1.02, 1.02, 1.02)`)
    setGlare({ x: x * 100, y: y * 100, opacity: 0.15 })
  }

  function handleMouseLeave() {
    setTransform("")
    setGlare({ x: 50, y: 50, opacity: 0 })
  }

  return (
    <section className="relative border-t border-dashed border-border/60">
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          backgroundImage: `linear-gradient(to right, rgb(0 0 0 / 0.025) 1px, transparent 1px), 
                           linear-gradient(to bottom, rgb(0 0 0 / 0.025) 1px, transparent 1px)`,
          backgroundSize: "48px 48px",
        }}
      />

      <div className="relative mx-auto max-w-7xl px-5 py-20 sm:py-24 lg:px-8 lg:py-28">
        <div
          className={cn(
            "grid items-center gap-12 lg:grid-cols-2 lg:gap-16",
            reversed && "lg:[&>*:first-child]:order-2"
          )}
        >
          {/* Content */}
          <div className="max-w-xl">
            <h2 className="text-3xl font-medium tracking-[-0.015em] text-foreground sm:text-4xl">
              {title}
            </h2>
            <p className="mt-4 text-base leading-relaxed text-muted-foreground sm:text-lg">
              {description}
            </p>
          </div>

          {/* Illustration with 3D tilt */}
          <div className="relative">
            <div className="absolute -left-2 -top-2 h-4 w-4 border-l border-t border-dashed border-muted-foreground/20" />
            <div className="absolute -right-2 -top-2 h-4 w-4 border-r border-t border-dashed border-muted-foreground/20" />
            <div className="absolute -bottom-2 -left-2 h-4 w-4 border-b border-l border-dashed border-muted-foreground/20" />
            <div className="absolute -bottom-2 -right-2 h-4 w-4 border-b border-r border-dashed border-muted-foreground/20" />

            <div
              ref={cardRef}
              onMouseMove={handleMouseMove}
              onMouseLeave={handleMouseLeave}
              className="aspect-[4/3] w-full overflow-hidden rounded-md border border-border/70 bg-card shadow-sm transition-shadow duration-300 ease-out will-change-transform hover:shadow-xl hover:shadow-black/10"
              style={{
                transform: transform || "perspective(800px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)",
                transition: transform ? "transform 0.1s ease-out, box-shadow 0.3s ease-out" : "transform 0.5s ease-out, box-shadow 0.3s ease-out",
              }}
            >
              {/* Glare overlay */}
              <div
                className="pointer-events-none absolute inset-0 z-10 rounded-md"
                style={{
                  background: `radial-gradient(circle at ${glare.x}% ${glare.y}%, rgba(255,255,255,${glare.opacity}) 0%, transparent 60%)`,
                  transition: glare.opacity ? "opacity 0.1s ease-out" : "opacity 0.5s ease-out",
                }}
              />
              {image ? (
                <Image
                  src={image}
                  alt={title}
                  width={1024}
                  height={768}
                  className="h-full w-full object-cover"
                />
              ) : (
                <div className="flex h-full items-center justify-center">
                  <span className="text-xs text-muted-foreground/40">Illustration</span>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
