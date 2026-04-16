"use client"

import { useEffect, useState } from "react"

export function useNow(intervalMs: number = 30_000): number {
  const [now, setNow] = useState(() => Date.now())

  useEffect(() => {
    const timer = window.setInterval(() => {
      setNow(Date.now())
    }, intervalMs)

    return () => window.clearInterval(timer)
  }, [intervalMs])

  return now
}
