"use client"

import { useEffect, useRef, useCallback } from "react"

const steps = [
  {
    name: "Open a PR",
    desc: "Push your infra code as normal on GitHub.",
    icon: (
      <svg className="ico" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#bbb" strokeWidth="1.6">
        <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" />
      </svg>
    ),
  },
  {
    name: "Gemini scans",
    desc: "Findings posted inline on your PR in under 4s.",
    icon: (
      <svg className="ico" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#bbb" strokeWidth="1.6">
        <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
      </svg>
    ),
  },
  {
    name: "Approve fix",
    desc: "Review and approve Gemini's fix in one click.",
    icon: (
      <svg className="ico" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#bbb" strokeWidth="1.6">
        <polyline points="9,11 12,14 22,4" /><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11" />
      </svg>
    ),
  },
  {
    name: "Merge clean",
    desc: "Secure, compliant and ready to ship.",
    icon: (
      <svg className="ico" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#bbb" strokeWidth="1.6">
        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22,4 12,14.01 9,11.01" />
      </svg>
    ),
  },
]

export function HeroFlow() {
  const nodesRef = useRef<(HTMLDivElement | null)[]>([])
  const badgesRef = useRef<(HTMLDivElement | null)[]>([])
  const fillsRef = useRef<(HTMLDivElement | null)[]>([])
  const arrowsRef = useRef<(HTMLDivElement | null)[]>([])
  const timersRef = useRef<ReturnType<typeof setTimeout>[]>([])

  const clearAll = useCallback(() => {
    timersRef.current.forEach(clearTimeout)
    timersRef.current = []
  }, [])

  const setNode = useCallback((i: number, state: string) => {
    const n = nodesRef.current[i]
    const b = badgesRef.current[i]
    if (!n || !b) return
    n.classList.remove("flow-active", "flow-done")
    b.classList.remove("flow-active", "flow-done")
    if (state === "active") { n.classList.add("flow-active"); b.classList.add("flow-active") }
    if (state === "done") { n.classList.add("flow-done"); b.classList.add("flow-done") }
  }, [])

  const setLine = useCallback((i: number, pct: number, on: boolean) => {
    const lf = fillsRef.current[i]
    const la = arrowsRef.current[i]
    if (lf) lf.style.width = pct + "%"
    if (la) { if (on) la.classList.add("lit"); else la.classList.remove("lit") }
  }, [])

  const resetAll = useCallback(() => {
    for (let i = 0; i < 4; i++) setNode(i, "idle")
    for (let i = 0; i < 3; i++) setLine(i, 0, false)
  }, [setNode, setLine])

  const push = useCallback((fn: () => void, ms: number) => {
    const t = setTimeout(fn, ms)
    timersRef.current.push(t)
    return t
  }, [])

  useEffect(() => {
    const delays = [400, 1300, 2200, 3100]
    const lineDur = 650

    function runCycle() {
      clearAll()
      resetAll()
      for (let i = 0; i < 4; i++) {
        ;((idx) => {
          push(() => setNode(idx, "active"), delays[idx])
          if (idx < 3) {
            push(() => {
              setLine(idx, 100, true)
              push(() => setNode(idx, "done"), lineDur)
            }, delays[idx] + 700)
          } else {
            push(() => {
              setNode(3, "done")
              push(runCycle, 1000)
            }, delays[idx] + 700)
          }
        })(i)
      }
    }

    const t = setTimeout(runCycle, 300)
    timersRef.current.push(t)

    return () => clearAll()
  }, [clearAll, resetAll, setNode, setLine, push])

  return (
    <>
      <style>{`
        .flow-active { background: #1a2332 !important; border-color: #1a2332 !important; }
        .flow-done { background: #1a2332 !important; border-color: #1a2332 !important; }
        .flow-active .ico, .flow-done .ico { stroke: #fff !important; }
        .flow-active.flow-badge { background: #1a2332 !important; color: #fff !important; border-color: #1a2332 !important; }
        .flow-done.flow-badge { background: #1a2332 !important; color: #fff !important; border-color: #1a2332 !important; }
        .conn-fill { transition: width 0.65s cubic-bezier(.4,0,.2,1); }
        .conn-arrow { transition: border-left-color 0.2s ease; }
        .conn-arrow.lit { border-left-color: #1a2332 !important; }
        .flow-node { transition: background 0.35s ease, border-color 0.35s ease; }
        .flow-badge { transition: all 0.3s ease; }
      `}</style>
      <div className="rounded-[18px] border border-[#e0e0dc] bg-[#f2f2f0] p-6 sm:p-8 relative min-h-[400px] sm:min-h-[500px] flex flex-col justify-center">
        {/* Dashed corners */}
        <div className="absolute left-[10px] top-[10px] h-4 w-4 border-l-[1.5px] border-t-[1.5px] border-dashed border-[#b0b0a8]" />
        <div className="absolute right-[10px] top-[10px] h-4 w-4 border-r-[1.5px] border-t-[1.5px] border-dashed border-[#b0b0a8]" />
        <div className="absolute bottom-[10px] left-[10px] h-4 w-4 border-b-[1.5px] border-l-[1.5px] border-dashed border-[#b0b0a8]" />
        <div className="absolute bottom-[10px] right-[10px] h-4 w-4 border-b-[1.5px] border-r-[1.5px] border-dashed border-[#b0b0a8]" />

        <div className="flex-1 rounded-[14px] border border-[#e0e0dc] bg-white px-6 py-10 sm:px-14 sm:py-12 flex flex-col justify-center">
          {/* Header */}
          <div className="text-center mb-10 sm:mb-14">
            <h3 className="text-lg sm:text-[22px] font-semibold text-[#1a2332] mb-2 tracking-[-0.3px]">
              How Polaris works
            </h3>
            <p className="text-[13px] text-[#aaa] tracking-[0.1px]">
              From open to secure in under 60 seconds — zero manual security review needed.
            </p>
          </div>

          {/* Steps row */}
          <div className="flex items-start justify-center">
            {steps.map((step, i) => (
              <div key={step.name} className="contents">
                {/* Step */}
                <div className="flex flex-col items-center w-[120px] sm:w-[180px] shrink-0">
                  <div
                    ref={(el) => { nodesRef.current[i] = el }}
                    className="flow-node w-12 h-12 sm:w-[60px] sm:h-[60px] rounded-full bg-white border-[1.5px] border-[#d0d0cc] flex items-center justify-center mb-4 sm:mb-5 relative"
                  >
                    <div
                      ref={(el) => { badgesRef.current[i] = el }}
                      className="flow-badge absolute -top-1 -right-1 w-[18px] h-[18px] sm:w-5 sm:h-5 rounded-full bg-[#f2f2f0] border border-[#d0d0cc] text-[8px] sm:text-[9px] font-bold text-[#aaa] flex items-center justify-center"
                    >
                      {i + 1}
                    </div>
                    {step.icon}
                  </div>
                  <div className="text-xs sm:text-sm font-semibold text-[#1a2332] text-center mb-1 sm:mb-2">
                    {step.name}
                  </div>
                  <div className="text-[10px] sm:text-xs text-[#aaa] text-center leading-[1.55] max-w-[100px] sm:max-w-[140px]">
                    {step.desc}
                  </div>
                </div>

                {/* Connector */}
                {i < 3 && (
                  <div className="flex-1 mt-6 sm:mt-[30px] relative h-[1.5px] bg-[#e4e4e0]">
                    <div
                      ref={(el) => { fillsRef.current[i] = el }}
                      className="conn-fill absolute top-0 left-0 h-full w-0 bg-[#1a2332]"
                    />
                    <div
                      ref={(el) => { arrowsRef.current[i] = el }}
                      className="conn-arrow absolute -right-[6px] -top-[5px] w-0 h-0"
                      style={{
                        borderTop: "5.5px solid transparent",
                        borderBottom: "5.5px solid transparent",
                        borderLeft: "7px solid #e4e4e0",
                      }}
                    />
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </>
  )
}
