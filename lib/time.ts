const RELATIVE_TIME_FORMATTER = new Intl.RelativeTimeFormat(undefined, {
  numeric: "auto",
})

const RELATIVE_UNITS: Array<[Intl.RelativeTimeFormatUnit, number]> = [
  ["year", 1000 * 60 * 60 * 24 * 365],
  ["month", 1000 * 60 * 60 * 24 * 30],
  ["week", 1000 * 60 * 60 * 24 * 7],
  ["day", 1000 * 60 * 60 * 24],
  ["hour", 1000 * 60 * 60],
  ["minute", 1000 * 60],
  ["second", 1000],
]

function parseTimestamp(value: string | number | Date): Date {
  if (value instanceof Date) return value

  if (typeof value === "string") {
    const hasTimezone = /(?:Z|[+-]\d{2}:\d{2})$/i.test(value)
    const normalized = hasTimezone ? value : `${value}Z`
    return new Date(normalized)
  }

  return new Date(value)
}

export function formatLocalDateTime(value: string | number | Date): string {
  const date = parseTimestamp(value)
  if (Number.isNaN(date.getTime())) return "Invalid time"

  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date)
}

export function formatRelativeTime(
  value: string | number | Date,
  nowMs: number = Date.now()
): string {
  const date = parseTimestamp(value)
  if (Number.isNaN(date.getTime())) return "unknown time"

  const delta = date.getTime() - nowMs
  if (Math.abs(delta) < 15_000) return "just now"

  for (const [unit, unitMs] of RELATIVE_UNITS) {
    if (Math.abs(delta) >= unitMs || unit === "second") {
      return RELATIVE_TIME_FORMATTER.format(Math.round(delta / unitMs), unit)
    }
  }

  return "just now"
}

export function getUserTimeZone(): string {
  return Intl.DateTimeFormat().resolvedOptions().timeZone || "local time"
}
