const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

export function relativeTime(value: string | Date, now = new Date()): string {
  const date = typeof value === "string" ? new Date(value) : value;
  const seconds = Math.round((date.getTime() - now.getTime()) / 1000);
  const units = [
    ["year", 31_536_000],
    ["month", 2_592_000],
    ["day", 86_400],
    ["hour", 3_600],
    ["minute", 60],
  ] as const;
  for (const [unit, size] of units) {
    if (Math.abs(seconds) >= size) return rtf.format(Math.round(seconds / size), unit);
  }
  return rtf.format(seconds, "second");
}

export function formatDate(value: string | Date): string {
  const date = typeof value === "string" ? new Date(value) : value;
  return Number.isNaN(date.getTime())
    ? "Unknown"
    : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

export function formatAge(days: number | null): string {
  if (days === null) return "Unknown";
  if (days < 30) return `${days} ${days === 1 ? "day" : "days"} old`;
  if (days < 365) return `${Math.floor(days / 30)} months old`;
  const years = Math.floor(days / 365);
  return `${years} ${years === 1 ? "year" : "years"} old`;
}
