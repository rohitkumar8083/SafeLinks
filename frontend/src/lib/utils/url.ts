export function normalizeUrl(input: string): string {
  let value = input.trim().replace(/[\u0000-\u001F\u007F-\u009F\u200B-\u200D\uFEFF]/g, "");
  if (value.length > 2048) throw new Error("Link is too long (max 2048 characters)");
  if (!/^[a-zA-Z][a-zA-Z\d+.-]*:\/\//.test(value)) value = `https://${value}`;
  let parsed: URL;
  try { parsed = new URL(value); } catch { throw new Error("That does not look like a valid link"); }
  if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Only http and https links can be scanned");
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(parsed.hostname);
  if ((!parsed.hostname.includes(".") && !ipv4) || !parsed.hostname) throw new Error("That does not look like a valid link");
  return parsed.toString();
}
export function defangUrl(value: string) {
  try {
    const url = new URL(value);
    const protocol = url.protocol === "https:" ? "hxxps:" : "hxxp:";
    return `${protocol}//${url.host.replace(/\./g, "[.]")}${url.pathname}${url.search}${url.hash}`;
  } catch { return value; }
}
export function hostname(value: string) { try { return new URL(value).hostname; } catch { return value; } }
