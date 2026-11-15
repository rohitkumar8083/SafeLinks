import { Bug, CalendarClock, CircleAlert, Fish, Globe, Info, Link2, Lock, OctagonAlert, ShieldAlert, ShieldCheck, ShieldQuestion, ShieldX, Siren, TriangleAlert } from "lucide-react";
import type { CheckCategory, Severity, Verdict } from "../api/types";

export const verdictMeta = {
  likely_safe: { label: "Low risk", tone: "safe", icon: ShieldCheck },
  suspicious: { label: "Suspicious", tone: "caution", icon: ShieldAlert },
  likely_malicious: { label: "High risk", tone: "danger", icon: ShieldX },
  unknown: { label: "Unable to determine", tone: "unknown", icon: ShieldQuestion },
} satisfies Record<Verdict, { label: string; tone: string; icon: typeof ShieldCheck }>;
export const severityMeta = {
  info: { label: "Info", tone: "unknown", icon: Info, rank: 0 },
  low: { label: "Low", tone: "primary", icon: CircleAlert, rank: 1 },
  medium: { label: "Medium", tone: "caution", icon: TriangleAlert, rank: 2 },
  high: { label: "High", tone: "orange", icon: OctagonAlert, rank: 3 },
  critical: { label: "Critical", tone: "danger", icon: Siren, rank: 4 },
} satisfies Record<Severity, { label: string; tone: string; icon: typeof Info; rank: number }>;
export const categoryIcons: Record<CheckCategory, typeof Fish> = { phishing: Fish, malware: Bug, reputation: Globe, domain: CalendarClock, ssl: Lock, url_structure: Link2 };
const labels: Record<string, string> = { has_ip_host: "Uses an IP address as the host", is_https: "Uses HTTPS", is_shortener: "URL shortener", risky_tld: "Risky domain ending", brand_in_subdomain: "Brand name in subdomain", brand_in_path: "Brand name in path", has_at_symbol: "Contains an @ symbol", has_punycode: "Lookalike (punycode) characters", has_custom_port: "Non-standard port", keyword_count_host: "Suspicious words in domain", keyword_count_path: "Suspicious words in path", host_entropy: "Randomness of domain name", path_entropy: "Randomness of path", subdomain_count: "Number of subdomains", url_length: "URL length", suspicious_extension: "Risky file extension" };
export const featureLabel = (id: string) => {
  const human = id.replace(/_/g, " ");
  return labels[id] ?? `${human.charAt(0).toUpperCase()}${human.slice(1)}`;
};
