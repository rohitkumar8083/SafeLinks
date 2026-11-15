import { ApiError } from "./errors";
import type {
  Check,
  CheckCategory,
  CheckId,
  HealthResponse,
  MlFeature,
  ScanApi,
  ScanMode,
  ScanResponse,
  ScanResult,
  Severity,
} from "./types";

type Scenario = "safe" | "phishing" | "unknown" | "failed" | "suspicious";
type StoredScan = {
  scanId: string;
  submittedUrl: string;
  normalizedUrl: string;
  createdAt: number;
  stepMs: number;
  scenario: Scenario;
  mode: ScanMode;
};

const scans = new Map<string, StoredScan>([
  [
    "demo-safe",
    {
      scanId: "demo-safe",
      submittedUrl: "https://google.com",
      normalizedUrl: "https://google.com",
      createdAt: Date.now() - 100_000,
      stepMs: 100,
      scenario: "safe",
      mode: "full",
    },
  ],
  [
    "demo-phishing",
    {
      scanId: "demo-phishing",
      submittedUrl: "https://paypal-secure-login.xyz",
      normalizedUrl: "https://paypal-secure-login.xyz",
      createdAt: Date.now() - 100_000,
      stepMs: 100,
      scenario: "phishing",
      mode: "full",
    },
  ],
]);
const wait = (ms: number) => new Promise<void>((resolve) => globalThis.setTimeout(resolve, ms));
const futureIso = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();

const definitions: ReadonlyArray<{
  id: CheckId;
  name: string;
  category: CheckCategory;
  source: string;
}> = [
  { id: "url_structure", name: "URL structure analysis", category: "url_structure", source: "SafeLinks heuristics" },
  { id: "ml_phishing", name: "Machine-learning phishing model", category: "phishing", source: "SafeLinks ML model" },
  { id: "domain_age", name: "Domain age", category: "domain", source: "WHOIS/RDAP" },
  { id: "ssl_certificate", name: "SSL certificate", category: "ssl", source: "TLS handshake" },
  { id: "redirect_chain", name: "Redirect chain", category: "url_structure", source: "SafeLinks crawler" },
  { id: "google_safe_browsing", name: "Google Safe Browsing", category: "reputation", source: "Google Safe Browsing" },
  { id: "virustotal", name: "VirusTotal", category: "malware", source: "VirusTotal" },
  { id: "urlhaus", name: "URLhaus", category: "malware", source: "abuse.ch URLhaus" },
];

function uuid4(): string {
  if (typeof globalThis.crypto?.randomUUID === "function") return globalThis.crypto.randomUUID();
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (character) => {
    const random = Math.floor(Math.random() * 16);
    const value = character === "x" ? random : (random & 0x3) | 0x8;
    return value.toString(16);
  });
}

function normalizeUrl(input: string): string {
  const withScheme = /^[a-z][a-z\d+.-]*:\/\//i.test(input.trim()) ? input.trim() : `https://${input.trim()}`;
  const url = new URL(withScheme);
  url.hostname = url.hostname.toLowerCase();
  url.hash = "";
  return url.toString();
}

function chooseScenario(url: string): Scenario {
  const value = url.toLowerCase();
  if (value.includes("fail")) return "failed";
  if (value.includes("unknown")) return "unknown";
  if (["google", "github", "wikipedia", "microsoft"].some((keyword) => value.includes(keyword))) return "safe";
  const phishingKeyword = ["login", "verify", "secure", "account", "update", "wallet"].some((keyword) => value.includes(keyword));
  const phishingTld = /\.(xyz|top|click|zip)(?:[/:?#]|$)/i.test(value);
  return phishingKeyword || phishingTld ? "phishing" : "suspicious";
}

function check(id: CheckId, severity: Severity, title: string, detail: string, evidence: string[] = []): Check {
  const definition = definitions.find((item) => item.id === id);
  if (!definition) throw new Error(`Unknown mock check: ${id}`);
  return { ...definition, status: "done", severity, title, detail, evidence };
}

function safeChecks(): Check[] {
  return [
    check("url_structure", "info", "No issues found", "The URL uses a conventional domain and does not contain deceptive formatting.", ["No IP address, @ symbol, punycode, or unusual port detected"]),
    check("ml_phishing", "info", "No issues found", "The URL pattern has a very low similarity to known phishing links.", ["Phishing probability: 3%", "HTTPS and a concise path lowered the estimate"]),
    check("domain_age", "info", "No issues found", "The domain has been registered for more than 25 years.", ["Domain age: 9,400 days", "Registrar: MarkMonitor Inc."]),
    check("ssl_certificate", "info", "No issues found", "The site presents a valid certificate from a recognized issuer.", ["Issuer: Google Trust Services", "Certificate has 62 days remaining"]),
    check("redirect_chain", "info", "No issues found", "The URL does not redirect through another domain.", ["Final host matches the submitted host"]),
    check("google_safe_browsing", "info", "No issues found", "No unsafe-site warnings were returned for this URL.", ["No threat matches found"]),
    check("virustotal", "info", "No issues found", "0 of 71 engines flagged this URL.", ["71 security engines returned no detections"]),
    check("urlhaus", "info", "No issues found", "The URL is not listed as a known malware distribution address.", ["No matching URLhaus entry"]),
  ];
}

function phishingChecks(): Check[] {
  return [
    check("url_structure", "high", "Deceptive URL structure", "The domain combines a trusted brand name with suspicious words and an uncommon ending.", ["Brand “paypal” appears in the domain", "3 hyphens split the domain into misleading terms", "Suspicious keywords: secure, login, verify", "Risky top-level domain detected"]),
    check("ml_phishing", "critical", "Strong phishing pattern", "The URL closely matches patterns commonly used by credential-stealing pages.", ["Phishing probability: 96%", "Brand impersonation and risky domain features raised the estimate"]),
    check("domain_age", "critical", "Domain registered very recently", "The domain was registered 4 days ago. Very new domains are common in short-lived phishing campaigns.", ["Registration age: 4 days", "Registrar record was created this week"]),
    check("ssl_certificate", "medium", "Certificate is unusually new", "The certificate is valid, but it was issued only 2 days ago and expires soon.", ["Issuer: Let's Encrypt", "Issued 2 days ago", "11 days remaining"]),
    check("redirect_chain", "medium", "Cross-domain redirects detected", "The link redirects through two unrelated domains before reaching its final destination.", ["2 cross-domain hops", "Final host differs from the submitted host"]),
    check("google_safe_browsing", "critical", "Known social-engineering page", "The destination is identified as a deceptive page intended to trick visitors.", ["Threat type: SOCIAL_ENGINEERING"]),
    check("virustotal", "high", "Flagged by multiple security engines", "14 of 70 engines flagged this URL as phishing or malicious.", ["Fortinet: phishing", "Sophos: malicious", "ESET: phishing", "BitDefender: suspicious"]),
    { ...definitions[7], status: "skipped", severity: "info", title: "Check skipped", detail: "Auth key not configured on the server", evidence: [] },
  ];
}

function suspiciousChecks(): Check[] {
  return [
    check("url_structure", "low", "Unusual URL pattern", "The URL contains promotional wording and a longer-than-average path.", ["Promotional keyword found in path", "URL length is above the typical range"]),
    check("ml_phishing", "medium", "Mixed phishing signals", "The model found some suspicious patterns, but the evidence is not conclusive.", ["Phishing probability: 48%", "Path wording raised the estimate"]),
    check("domain_age", "low", "Relatively new domain", "The domain was registered 120 days ago.", ["Domain age: 120 days"]),
    check("ssl_certificate", "info", "No issues found", "The certificate is valid and has not expired.", ["Issuer: Let's Encrypt", "Certificate has 48 days remaining"]),
    check("redirect_chain", "low", "One redirect detected", "The URL redirects once, but remains on the same registered domain.", ["1 same-domain redirect"]),
    check("google_safe_browsing", "info", "No issues found", "No unsafe-site warnings were returned for this URL.", ["No threat matches found"]),
    check("virustotal", "medium", "One security engine raised a warning", "1 of 70 engines flagged this URL.", ["CRDF: suspicious"]),
    check("urlhaus", "info", "No issues found", "The URL is not listed as a known malware distribution address.", ["No matching URLhaus entry"]),
  ];
}

function unknownChecks(): Check[] {
  const checks = safeChecks();
  checks[1] = { ...definitions[1], status: "error", severity: "info", title: "Model unavailable", detail: "The phishing model did not return a result before the timeout.", evidence: [] };
  checks[2] = { ...definitions[2], status: "error", severity: "info", title: "Domain age unavailable", detail: "Registration records could not be retrieved for this domain.", evidence: [] };
  checks[3] = { ...definitions[3], status: "skipped", severity: "info", title: "Certificate check skipped", detail: "No TLS certificate was available to inspect.", evidence: [] };
  checks[6] = { ...definitions[6], status: "error", severity: "info", title: "Reputation check unavailable", detail: "The reputation service did not respond in time.", evidence: [] };
  checks[7] = { ...definitions[7], status: "skipped", severity: "info", title: "Check skipped", detail: "Auth key not configured on the server", evidence: [] };
  return checks;
}

function mlFeatures(scenario: Exclude<Scenario, "failed" | "unknown">): MlFeature[] {
  if (scenario === "safe") return [
    { name: "is_https", value: true, impact: -0.31 },
    { name: "url_length", value: 24, impact: -0.18 },
    { name: "subdomain_count", value: 0, impact: -0.12 },
  ];
  if (scenario === "phishing") return [
    { name: "risky_tld", value: true, impact: 0.31 },
    { name: "keyword_count_host", value: 3, impact: 0.27 },
    { name: "brand_in_subdomain", value: true, impact: 0.22 },
    { name: "hyphen_count_host", value: 3, impact: 0.18 },
    { name: "url_length", value: 68, impact: 0.12 },
    { name: "subdomain_count", value: 2, impact: 0.09 },
    { name: "is_https", value: true, impact: -0.08 },
    { name: "path_depth", value: 3, impact: 0.05 },
  ];
  return [
    { name: "keyword_count_path", value: 2, impact: 0.24 },
    { name: "url_length", value: 52, impact: 0.16 },
    { name: "path_depth", value: 2, impact: 0.11 },
    { name: "is_https", value: true, impact: -0.13 },
    { name: "subdomain_count", value: 1, impact: -0.05 },
  ];
}

function resultFor(scan: StoredScan): ScanResult {
  const domain = new URL(scan.normalizedUrl).hostname;
  if (scan.scenario === "unknown") return {
    risk_score: 0,
    verdict: "unknown",
    confidence: 0.2,
    summary: "We could not complete enough checks to give a reliable verdict.",
    recommendations: ["Verify the address with the sender before opening it.", "Use the organization’s official website instead of this link."],
    ml: null,
    domain_info: null,
  };
  if (scan.scenario === "safe") return {
    risk_score: 6,
    verdict: "likely_safe",
    confidence: 0.93,
    summary: "No significant warning signs were found across the completed checks.",
    recommendations: ["Check that the domain is the one you expected.", "Stay alert for unexpected requests for sensitive information."],
    ml: { phishing_probability: 0.03, model_version: "safelinks-url-v1.4", top_features: mlFeatures("safe") },
    domain_info: { domain, age_days: 9400, registrar: "MarkMonitor Inc.", ssl: { valid: true, issuer: "Google Trust Services", expires_at: futureIso(62), days_remaining: 62 } },
  };
  if (scan.scenario === "phishing") return {
    risk_score: 93,
    verdict: "likely_malicious",
    confidence: 0.91,
    summary: "Several strong warning signs suggest this link is designed to steal account information.",
    recommendations: ["Do not open this link.", "Do not enter usernames, passwords, or payment details.", "If you already entered a password, change it and enable two-factor authentication.", "Report the message as phishing."],
    ml: { phishing_probability: 0.96, model_version: "safelinks-url-v1.4", top_features: mlFeatures("phishing") },
    domain_info: { domain, age_days: 4, registrar: "NameSilo, LLC", ssl: { valid: true, issuer: "Let's Encrypt", expires_at: futureIso(11), days_remaining: 11 } },
  };
  return {
    risk_score: 52,
    verdict: "suspicious",
    confidence: 0.62,
    summary: "This link has unusual characteristics. Verify the sender and destination before continuing.",
    recommendations: ["Confirm the link with the sender using another channel.", "Avoid entering sensitive information.", "Use the organization’s official website instead."],
    ml: { phishing_probability: 0.48, model_version: "safelinks-url-v1.4", top_features: mlFeatures("suspicious") },
    domain_info: { domain, age_days: 120, registrar: "NameCheap, Inc.", ssl: { valid: true, issuer: "Let's Encrypt", expires_at: futureIso(48), days_remaining: 48 } },
  };
}

function finalChecks(scenario: Scenario): Check[] {
  if (scenario === "safe") return safeChecks();
  if (scenario === "phishing") return phishingChecks();
  if (scenario === "unknown") return unknownChecks();
  return suspiciousChecks();
}

function checkProgress(scan: StoredScan, elapsed: number): { checks: Check[]; completed: number; duration: number } {
  const final = finalChecks(scan.scenario);
  const activeCount = scan.mode === "quick" ? 2 : 8;
  const duration = activeCount * scan.stepMs;
  const activeCompleted = Math.min(activeCount, Math.floor(elapsed / scan.stepMs));
  const checks = final.map((item, index): Check => {
    if (scan.mode === "quick" && index >= 2) {
      return { ...definitions[index], status: "skipped", severity: "info", title: "Check skipped", detail: "Not run in quick mode", evidence: [] };
    }
    if (index < activeCompleted) return item;
    if (index === activeCompleted && elapsed < duration) {
      return { ...definitions[index], status: "running", severity: "info", title: "", detail: "", evidence: [] };
    }
    return { ...definitions[index], status: "pending", severity: "info", title: "", detail: "", evidence: [] };
  });
  const skipped = scan.mode === "quick" ? 6 : 0;
  return { checks, completed: activeCompleted + skipped, duration };
}

export const mockClient: ScanApi = {
  async createScan(url: string, mode: ScanMode = "full") {
    const lower = url.toLowerCase();
    if (lower.includes("ratelimit")) throw new ApiError(429, "RATE_LIMITED", "Too many scans. Please wait a minute and try again.");
    if (lower.includes("offline")) throw new ApiError(0, "NETWORK", "Could not connect to SafeLinks. Check your connection and try again.");
    await wait(300 + Math.floor(Math.random() * 301));
    let normalizedUrl: string;
    try {
      normalizedUrl = normalizeUrl(url);
    } catch {
      throw new ApiError(422, "INVALID_URL", "That does not look like a valid link.");
    }
    const scanId = uuid4();
    scans.set(scanId, {
      scanId,
      submittedUrl: url,
      normalizedUrl,
      createdAt: Date.now(),
      stepMs: 920 + Math.floor(Math.random() * 31),
      scenario: chooseScenario(normalizedUrl),
      mode,
    });
    return { scan_id: scanId, status: "queued", submitted_url: url, normalized_url: normalizedUrl };
  },

  async getScan(scanId: string): Promise<ScanResponse> {
    const scan = scans.get(scanId);
    if (!scan) throw new ApiError(404, "NOT_FOUND", "This report was not found or has expired.");
    await wait(80);
    const elapsed = Date.now() - scan.createdAt;
    const progress = checkProgress(scan, elapsed);
    if (scan.scenario === "failed" && elapsed >= 3_000) {
      return {
        scan_id: scan.scanId,
        status: "failed",
        submitted_url: scan.submittedUrl,
        normalized_url: scan.normalizedUrl,
        created_at: new Date(scan.createdAt).toISOString(),
        completed_at: null,
        progress: { completed_checks: progress.completed, total_checks: 8 },
        checks: progress.checks,
        result: null,
        error: { code: "SCAN_FAILED", message: "The scan could not be completed. Please try again." },
      };
    }
    const complete = elapsed >= progress.duration;
    return {
      scan_id: scan.scanId,
      status: complete ? "completed" : "running",
      submitted_url: scan.submittedUrl,
      normalized_url: scan.normalizedUrl,
      created_at: new Date(scan.createdAt).toISOString(),
      completed_at: complete ? new Date(scan.createdAt + progress.duration).toISOString() : null,
      progress: { completed_checks: progress.completed, total_checks: 8 },
      checks: progress.checks,
      result: complete ? resultFor(scan) : null,
      error: null,
    };
  },

  async health(): Promise<HealthResponse> {
    await wait(100);
    return { status: "ok", version: "mock-v1", ml_model_loaded: true };
  },
};
