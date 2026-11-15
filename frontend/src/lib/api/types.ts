export type ScanMode = "full" | "quick";
export type ScanStatus = "queued" | "running" | "completed" | "failed";
export type CheckId = "url_structure" | "ml_phishing" | "domain_age" | "ssl_certificate" | "redirect_chain" | "google_safe_browsing" | "virustotal" | "urlhaus";
export type CheckCategory = "phishing" | "malware" | "reputation" | "domain" | "ssl" | "url_structure";
export type CheckStatus = "pending" | "running" | "done" | "skipped" | "error";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Verdict = "likely_safe" | "suspicious" | "likely_malicious" | "unknown";
export type ErrorCode = "INVALID_URL" | "INVALID_REQUEST" | "UNSUPPORTED_SCHEME" | "BLOCKED_TARGET" | "NOT_FOUND" | "RATE_LIMITED" | "INTERNAL";
export type MlFeatureName =
  | "url_length" | "host_length" | "path_length" | "query_length" | "dot_count"
  | "hyphen_count_host" | "hyphen_count_url" | "underscore_count" | "digit_count_url"
  | "digit_ratio_host" | "subdomain_count" | "has_ip_host" | "has_at_symbol" | "is_https"
  | "has_custom_port" | "double_slash_in_path" | "query_param_count" | "special_char_count"
  | "host_entropy" | "path_entropy" | "longest_host_token" | "has_punycode" | "risky_tld"
  | "is_shortener" | "keyword_count_host" | "keyword_count_path" | "brand_in_subdomain"
  | "brand_in_path" | "path_depth" | "suspicious_extension" | "percent_encoded_count"
  | "vowel_ratio_host" | "registered_domain_length" | "uppercase_count";

export interface CreateScanRequest { url: string; mode?: ScanMode }
export interface CreateScanResponse { scan_id: string; status: "queued"; submitted_url: string; normalized_url: string }
export interface Check { id: CheckId; name: string; category: CheckCategory; status: CheckStatus; severity: Severity; title: string; detail: string; evidence: string[]; source: string }
export interface MlFeature { name: MlFeatureName; value: string | number | boolean; impact: number }
export interface MlResult { phishing_probability: number; model_version: string; top_features: MlFeature[] }
export interface SslInfo { valid: boolean; issuer: string; expires_at: string; days_remaining: number }
export interface DomainInfo { domain: string; age_days: number | null; registrar: string | null; ssl: SslInfo | null }
export interface ScanResult { risk_score: number; verdict: Verdict; confidence: number; summary: string; recommendations: string[]; ml: MlResult | null; domain_info: DomainInfo | null }
export interface ScanResponse {
  scan_id: string;
  status: ScanStatus;
  submitted_url: string;
  normalized_url: string;
  created_at: string;
  completed_at: string | null;
  progress: { completed_checks: number; total_checks: number };
  checks: Check[];
  result: ScanResult | null;
  error: { code: "SCAN_FAILED" | "TIMEOUT"; message: string } | null;
}
export interface HealthResponse { status: "ok"; version: string; ml_model_loaded: boolean }
export interface ErrorResponse { error: { code: ErrorCode; message: string; request_id: string | null } }

export interface ScanApi {
  createScan(url: string, mode?: ScanMode): Promise<CreateScanResponse>;
  getScan(scanId: string): Promise<ScanResponse>;
  health(): Promise<HealthResponse>;
}
