import { z } from "zod";

export const scanModeSchema = z.enum(["full", "quick"]);
export const scanStatusSchema = z.enum(["queued", "running", "completed", "failed"]);
export const checkIdSchema = z.enum(["url_structure", "ml_phishing", "domain_age", "ssl_certificate", "redirect_chain", "google_safe_browsing", "virustotal", "urlhaus"]);
export const checkCategorySchema = z.enum(["phishing", "malware", "reputation", "domain", "ssl", "url_structure"]);
export const checkStatusSchema = z.enum(["pending", "running", "done", "skipped", "error"]);
export const severitySchema = z.enum(["info", "low", "medium", "high", "critical"]);
export const verdictSchema = z.enum(["likely_safe", "suspicious", "likely_malicious", "unknown"]);
export const errorCodeSchema = z.enum(["INVALID_URL", "INVALID_REQUEST", "UNSUPPORTED_SCHEME", "BLOCKED_TARGET", "NOT_FOUND", "RATE_LIMITED", "INTERNAL"]);
export const mlFeatureNameSchema = z.enum([
  "url_length", "host_length", "path_length", "query_length", "dot_count", "hyphen_count_host",
  "hyphen_count_url", "underscore_count", "digit_count_url", "digit_ratio_host", "subdomain_count",
  "has_ip_host", "has_at_symbol", "is_https", "has_custom_port", "double_slash_in_path",
  "query_param_count", "special_char_count", "host_entropy", "path_entropy", "longest_host_token",
  "has_punycode", "risky_tld", "is_shortener", "keyword_count_host", "keyword_count_path",
  "brand_in_subdomain", "brand_in_path", "path_depth", "suspicious_extension",
  "percent_encoded_count", "vowel_ratio_host", "registered_domain_length", "uppercase_count",
]);

export const createScanRequestSchema = z.object({ url: z.string().max(2048), mode: scanModeSchema.optional() });
export const createScanResponseSchema = z.object({
  scan_id: z.string(),
  status: z.literal("queued"),
  submitted_url: z.string(),
  normalized_url: z.string(),
});
export const checkSchema = z.object({
  id: checkIdSchema,
  name: z.string(),
  category: checkCategorySchema,
  status: checkStatusSchema,
  severity: severitySchema,
  title: z.string(),
  detail: z.string(),
  evidence: z.array(z.string()),
  source: z.string(),
});
export const mlFeatureSchema = z.object({
  name: mlFeatureNameSchema,
  value: z.union([z.string(), z.number(), z.boolean()]),
  impact: z.number().min(-1).max(1),
});
export const mlResultSchema = z.object({
  phishing_probability: z.number().min(0).max(1),
  model_version: z.string(),
  top_features: z.array(mlFeatureSchema),
});
export const sslInfoSchema = z.object({
  valid: z.boolean(),
  issuer: z.string(),
  expires_at: z.string(),
  days_remaining: z.number().int(),
});
export const domainInfoSchema = z.object({
  domain: z.string(),
  age_days: z.number().int().nullable(),
  registrar: z.string().nullable(),
  ssl: sslInfoSchema.nullable(),
});
export const scanResultSchema = z.object({
  risk_score: z.number().int().min(0).max(100),
  verdict: verdictSchema,
  confidence: z.number().min(0).max(1),
  summary: z.string(),
  recommendations: z.array(z.string()),
  ml: mlResultSchema.nullable(),
  domain_info: domainInfoSchema.nullable(),
});
export const scanResponseSchema = z.object({
  scan_id: z.string(),
  status: scanStatusSchema,
  submitted_url: z.string(),
  normalized_url: z.string(),
  created_at: z.string(),
  completed_at: z.string().nullable(),
  progress: z.object({ completed_checks: z.number().int().min(0), total_checks: z.number().int().min(1) }),
  checks: z.array(checkSchema),
  result: scanResultSchema.nullable(),
  error: z.object({ code: z.enum(["SCAN_FAILED", "TIMEOUT"]), message: z.string() }).nullable(),
});
export const healthResponseSchema = z.object({
  status: z.literal("ok"),
  version: z.string(),
  ml_model_loaded: z.boolean(),
});
export const errorResponseSchema = z.object({
  error: z.object({
    code: errorCodeSchema,
    message: z.string(),
    request_id: z.string().nullable(),
  }),
});
