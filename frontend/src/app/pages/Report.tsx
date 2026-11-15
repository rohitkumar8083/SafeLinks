import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip as ChartTooltip, XAxis, YAxis } from "recharts";
import {
  AlertTriangle,
  ArrowLeft,
  Calendar,
  CheckCircle2,
  ChevronDown,
  Clipboard,
  Copy,
  Download,
  ExternalLink,
  Info,
  LoaderCircle,
  Printer,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  XCircle,
} from "lucide-react";
import { toast } from "sonner";
import { CONFIG } from "../../config";
import { scanApi, type Check, type ScanResponse } from "../../lib/api";
import { getCachedReport, getHistoryEntry } from "../../lib/hooks/useHistory";
import { useScan } from "../../lib/hooks/useScan";
import { useCapabilities } from "../../lib/motion/useCapabilities";
import { formatAge, formatDate, relativeTime } from "../../lib/utils/format";
import { defangUrl } from "../../lib/utils/url";
import { categoryIcons, featureLabel, severityMeta, verdictMeta } from "../../lib/utils/verdict";
import { VerdictBadge } from "../components/shared";
import { Alert, Badge, Button, Card, Progress, Skeleton, Tooltip, cn } from "../components/ui";
import { VerdictOrb } from "../../components/three/VerdictOrb";
import { ScanConstellation } from "../../components/scan/ScanConstellation";
import { CountUp } from "../../components/fx/CountUp";
import { TextScramble } from "../../components/fx/TextScramble";

function LoadingReport() {
  return (
    <div className="container page">
      <Skeleton className="skeleton-title" />
      <div className="report-grid">
        <Skeleton className="skeleton-card" />
        <div>
          <Skeleton className="skeleton-line" />
          <Skeleton className="skeleton-card" />
        </div>
      </div>
    </div>
  );
}

function RiskGauge({ scan }: { scan: ScanResponse }) {
  const result = scan.result;
  const scanning = !result && scan.status !== "failed";
  const unknown = scan.status === "failed" || result?.verdict === "unknown";
  const score = result?.risk_score ?? 0;
  const isHighRisk = (result?.verdict === "likely_malicious" || score >= 75) && !unknown && !scanning;
  const isSafe = (result?.verdict === "likely_safe" && score < 30) && !unknown && !scanning;

  return (
    <div className={cn("gauge-wrap", (unknown || scanning) && "gauge-neutral")}>
      <svg
        viewBox="0 0 220 126"
        role="img"
        aria-label={
          scanning
            ? "Scanning in progress"
            : unknown
              ? "Unable to determine risk"
              : `Risk score ${score} out of 100`
        }
      >
        <path className="gauge-base" d="M25 108 A85 85 0 0 1 195 108" />
        <path
          className="gauge-safe"
          d="M25 108 A85 85 0 0 1 56 43"
          style={isSafe ? { filter: "drop-shadow(0 0 8px hsl(142 71% 45% / 0.8))", strokeWidth: 10 } : undefined}
        />
        <path className="gauge-warn" d="M61 38 A85 85 0 0 1 159 38" />
        <path
          className="gauge-danger"
          d="M164 43 A85 85 0 0 1 195 108"
          style={isHighRisk ? { filter: "drop-shadow(0 0 8px hsl(0 84% 60% / 0.8))", strokeWidth: 10 } : undefined}
        />
      </svg>
      <div className="gauge-score">
        {scanning ? (
          <div className="gauge-scanning-content">
            <LoaderCircle className="spin" style={{ width: "2rem", height: "2rem", margin: "0 auto 0.35rem", color: "var(--primary)" }} />
            <span>Scanning...</span>
          </div>
        ) : unknown ? (
          <>
            <strong>—</strong>
            <span>Unable to determine</span>
          </>
        ) : (
          <div className="gauge-score-value">
            <strong>
              <CountUp target={score} />
            </strong>
            <span className="gauge-slash">/ 100</span>
          </div>
        )}
      </div>
    </div>
  );
}

function SummaryCard({ scan }: { scan: ScanResponse }) {
  const navigate = useNavigate();
  const { reducedMotion } = useCapabilities();
  const result = scan.result;
  const meta = result ? verdictMeta[result.verdict] : { tone: "unknown", icon: ShieldQuestion };
  const Icon = meta.icon;
  const partial =
    scan.status === "completed" &&
    scan.checks.some((item) => item.status === "skipped" || item.status === "error");
  const isHighRisk =
    scan.result?.verdict === "likely_malicious" || (scan.result?.risk_score ?? 0) >= 75;
  const isSafe =
    scan.result?.verdict === "likely_safe" && (scan.result?.risk_score ?? 0) < 30;

  // Extract detected threats from critical/high checks
  const criticalThreats = scan.checks
    .filter((c) => c.severity === "critical" || c.severity === "high")
    .map((c) => c.name);
  const displayThreats =
    criticalThreats.length > 0
      ? criticalThreats.slice(0, 4)
      : ["Phishing Pattern", "Malware Risk", "Suspicious Activity", "Data Theft Risk"];

  return (
    <Card className={cn("summary-card mesh-bg", isHighRisk && "high-risk-vignette", isSafe && "safe-vignette")}>
      <div className={cn("verdict-slot three-slot", `tone-${meta.tone}`)}>
        {reducedMotion ? (
          <>
            <div className="verdict-halo" />
            <Icon />
          </>
        ) : (
          <VerdictOrb scan={scan} />
        )}
      </div>
      <RiskGauge scan={scan} />
      <div aria-live="polite">
        {result ? (
          <VerdictBadge verdict={result.verdict} />
        ) : scan.status === "failed" ? (
          <Badge tone="unknown">
            <ShieldQuestion />
            Unable to determine
          </Badge>
        ) : (
          <Badge tone="unknown">
            <LoaderCircle className="spin" style={{ width: "0.95rem", height: "0.95rem" }} />
            Scanning...
          </Badge>
        )}
      </div>

      {result && isHighRisk && (
        <>
          <div className="danger-alert-box">
            <div className="danger-alert-icon-wrap">
              <AlertTriangle className="danger-alert-icon" />
            </div>
            <div className="danger-alert-body">
              <h4>This website is <span className="danger-glow-word">Dangerous!</span></h4>
              <p>It may be used to steal your account information, passwords or personal data.</p>
            </div>
          </div>

          <div className="threats-detected-box">
            <div className="threats-detected-header">
              <span className="threats-detected-title">
                <ShieldAlert style={{ width: "1rem", height: "1rem" }} /> Threats Detected:
              </span>
              <span className="threats-confidence-tag">
                {Math.round(result.confidence * 100)}% Confidence
              </span>
            </div>
            <div className="threats-tag-list">
              {displayThreats.map((tag) => (
                <span key={tag} className="threat-pill">
                  <XCircle className="threat-pill-icon" /> {tag}
                </span>
              ))}
            </div>
          </div>

          <Button
            className="go-back-safety-btn"
            onClick={() => navigate("/")}
          >
            <ArrowLeft /> Go Back to Safety
          </Button>
        </>
      )}

      {result && isSafe && (
        <>
          <div className="safe-alert-box">
            <div className="safe-alert-icon-wrap">
              <ShieldCheck className="safe-alert-icon" />
            </div>
            <div className="safe-alert-body">
              <h4>This website is <span className="safe-glow-word">Verified Safe!</span></h4>
              <p>No phishing, malware, or credential harvesting detected across security layers.</p>
            </div>
          </div>

          <div className="safe-highlights-box">
            <div className="safe-highlights-header">
              <span className="safe-highlights-title">
                <Shield style={{ width: "1rem", height: "1rem" }} /> Security Verified:
              </span>
              <span className="safe-confidence-tag">
                {Math.round(result.confidence * 100)}% Confidence
              </span>
            </div>
            <div className="safe-tag-list">
              <span className="safe-pill"><CheckCircle2 className="safe-pill-icon" /> Valid SSL Certificate</span>
              <span className="safe-pill"><CheckCircle2 className="safe-pill-icon" /> Established Domain</span>
              <span className="safe-pill"><CheckCircle2 className="safe-pill-icon" /> Clean Reputation</span>
              <span className="safe-pill"><CheckCircle2 className="safe-pill-icon" /> Safe Heuristics</span>
            </div>
          </div>

          <Button
            className="safe-continue-btn"
            onClick={() => window.open(scan.normalized_url, "_blank", "noopener,noreferrer")}
          >
            <ExternalLink /> Open Link Safely
          </Button>
        </>
      )}

      {result && !isHighRisk && !isSafe && (
        <>
          <p className="summary-copy">{result.summary}</p>
          <Tooltip text="How sure SafeLinks is, based on how many checks completed and how well they agree">
            <span className="confidence">
              <Info />
              Confidence: {Math.round(result.confidence * 100)}%
            </span>
          </Tooltip>
        </>
      )}

      {partial && (
        <p className="fine-print">
          Some checks were skipped or failed. The score uses the remaining checks.
        </p>
      )}
      <p className="fine-print">Automated results can be wrong.</p>
    </Card>
  );
}

function ScanProgress({ scan }: { scan: ScanResponse }) {
  if (!["queued", "running"].includes(scan.status)) return null;
  const value = (scan.progress.completed_checks / scan.progress.total_checks) * 100;
  return (
    <Card className="progress-card" aria-live="polite">
      <div className="row-between">
        <span style={{ display: "inline-flex", alignItems: "center", gap: "0.55rem" }}>
          <LoaderCircle className="spin" style={{ width: "1.15rem", height: "1.15rem", color: "var(--primary)", flexShrink: 0 }} />
          <span>Scanning link...</span>
        </span>
        <strong style={{ fontFamily: "JetBrains Mono, monospace", color: "var(--primary)" }}>
          <CountUp target={scan.progress.completed_checks} /> of {scan.progress.total_checks} checks complete
        </strong>
      </div>
      <Progress value={value} className="animated-stripes" />
    </Card>
  );
}

const tabs = ["all", "phishing", "malware", "reputation", "domain", "ssl", "url_structure"] as const;

function CheckCard({ check }: { check: Check }) {
  const categoryIcon = categoryIcons[check.category];
  const meta = severityMeta[check.severity];
  const SeverityIcon = meta.icon;
  const CategoryIcon = categoryIcon;

  if (check.status === "pending") {
    return (
      <Card id={`check-card-${check.id}`} className="check-card">
        <Skeleton className="skeleton-line" />
        <Skeleton className="skeleton-line short" />
      </Card>
    );
  }

  return (
    <Card id={`check-card-${check.id}`} className={cn("check-card", `severity-${check.severity}`)}>
      {check.status === "running" && <span className="scan-sweep-line" aria-hidden="true" />}
      <div className="check-icon">
        <CategoryIcon />
      </div>
      <div className="check-main">
        <div className="check-meta">
          <span>{check.name}</span>
          {check.status === "running" ? (
            <Badge>
              <LoaderCircle className="spin" />
              Checking...
            </Badge>
          ) : check.status === "skipped" ? (
            <Badge>Skipped</Badge>
          ) : check.status === "error" ? (
            <Badge tone="caution">Could not complete</Badge>
          ) : check.severity === "info" ? (
            <Badge tone="safe">
              <CheckCircle2 />
              No issues found
            </Badge>
          ) : (
            <Badge tone={meta.tone}>
              <SeverityIcon />
              {meta.label}
            </Badge>
          )}
        </div>
        <h3>{check.title || check.name}</h3>
        <p>{check.detail}</p>
        <small>Source: {check.source}</small>
        {check.evidence.length > 0 && (
          <details className="evidence">
            <summary>
              Evidence <ChevronDown />
            </summary>
            <ul>
              {check.evidence.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </details>
        )}
      </div>
    </Card>
  );
}

function CheckList({ scan }: { scan: ScanResponse }) {
  const [tab, setTab] = useState<(typeof tabs)[number]>("all");
  const { reducedMotion } = useCapabilities();

  const sorted = useMemo(() => {
    const list = tab === "all" ? scan.checks : scan.checks.filter((check) => check.category === tab);
    return scan.status === "completed"
      ? [...list].sort((a, b) => severityMeta[b.severity].rank - severityMeta[a.severity].rank)
      : list;
  }, [scan, tab]);

  return (
    <section className="checks-section">
      <div className="section-title">
        <div>
          <p className="eyebrow">DETECTION LAYERS</p>
          <h2>Safety checks</h2>
        </div>
        <Badge>{scan.checks.filter((c) => c.status === "done").length}/8 complete</Badge>
      </div>

      {reducedMotion ? (
        <div className="constellation-slot three-slot" aria-label="Eight scan checks visualization">
          {scan.checks.map((check, index) => (
            <span
              key={check.id}
              className={cn("constellation-node", check.status === "done" && "complete")}
              style={{ "--i": index } as React.CSSProperties}
            >
              <CheckCircle2 />
            </span>
          ))}
          <Shield />
        </div>
      ) : (
        <ScanConstellation scan={scan} />
      )}

      <div className="tabs" role="tablist" aria-label="Filter checks">
        {tabs.map((item) => {
          const count =
            item === "all" ? scan.checks.length : scan.checks.filter((c) => c.category === item).length;
          return (
            <button
              role="tab"
              aria-selected={tab === item}
              key={item}
              onClick={() => setTab(item)}
            >
              {item === "url_structure" ? "URL" : `${item.charAt(0).toUpperCase()}${item.slice(1)}`}
              <Badge>{count}</Badge>
            </button>
          );
        })}
      </div>

      <div className="check-list">
        {sorted.map((check) => (
          <CheckCard key={check.id} check={check} />
        ))}
      </div>
    </section>
  );
}

function DomainInfoCard({ scan }: { scan: ScanResponse }) {
  const info = scan.result?.domain_info;
  const entries = [
    ["Domain", info?.domain ?? "Unknown"],
    ["Domain age", formatAge(info?.age_days ?? null)],
    ["Registrar", info?.registrar ?? "Unknown"],
    ["SSL certificate", info?.ssl ? (info.ssl.valid ? "Valid" : "Invalid") : "Unknown"],
    ["Issuer", info?.ssl?.issuer ?? "Unknown"],
    ["Expiry", info?.ssl ? `${formatDate(info.ssl.expires_at)} · ${info.ssl.days_remaining} days remaining` : "Unknown"],
  ] as const;

  return (
    <Card className="side-card">
      <div className="card-title">
        <Calendar />
        <h2>Domain details</h2>
      </div>
      <dl>
        {entries.map(([label, value], index) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd
              className={cn(
                index === 0 && "mono",
                label === "Domain age" && info?.age_days != null && info.age_days < 30 && "danger-text",
                label === "SSL certificate" && (info?.ssl?.valid ? "safe-text" : "danger-text")
              )}
            >
              {label === "SSL certificate" && info?.ssl && (info.ssl.valid ? <CheckCircle2 /> : <AlertTriangle />)}
              {value}
            </dd>
          </div>
        ))}
      </dl>
    </Card>
  );
}

function FeatureChart({ scan }: { scan: ScanResponse }) {
  const ml = scan.result?.ml;
  if (!ml) {
    return (
      <Card className="chart-card">
        <h2>Why this score?</h2>
        <p>ML analysis unavailable for this scan.</p>
      </Card>
    );
  }
  const data = ml.top_features.slice(0, 8).map((item) => ({ ...item, label: featureLabel(item.name) }));
  return (
    <Card className="chart-card">
      <div className="row-between chart-heading">
        <div>
          <p className="eyebrow">MODEL EXPLANATION</p>
          <h2>Why this score?</h2>
          <p>How each URL feature pushed the phishing estimate</p>
        </div>
        <Badge tone={ml.phishing_probability >= 0.7 ? "danger" : ml.phishing_probability >= 0.3 ? "caution" : "safe"}>
          {Math.round(ml.phishing_probability * 100)}% likelihood
        </Badge>
      </div>
      <div className="likelihood">
        <span>Phishing likelihood</span>
        <strong>{Math.round(ml.phishing_probability * 100)}%</strong>
        <Progress value={ml.phishing_probability * 100} />
      </div>
      <div className="chart-visual" aria-hidden="true">
        <ResponsiveContainer width="100%" height={330}>
          <BarChart data={data} layout="vertical" margin={{ left: 8, right: 20 }}>
            <XAxis type="number" domain={[-1, 1]} hide />
            <YAxis
              type="category"
              dataKey="label"
              width={168}
              tick={{ fill: "currentColor", fontSize: 11 }}
              axisLine={false}
              tickLine={false}
            />
            <ChartTooltip
              cursor={{ fill: "color-mix(in hsl, var(--primary) 12%, transparent)", radius: 6 }}
              formatter={(value, _name, item) => [
                `Impact: ${Number(value).toFixed(2)} · Raw: ${String(item.payload.value)}`,
                "Feature",
              ]}
              contentStyle={{
                background: "var(--solid)",
                border: "1px solid var(--border)",
                borderRadius: "12px",
              }}
            />
            <Bar dataKey="impact" radius={5}>
              {data.map((item) => (
                <Cell key={item.name} fill={item.impact > 0 ? "var(--danger)" : "var(--safe)"} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      <ul className="feature-list" aria-label="Feature impact text alternative">
        {data.map((item) => (
          <li key={item.name}>
            <span>{item.label}</span>
            <strong className={item.impact > 0 ? "danger-text" : "safe-text"}>
              {item.impact > 0 ? "Raises" : "Lowers"} risk · {Math.abs(item.impact).toFixed(2)}
            </strong>
            <small>Raw value: {String(item.value)}</small>
          </li>
        ))}
      </ul>
      <p className="model-note">
        Model version: <span className="mono">{ml.model_version}</span>
      </p>
    </Card>
  );
}

function Recommendations({ scan }: { scan: ScanResponse }) {
  const result = scan.result;
  if (!result) return null;
  return (
    <Card className="recommend-card">
      <div className="card-title">
        <ShieldAlert />
        <h2>What you should do</h2>
      </div>
      {result.verdict === "likely_malicious" && (
        <Alert danger>
          <AlertTriangle />
          <strong>Do not open this link or enter any passwords or card details.</strong>
        </Alert>
      )}
      <ol>
        {result.recommendations.map((item, index) => (
          <li key={item}>
            <span>{index + 1}</span>
            <p>{item}</p>
          </li>
        ))}
      </ol>
    </Card>
  );
}

function ActionsCard({ scan }: { scan: ScanResponse }) {
  const navigate = useNavigate();

  async function copy(text: string, message: string) {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(message);
    } catch {
      try {
        const field = document.createElement("textarea");
        field.value = text;
        field.style.position = "fixed";
        field.style.opacity = "0";
        document.body.appendChild(field);
        field.select();
        const copied = document.execCommand("copy");
        field.remove();
        if (!copied) throw new Error("Copy unavailable");
        toast.success(message);
      } catch {
        toast.error("Copy failed. Select the text and copy it manually.");
      }
    }
  }

  async function again() {
    try {
      const next = await scanApi.createScan(scan.normalized_url);
      navigate(`/scan/${next.scan_id}`);
    } catch {
      toast.error("Could not start a new scan. Please try again.");
    }
  }

  function download() {
    try {
      const blob = new Blob([JSON.stringify(scan, null, 2)], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `safelinks-report-${scan.scan_id}.json`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch {
      void copy(JSON.stringify(scan, null, 2), "Report JSON copied");
    }
  }

  return (
    <Card className="side-card actions-card">
      <h2>Report actions</h2>
      <Button variant="primary" onClick={again}>
        <RefreshCw />
        Scan again
      </Button>
      <Tooltip text="Works while the report is still stored">
        <Button onClick={() => copy(location.href, "Link copied")}>
          <Copy />
          Copy report link
        </Button>
      </Tooltip>
      <Button onClick={download}>
        <Download />
        Download JSON
      </Button>
      <Button
        onClick={() => {
          try {
            window.print();
          } catch {
            toast.error("Printing is not available in this browser.");
          }
        }}
      >
        <Printer />
        Print / Save as PDF
      </Button>
    </Card>
  );
}

export function Report() {
  const { scanId = "" } = useParams();
  const [defanged, setDefanged] = useState(false);
  const [copiedUrl, setCopiedUrl] = useState(false);
  const { scan: liveScan, isLoading, error, backendSlow, retry } = useScan(scanId);
  const navigate = useNavigate();

  const cachedScan = error?.code === "NOT_FOUND" ? getCachedReport(scanId) : null;
  const scan = liveScan ?? cachedScan;
  const savedCopy = Boolean(cachedScan && !liveScan);
  const historyEntry = getHistoryEntry(scanId);

  async function scanAgain(url: string) {
    try {
      const next = await scanApi.createScan(url);
      navigate(`/scan/${next.scan_id}`);
    } catch {
      toast.error("Could not start a new scan. Please try again.");
    }
  }

  if (isLoading && !scan) return <LoadingReport />;

  if (error && !scan) {
    if (error.code === "NOT_FOUND") {
      return (
        <div className="container page">
          <Card className="empty-state">
            <AlertTriangle className="empty-floating" />
            <p className="eyebrow">REPORT EXPIRED</p>
            <h1>Report expired</h1>
            <p>The server no longer has this report.</p>
            {historyEntry ? (
              <Button variant="primary" size="lg" onClick={() => void scanAgain(historyEntry.normalized_url)}>
                <RefreshCw />
                Scan again
              </Button>
            ) : (
              <Link className="button button-primary button-lg" to="/">
                Scan a link
              </Link>
            )}
          </Card>
        </div>
      );
    }
    const badResponse = error.code === "BAD_RESPONSE";
    return (
      <div className="container page">
        <Card className="empty-state">
          <Alert danger>
            <AlertTriangle />
            {badResponse
              ? "SafeLinks received an unexpected server response."
              : "Cannot reach the SafeLinks server"}
          </Alert>
          {error.requestId && <p className="mono">Request ID: {error.requestId}</p>}
          {!badResponse && <p>If this app is served over https, the backend must also use https.</p>}
          <Button variant="primary" onClick={retry}>
            <RefreshCw />
            Retry
          </Button>
        </Card>
      </div>
    );
  }

  if (!scan) return <LoadingReport />;

  const url = defanged ? defangUrl(scan.normalized_url) : scan.normalized_url;

  return (
    <div className="report-page mesh-bg">
      <div className="container page">
        {CONFIG.USE_MOCK && (
          <Alert>
            <Info />
            You are viewing demo data. Connect the backend to see real results.
          </Alert>
        )}
        {backendSlow && (
          <Alert>
            <Info />
            Waking up the server... free hosting can take up to a minute to start
          </Alert>
        )}
        {savedCopy && (
          <Alert>
            <Info />
            Showing a saved copy. The server no longer has this report.
            <Button onClick={() => void scanAgain(scan.normalized_url)}>Scan again</Button>
          </Alert>
        )}
        {error?.code === "NETWORK" && (
          <Alert danger>
            <AlertTriangle />
            <span>
              Cannot reach the SafeLinks server. If this app is served over https, the backend must
              also use https.
            </span>
            <Button onClick={retry}>Retry</Button>
          </Alert>
        )}
        {error?.code === "BAD_RESPONSE" && (
          <Alert danger>
            <AlertTriangle />
            <span>
              SafeLinks received an unexpected server response.
              {error.requestId ? ` Request ID: ${error.requestId}` : ""}
            </span>
            <Button onClick={retry}>Retry</Button>
          </Alert>
        )}

        <header className="scan-header">
          <p className="breadcrumb">
            <Link to="/">Scan</Link>
            <span>/</span>Report
          </p>
          <div className="scan-title-row">
            <div>
              <p className="eyebrow">
                {scan.status === "completed" ? "ANALYSIS COMPLETE" : "LINK ANALYSIS"}
              </p>
              <h1>Security report</h1>
            </div>
            <div className="scan-time">
              <span>{formatDate(scan.created_at)}</span>
              <small>{relativeTime(scan.created_at)}</small>
            </div>
          </div>
          <div className="url-display">
            <Tooltip text={url}>
              <code>
                <TextScramble text={url} />
              </code>
            </Tooltip>
            <Button
              variant="ghost"
              size="icon"
              aria-label="Copy scanned URL"
              onClick={() =>
                navigator.clipboard
                  .writeText(url)
                  .then(() => {
                    setCopiedUrl(true);
                    toast.success("Link copied");
                    setTimeout(() => setCopiedUrl(false), 1500);
                  })
                  .catch(() => toast.error("Copy failed"))
              }
            >
              {copiedUrl ? <CheckCircle2 style={{ color: "var(--safe)" }} /> : <Clipboard />}
            </Button>
            <label className="switch">
              <input type="checkbox" checked={defanged} onChange={(e) => setDefanged(e.target.checked)} />
              <span />
              Defang
            </label>
          </div>
        </header>

        {scan.status === "failed" && (
          <Alert danger>
            {scan.error?.message}
            <Button onClick={() => void scanAgain(scan.normalized_url)}>Try again</Button>
          </Alert>
        )}

        <div className="report-grid">
          <aside className="report-side">
            <SummaryCard scan={scan} />
            <DomainInfoCard scan={scan} />
            <ActionsCard scan={scan} />
          </aside>
          <div className="report-main">
            <ScanProgress scan={scan} />
            <CheckList scan={scan} />
            <FeatureChart scan={scan} />
            <Recommendations scan={scan} />
          </div>
        </div>
      </div>
    </div>
  );
}
