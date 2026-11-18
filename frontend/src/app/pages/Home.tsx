import { Bug, CalendarClock, CheckCircle2, Fish, Gauge, Link2, LockKeyhole, ScanSearch, ShieldCheck, Sparkles } from "lucide-react";
import { Link } from "react-router";
import { CONFIG } from "../../config";
import { useHistory } from "../../lib/hooks/useHistory";
import { useCapabilities } from "../../lib/motion/useCapabilities";
import { hostname } from "../../lib/utils/url";
import { relativeTime } from "../../lib/utils/format";
import { UrlScanForm, VerdictBadge } from "../components/shared";
import { Badge } from "../components/ui";
import { Reveal } from "../../components/fx/Reveal";
import { TiltCard } from "../../components/fx/TiltCard";
import { CountUp } from "../../components/fx/CountUp";
import { HeroShield } from "../../components/three/HeroShield";

const features = [
  [Fish, "Phishing detection", "Spots lookalike and deceptive URLs using machine learning and URL pattern analysis"],
  [Bug, "Malware and reputation", "Cross-checks Google Safe Browsing, VirusTotal and URLhaus"],
  [CalendarClock, "Domain and SSL", "Checks how old the domain is and whether its certificate is valid"],
] as const;

const faqs = [
  ["Does SafeLinks open the link?", "No. Checks run on our servers, the page is never shown to you, and you never need to visit it."],
  ["Is a low score a guarantee?", "No. No tool is 100% accurate. Treat the report as one signal and stay alert."],
  ["What do the risk levels mean?", "Low risk means no major warnings were found. Suspicious means caution is needed. High risk means strong threat signals were found."],
  ["Is my link stored?", "Reports are kept temporarily and then deleted."],
] as const;

export function Home() {
  const { items } = useHistory();
  const { reducedMotion } = useCapabilities();
  const recentScans = items.slice(0, 3);

  return (
    <>
      <section className="hero mesh-bg">
        <div className="container hero-grid">
          <div className="hero-copy">
            <Badge tone="primary">
              <Sparkles />
              Free link safety checker
            </Badge>
            <h1>
              Is this link <span className="gradient-text gradient-shimmer">safe?</span>
            </h1>
            <p className="hero-lead">
              Paste a link and SafeLinks checks it for phishing, malware, bad reputation, brand-new
              domains and SSL problems, without ever opening it on your device.
            </p>
            <UrlScanForm />
            <div className="examples">
              <span>Try an example</span>
              {[
                ["google.com", "safe demo"],
                ["paypal-secure-login.xyz", "phishing demo"],
                ["example-shop.com/offer", "suspicious demo"],
              ].map(([url, label]) => (
                <button
                  key={url}
                  className="example-chip"
                  onClick={() => window.dispatchEvent(new CustomEvent("safelinks:fill", { detail: url }))}
                >
                  {url}
                  <small>{label}</small>
                </button>
              ))}
            </div>
            <p className="fine-print">
              We never open the link on your device. Results are automated and can be wrong.
            </p>
          </div>
          <div className="hero-visual three-slot" aria-label="Decorative security shield">
            {reducedMotion ? (
              <>
                <div className="orb-rings" />
                <div className="hero-shield">
                  <ShieldCheck />
                </div>
                <span className="signal signal-one" />
                <span className="signal signal-two" />
                <span className="signal signal-three" />
              </>
            ) : (
              <HeroShield />
            )}
          </div>
        </div>
      </section>

      <section className="container section compact-section">
        <Reveal>
          <div className="trust-strip">
            <div>
              <ScanSearch />
              <strong>
                <CountUp target={8} /> safety checks
              </strong>
              <span>working in parallel</span>
            </div>
            <div>
              <Gauge />
              <strong>Under 10 seconds</strong>
              <span>for most reports</span>
            </div>
            <div>
              <LockKeyhole />
              <strong>No link opened</strong>
              <span>on your device</span>
            </div>
          </div>
        </Reveal>
      </section>

      <section className="container section">
        <Reveal>
          <div className="section-heading">
            <Badge>What we inspect</Badge>
            <h2>Security signals, made understandable</h2>
            <p>Eight focused checks come together in one clear report.</p>
          </div>
        </Reveal>
        <div className="card-grid">
          {features.map(([Icon, title, copy], i) => (
            <TiltCard key={title} className="feature-card">
              <span className={`feature-icon feature-${i}`}>
                <Icon />
              </span>
              <h3>{title}</h3>
              <p>{copy}</p>
              <span className="learn-link">
                Included in every full scan <CheckCircle2 />
              </span>
            </TiltCard>
          ))}
        </div>
      </section>

      <section className="container section">
        <Reveal>
          <div className="section-heading">
            <Badge>Simple by design</Badge>
            <h2>From pasted link to clear answer</h2>
          </div>
        </Reveal>
        <div className="steps">
          {(
            [
              [Link2, "Paste a link"],
              [ScanSearch, "We run 8 safety checks in parallel"],
              [ShieldCheck, "Get a risk score with plain-language reasons"],
            ] as const
          ).map(([Icon, text], index) => (
            <div className="step" key={text}>
              <span>
                <CountUp target={index + 1} />
              </span>
              <Icon />
              <h3>{text}</h3>
            </div>
          ))}
        </div>
      </section>

      {recentScans.length > 0 && (
        <section className="container section">
          <Reveal>
            <div className="row-between">
              <div>
                <p className="eyebrow">RECENT ACTIVITY</p>
                <h2>Recent scans</h2>
              </div>
              <Link to="/history" className="text-link">
                View all history
              </Link>
            </div>
          </Reveal>
          <div className="recent-strip">
            {recentScans.map((scan) => (
              <Link key={scan.scan_id} to={`/scan/${scan.scan_id}`} className="recent-item">
                <VerdictBadge verdict={scan.verdict} />
                <span className="mono">{hostname(scan.normalized_url)}</span>
                <small>{relativeTime(scan.created_at)}</small>
              </Link>
            ))}
          </div>
        </section>
      )}

      <section className="container section faq-section">
        <div>
          <Badge>FAQ</Badge>
          <h2>Questions, answered plainly</h2>
          <p>SafeLinks helps you make a more informed choice before clicking.</p>
        </div>
        <div className="faq-list">
          {faqs.map(([q, a]) => (
            <details key={q}>
              <summary>
                {q}
                <span>+</span>
              </summary>
              <p>{a}</p>
            </details>
          ))}
        </div>
      </section>
    </>
  );
}
