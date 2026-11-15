import { AlertTriangle, Bug, CalendarClock, Fish, Globe, Link2, Lock, Mail, Network, Radar, ShieldCheck } from "lucide-react";
import { Link } from "react-router";
import { Badge, Card } from "../components/ui";
import { TiltCard } from "../../components/fx/TiltCard";
import { Reveal } from "../../components/fx/Reveal";

const checks = [
  [
    Link2,
    "URL structure",
    "Looks for misleading symbols, unusual ports, excessive subdomains and risky file endings.",
    "Attackers often make links look familiar at a glance.",
  ],
  [
    Fish,
    "Phishing prediction",
    "Uses URL patterns to estimate whether a link resembles known phishing techniques.",
    "It can identify deceptive patterns before a reputation database catches up.",
  ],
  [
    CalendarClock,
    "Domain age",
    "Checks how recently the domain was registered.",
    "Brand-new domains are commonly used in short-lived scams.",
  ],
  [
    Lock,
    "SSL certificate",
    "Checks whether the certificate is current and valid.",
    "Broken encryption can indicate neglect or impersonation.",
  ],
  [
    Network,
    "Redirect chain",
    "Checks whether the address silently sends visitors through other destinations.",
    "Unexpected redirects can hide the final site and make a link harder to judge.",
  ],
  [
    Radar,
    "Safe browsing",
    "Checks whether the destination appears in established unsafe-site records.",
    "Known phishing and malware pages may already have public warnings.",
  ],
  [
    Globe,
    "Reputation engines",
    "Compares detections reported by independent security scanners.",
    "Agreement between several engines is a strong warning signal.",
  ],
  [
    Bug,
    "Malware database",
    "Looks for associations with malware delivery and harmful downloads.",
    "Known malware infrastructure should be avoided.",
  ],
] as const;

export function About() {
  return (
    <div className="container page about-page">
      <div className="page-heading centered">
        <Badge tone="primary">Built for clarity</Badge>
        <h1>How SafeLinks works</h1>
        <p>
          Eight focused checks turn technical security signals into a plain-language report you can
          act on.
        </p>
      </div>

      <div className="about-checks">
        {checks.map(([Icon, title, look, why], index) => (
          <TiltCard key={title} className="glass-card">
            <span className="check-number">0{index + 1}</span>
            <Icon />
            <h2>{title}</h2>
            <h3>What it looks for</h3>
            <p>{look}</p>
            <h3>Why it matters</h3>
            <p>{why}</p>
          </TiltCard>
        ))}
      </div>

      <Reveal>
        <section className="about-section score-explainer">
          <div>
            <Badge>Risk score</Badge>
            <h2>One score, three clear levels</h2>
            <p>
              The score combines completed check results and model signals. Higher scores mean
              stronger or more numerous warning signs.
            </p>
          </div>
          <div className="score-levels">
            <div>
              <span className="safe-bg">0–29</span>
              <strong>Low risk</strong>
              <p>No major warnings found.</p>
            </div>
            <div>
              <span className="caution-bg">30–69</span>
              <strong>Suspicious</strong>
              <p>Pause and verify first.</p>
            </div>
            <div>
              <span className="danger-bg">70–100</span>
              <strong>High risk</strong>
              <p>Strong threat signals found.</p>
            </div>
          </div>
        </section>
      </Reveal>

      <div className="about-two">
        <TiltCard className="glass-card">
          <AlertTriangle />
          <h2>Limitations</h2>
          <ul>
            <li>No tool is 100% accurate.</li>
            <li>New threats can be missed.</li>
            <li>A low score is not a guarantee.</li>
            <li>False positives happen.</li>
          </ul>
        </TiltCard>
        <TiltCard className="glass-card">
          <ShieldCheck />
          <h2>Privacy</h2>
          <p>
            Links are sent to our server for analysis. Reports expire automatically and are not
            intended as permanent storage.
          </p>
        </TiltCard>
      </div>

      <Card className="contact-card">
        <Mail />
        <div>
          <h2>Something look wrong?</h2>
          <p>Tell us about an inaccurate or confusing report.</p>
        </div>
        <a className="button button-secondary" href="mailto:security@safelinks.example">
          Report a problem
        </a>
      </Card>

      <div className="centered">
        <Link to="/" className="button button-primary button-lg">
          Scan a link
        </Link>
      </div>
    </div>
  );
}
