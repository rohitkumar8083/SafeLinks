import { History as HistoryIcon, Search, Trash2 } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router";
import { motion, AnimatePresence } from "motion/react";
import { useHistory } from "../../lib/hooks/useHistory";
import { useCapabilities } from "../../lib/motion/useCapabilities";
import { hostname } from "../../lib/utils/url";
import { relativeTime } from "../../lib/utils/format";
import { UrlScanForm, VerdictBadge } from "../components/shared";
import { Button, Card, Modal } from "../components/ui";

export function History() {
  const { items, remove, clear } = useHistory();
  const { reducedMotion } = useCapabilities();
  const [confirm, setConfirm] = useState(false);
  const navigate = useNavigate();

  return (
    <div className="container page">
      <div className="page-heading row-between">
        <div>
          <p className="eyebrow">YOUR DEVICE</p>
          <h1>Scan history</h1>
          <p>Reports saved locally for quick access.</p>
        </div>
        {items.length > 0 && (
          <Button variant="danger" onClick={() => setConfirm(true)}>
            <Trash2 />
            Clear all
          </Button>
        )}
      </div>

      {items.length === 0 ? (
        <Card className="empty-state">
          <div className="empty-icon empty-floating">
            <HistoryIcon />
            <Search />
          </div>
          <h2>No scans yet</h2>
          <p>Check a link and its report will appear here.</p>
          <Link className="button button-primary button-lg" to="/">
            Scan a link
          </Link>
        </Card>
      ) : (
        <>
          <div className="history-table">
            <div className="history-row history-head">
              <span>Domain</span>
              <span>Verdict</span>
              <span>Score</span>
              <span>Scanned</span>
              <span />
            </div>
            <AnimatePresence initial={false}>
              {items.map((scan) => (
                <motion.div
                  className="history-row"
                  key={scan.scan_id}
                  role="link"
                  tabIndex={0}
                  onClick={() => navigate(`/scan/${scan.scan_id}`)}
                  onKeyDown={(event) => event.key === "Enter" && navigate(`/scan/${scan.scan_id}`)}
                  initial={reducedMotion ? false : { opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: "auto" }}
                  exit={reducedMotion ? undefined : { opacity: 0, height: 0, overflow: "hidden" }}
                  transition={{ duration: 0.2 }}
                >
                  <span className="mono">{hostname(scan.normalized_url)}</span>
                  <VerdictBadge verdict={scan.verdict} />
                  <strong>
                    {scan.verdict === "unknown" ? "—" : scan.risk_score}
                    <small>{scan.verdict === "unknown" ? "" : "/100"}</small>
                  </strong>
                  <span>{relativeTime(scan.created_at)}</span>
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label={`Delete ${hostname(scan.normalized_url)}`}
                    onClick={(event) => {
                      event.stopPropagation();
                      remove(scan.scan_id);
                    }}
                  >
                    <Trash2 />
                  </Button>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>

          <div className="history-cards">
            <AnimatePresence initial={false}>
              {items.map((scan) => (
                <motion.div
                  key={scan.scan_id}
                  initial={reducedMotion ? false : { opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={reducedMotion ? undefined : { opacity: 0, scale: 0.95 }}
                  transition={{ duration: 0.2 }}
                >
                  <Card onClick={() => navigate(`/scan/${scan.scan_id}`)}>
                    <div className="row-between">
                      <VerdictBadge verdict={scan.verdict} />
                      <Button
                        variant="ghost"
                        size="icon"
                        aria-label="Delete scan"
                        onClick={(event) => {
                          event.stopPropagation();
                          remove(scan.scan_id);
                        }}
                      >
                        <Trash2 />
                      </Button>
                    </div>
                    <p className="mono">{hostname(scan.normalized_url)}</p>
                    <div className="row-between">
                      <strong>
                        {scan.verdict === "unknown" ? "—" : `${scan.risk_score}/100`}
                      </strong>
                      <small>{relativeTime(scan.created_at)}</small>
                    </div>
                  </Card>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        </>
      )}

      <section className="history-cta">
        <h2>Check another link</h2>
        <UrlScanForm />
      </section>

      <Modal open={confirm} onClose={() => setConfirm(false)} title="Clear scan history?">
        <p>This removes all saved reports from this device. This cannot be undone.</p>
        <div className="modal-actions">
          <Button onClick={() => setConfirm(false)}>Cancel</Button>
          <Button
            variant="danger"
            onClick={() => {
              clear();
              setConfirm(false);
            }}
          >
            Clear all
          </Button>
        </div>
      </Modal>
    </div>
  );
}
