import { useEffect, useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router";
import { Link2, Menu, Moon, ShieldCheck, Sparkles, Sun, X, ZapOff } from "lucide-react";
import { motion, AnimatePresence } from "motion/react";
import { CONFIG } from "../../config";
import { scanApi } from "../../lib/api";
import { useCapabilities } from "../../lib/motion/useCapabilities";
import { useTheme } from "../theme";
import { Alert, Badge, Button, Tooltip, cn } from "./ui";
import { AnimatedGrid } from "../../components/fx/AnimatedGrid";
import { ParticleBackdrop } from "../../components/fx/ParticleBackdrop";
import { GradientBlobs } from "../../components/fx/GradientBlobs";
import { GlowCursor } from "../../components/fx/GlowCursor";
import { NoiseOverlay } from "../../components/fx/NoiseOverlay";

export function Logo() {
  return (
    <Link to="/" className="logo" aria-label="SafeLinks home">
      <span className="logo-mark">
        <ShieldCheck />
        <Link2 />
      </span>
      <span>
        Safe<span className="primary-text">Links</span>
      </span>
    </Link>
  );
}

function ThemeControl() {
  const { theme, setTheme } = useTheme();
  return (
    <div className="theme-control" aria-label="Theme">
      <Button
        variant="ghost"
        size="icon"
        aria-label="Use light theme"
        onClick={() => setTheme("light")}
        className={theme === "light" ? "active" : ""}
      >
        <Sun />
      </Button>
      <Button
        variant="ghost"
        size="icon"
        aria-label="Use dark theme"
        onClick={() => setTheme("dark")}
        className={theme === "dark" ? "active" : ""}
      >
        <Moon />
      </Button>
      <Button
        variant="ghost"
        className={theme === "system" ? "active" : ""}
        onClick={() => setTheme("system")}
      >
        Auto
      </Button>
    </div>
  );
}

function EffectsControl() {
  const { effectsMode, setEffectsMode } = useCapabilities();
  return (
    <div className="theme-control" aria-label="Visual effects mode" style={{ marginLeft: "0.4rem" }}>
      <Button
        variant="ghost"
        className={effectsMode === "full" ? "active" : ""}
        onClick={() => setEffectsMode("full")}
        aria-label="Full visual effects"
        title="Full visual effects"
        style={{ paddingInline: "0.45rem", minHeight: "2.15rem", height: "2.15rem" }}
      >
        <Sparkles style={{ width: "0.85rem", height: "0.85rem" }} />
      </Button>
      <Button
        variant="ghost"
        className={effectsMode === "reduced" ? "active" : ""}
        onClick={() => setEffectsMode("reduced")}
        aria-label="Reduced motion and effects"
        title="Reduced motion and effects"
        style={{ paddingInline: "0.45rem", minHeight: "2.15rem", height: "2.15rem" }}
      >
        <ZapOff style={{ width: "0.85rem", height: "0.85rem" }} />
      </Button>
    </div>
  );
}

const nav = [
  ["Scan", "/"],
  ["History", "/history"],
  ["How it works", "/about"],
] as const;

let healthCheck: Promise<{ online: true } | { online: false; error: string }> | null = null;
function checkApiHealth() {
  healthCheck ??= scanApi
    .health()
    .then(() => ({ online: true as const }))
    .catch((error: unknown) => {
      // Reset so a transient cold-start failure is not permanently cached
      healthCheck = null;
      return {
        online: false as const,
        error: error instanceof Error ? error.message : "The API health check failed.",
      };
    });
  return healthCheck;
}

export function Layout() {
  const [open, setOpen] = useState(false);
  const [online, setOnline] = useState(() => typeof navigator === "undefined" || navigator.onLine);
  const [apiStatus, setApiStatus] = useState<"demo" | "checking" | "online" | "offline">(
    CONFIG.USE_MOCK ? "demo" : "checking"
  );
  const [apiError, setApiError] = useState("");
  const [scrolled, setScrolled] = useState(false);
  const location = useLocation();
  const { reducedMotion } = useCapabilities();

  useEffect(() => {
    let disposed = false;
    const handleOnline = () => setOnline(true);
    const handleOffline = () => setOnline(false);
    const handleScroll = () => setScrolled(window.scrollY > 8);

    window.addEventListener("online", handleOnline);
    window.addEventListener("offline", handleOffline);
    window.addEventListener("scroll", handleScroll, { passive: true });

    if (!CONFIG.USE_MOCK) {
      void checkApiHealth().then((result) => {
        if (disposed) return;
        if (result.online) setApiStatus("online");
        else {
          setApiStatus("offline");
          setApiError(result.error);
        }
      });
    }

    return () => {
      disposed = true;
      window.removeEventListener("online", handleOnline);
      window.removeEventListener("offline", handleOffline);
      window.removeEventListener("scroll", handleScroll);
    };
  }, []);

  const statusBadge = (
    <Badge tone={apiStatus === "online" ? "safe" : apiStatus === "offline" ? "danger" : "neutral"}>
      <span className={cn("status-dot", apiStatus === "offline" && "offline")} />
      {apiStatus === "demo"
        ? "Demo mode"
        : apiStatus === "online"
          ? "API online"
          : apiStatus === "offline"
            ? "API offline"
            : "Checking API"}
    </Badge>
  );

  return (
    <div className="app-shell">
      <a href="#main-content" className="skip-link">
        Skip to content
      </a>

      {/* Motion & 3D Environment Layer */}
      <AnimatedGrid />
      <ParticleBackdrop />
      <GradientBlobs />
      <GlowCursor />
      <NoiseOverlay />

      <header className={cn("site-header", scrolled && "scrolled")}>
        <div className="container header-inner">
          <Logo />
          <nav className="desktop-nav" aria-label="Main navigation">
            {nav.map(([label, path]) => (
              <NavLink
                key={path}
                to={path}
                end={path === "/"}
                className={({ isActive }) => cn("nav-link", "nav-link-wrap", isActive && "active")}
              >
                {({ isActive }) => (
                  <>
                    {!reducedMotion && isActive && (
                      <motion.span
                        layoutId="activeNavPill"
                        className="nav-link-indicator"
                        transition={{ type: "spring", stiffness: 350, damping: 30 }}
                      />
                    )}
                    <span style={{ position: "relative", zIndex: 1 }}>{label}</span>
                  </>
                )}
              </NavLink>
            ))}
          </nav>
          <div className="desktop-nav">
            <ThemeControl />
            <EffectsControl />
          </div>
          <Button
            className="mobile-menu"
            variant="ghost"
            size="icon"
            onClick={() => setOpen(true)}
            aria-label="Open menu"
          >
            <Menu />
          </Button>
        </div>
      </header>

      {open && (
        <div className="sheet-backdrop" onClick={() => setOpen(false)}>
          <aside
            className="sheet"
            aria-label="Mobile navigation"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="row-between">
              <Logo />
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setOpen(false)}
                aria-label="Close menu"
              >
                <X />
              </Button>
            </div>
            <motion.nav
              initial={reducedMotion ? false : "hidden"}
              animate="visible"
              variants={{
                visible: { transition: { staggerChildren: 0.06 } },
              }}
            >
              {nav.map(([label, path]) => (
                <motion.div
                  key={path}
                  variants={{
                    hidden: { opacity: 0, x: 12 },
                    visible: { opacity: 1, x: 0 },
                  }}
                >
                  <NavLink key={path} to={path} onClick={() => setOpen(false)}>
                    {label}
                  </NavLink>
                </motion.div>
              ))}
            </motion.nav>
            <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
              <ThemeControl />
              <EffectsControl />
            </div>
          </aside>
        </div>
      )}

      {!online && (
        <div className="container offline-banner">
          <Alert danger>Browser offline. Reconnect to start or update scans.</Alert>
        </div>
      )}

      <main id="main-content">
        <AnimatePresence mode="wait" initial={false}>
          <motion.div
            key={location.pathname}
            initial={reducedMotion ? false : { opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={reducedMotion ? undefined : { opacity: 0, y: -6 }}
            transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
          >
            <Outlet />
          </motion.div>
        </AnimatePresence>
      </main>

      <footer className="site-footer">
        <div className="container footer-inner">
          <div>
            <Logo />
            <p>
              Automated link checks can be wrong. Always pause before sharing sensitive information.
            </p>
          </div>
          <nav aria-label="Footer navigation">
            {nav.map(([label, path]) => (
              <Link key={path} to={path}>
                {label}
              </Link>
            ))}
          </nav>
          {apiStatus === "offline" ? (
            <Tooltip text={apiError || "The API health check failed."}>{statusBadge}</Tooltip>
          ) : (
            statusBadge
          )}
        </div>
      </footer>
    </div>
  );
}
