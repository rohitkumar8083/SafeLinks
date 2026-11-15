import { useEffect, useRef, useState, type FormEvent } from "react";
import { Check, Clipboard, Link as LinkIcon, LoaderCircle } from "lucide-react";
import { useNavigate } from "react-router";
import { toast } from "sonner";
import { scanApi, ApiError, type Verdict } from "../../lib/api";
import { normalizeUrl } from "../../lib/utils/url";
import { verdictMeta } from "../../lib/utils/verdict";
import { Alert, Badge, Button, Input, cn } from "./ui";
import { MagneticButton } from "../../components/fx/MagneticButton";

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const meta = verdictMeta[verdict];
  const Icon = meta.icon;
  return (
    <Badge tone={meta.tone}>
      <Icon />
      {meta.label}
    </Badge>
  );
}

const TYPEWRITER_EXAMPLES = [
  "https://example.com/login",
  "https://paypal-secure-login.xyz",
  "https://google.com",
  "https://account-verify-secure.net",
];

export function UrlScanForm({ initial = "" }: { initial?: string }) {
  const [value, setValue] = useState(initial);
  const [error, setError] = useState("");
  const [networkError, setNetworkError] = useState(false);
  const [loading, setLoading] = useState(false);
  const [isFocused, setIsFocused] = useState(false);
  const [isShaking, setIsShaking] = useState(false);
  const [placeholderText, setPlaceholderText] = useState(TYPEWRITER_EXAMPLES[0]);
  const navigate = useNavigate();
  const input = useRef<HTMLInputElement>(null);

  // Typewriter placeholder effect when idle
  useEffect(() => {
    if (value || isFocused) return;
    let exampleIndex = 0;
    let charIndex = 0;
    let isDeleting = false;
    let timeoutId: any = null;

    function tick() {
      const currentWord = TYPEWRITER_EXAMPLES[exampleIndex];
      if (!isDeleting) {
        charIndex++;
        setPlaceholderText(currentWord.slice(0, charIndex));
        if (charIndex === currentWord.length) {
          isDeleting = true;
          timeoutId = setTimeout(tick, 2200);
          return;
        }
        timeoutId = setTimeout(tick, 60);
      } else {
        charIndex--;
        setPlaceholderText(currentWord.slice(0, charIndex));
        if (charIndex === 0) {
          isDeleting = false;
          exampleIndex = (exampleIndex + 1) % TYPEWRITER_EXAMPLES.length;
          timeoutId = setTimeout(tick, 400);
          return;
        }
        timeoutId = setTimeout(tick, 30);
      }
    }

    timeoutId = setTimeout(tick, 1000);
    return () => clearTimeout(timeoutId);
  }, [value, isFocused]);

  useEffect(() => {
    if (matchMedia("(min-width: 768px)").matches) input.current?.focus();
  }, []);

  useEffect(() => {
    const fill = (event: Event) => {
      const detail = (event as CustomEvent<string>).detail;
      setValue(detail);
      input.current?.focus();
      validateInput(detail);
    };
    window.addEventListener("safelinks:fill", fill);
    return () => window.removeEventListener("safelinks:fill", fill);
  }, []);

  function emitFormState(state: { armed?: boolean; valid?: boolean; invalid?: boolean; launching?: boolean }) {
    window.dispatchEvent(new CustomEvent("safelinks:form-state", { detail: state }));
  }

  function validateInput(val: string) {
    const trimmed = val.trim();
    if (!trimmed) {
      emitFormState({ armed: isFocused, valid: false, invalid: false });
      return;
    }
    const looksLikeUrl =
      trimmed.includes(".") &&
      !trimmed.includes(" ") &&
      (trimmed.startsWith("http://") || trimmed.startsWith("https://") || trimmed.length > 4);
    emitFormState({ armed: true, valid: looksLikeUrl, invalid: !looksLikeUrl });
  }

  function triggerShake() {
    setIsShaking(true);
    setTimeout(() => setIsShaking(false), 450);
  }

  async function startScan() {
    setError("");
    setNetworkError(false);
    emitFormState({ launching: true });
    try {
      const normalized = normalizeUrl(value);
      setLoading(true);
      const response = await scanApi.createScan(normalized);
      navigate(`/scan/${response.scan_id}`);
    } catch (caught) {
      triggerShake();
      emitFormState({ invalid: true, launching: false });
      const message = caught instanceof Error ? caught.message : "Unable to start the scan.";
      if (caught instanceof ApiError && caught.code === "BLOCKED_TARGET") {
        setError("This link points to a private or blocked address and cannot be scanned");
      } else if (caught instanceof ApiError && caught.code === "RATE_LIMITED") {
        setError("Too many scans. Please wait a minute and try again.");
        toast.error("Too many scans. Please wait a minute and try again.");
      } else if (caught instanceof ApiError && caught.code === "NETWORK") {
        setError("Cannot reach the SafeLinks server.");
        setNetworkError(true);
      } else if (caught instanceof ApiError && caught.code === "BAD_RESPONSE") {
        setError(
          `SafeLinks received an unexpected server response.${caught.requestId ? ` Request ID: ${caught.requestId}` : ""}`
        );
      } else {
        setError(message);
      }
    } finally {
      setLoading(false);
    }
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    await startScan();
  }

  async function paste() {
    try {
      const text = await navigator.clipboard.readText();
      setValue(text);
      input.current?.focus();
      validateInput(text);
    } catch {
      toast.error("Paste with Ctrl/Cmd+V");
    }
  }

  return (
    <form onSubmit={submit} className="scan-form" noValidate>
      <div className={cn("input-shell", (error || isShaking) && "has-error", isShaking && "shake")}>
        <LinkIcon aria-hidden="true" className={isFocused ? "input-icon-focus" : ""} />
        <Input
          ref={input}
          value={value}
          onChange={(event) => {
            setValue(event.target.value);
            if (error) setError("");
            validateInput(event.target.value);
          }}
          onFocus={() => {
            setIsFocused(true);
            emitFormState({ armed: true });
          }}
          onBlur={() => {
            setIsFocused(false);
            emitFormState({ armed: false });
          }}
          disabled={loading}
          placeholder={value || isFocused ? "https://example.com/login" : placeholderText}
          aria-invalid={Boolean(error)}
          aria-describedby={error ? "url-error" : undefined}
        />
        <Button type="button" variant="ghost" size="icon" aria-label="Paste a link" onClick={paste}>
          <Clipboard />
        </Button>
      </div>
      <MagneticButton
        type="submit"
        variant="primary"
        size="lg"
        disabled={loading || !value.trim()}
      >
        {loading ? <LoaderCircle className="spin" /> : <Check />}
        {loading ? "Starting scan..." : "Scan link"}
      </MagneticButton>
      {error && (
        <p id="url-error" className="form-error">
          {error}
        </p>
      )}
      {networkError && (
        <Alert danger>
          <span>
            Cannot reach the SafeLinks server. If this app is served over https, the backend must
            also use https.
          </span>
          <Button type="button" onClick={() => void startScan()}>
            Retry
          </Button>
        </Alert>
      )}
    </form>
  );
}
