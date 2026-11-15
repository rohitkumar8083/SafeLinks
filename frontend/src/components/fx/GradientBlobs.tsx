import { useCapabilities } from "../../lib/motion/useCapabilities";

export function GradientBlobs() {
  const { reducedMotion } = useCapabilities();
  if (reducedMotion) return null;

  return (
    <div
      className="fx-blobs-container"
      aria-hidden="true"
      style={{
        position: "fixed",
        inset: 0,
        overflow: "hidden",
        pointerEvents: "none",
        zIndex: 0,
        filter: "blur(80px)",
        opacity: 0.55,
      }}
    >
      <div
        className="fx-blob fx-blob-1"
        style={{
          position: "absolute",
          top: "8%",
          left: "12%",
          width: "35rem",
          height: "35rem",
          borderRadius: "50%",
          background: "radial-gradient(circle, hsl(173 80% 40% / 0.18) 0%, transparent 70%)",
        }}
      />
      <div
        className="fx-blob fx-blob-2"
        style={{
          position: "absolute",
          top: "40%",
          right: "10%",
          width: "32rem",
          height: "32rem",
          borderRadius: "50%",
          background: "radial-gradient(circle, hsl(262 83% 66% / 0.16) 0%, transparent 70%)",
        }}
      />
      <div
        className="fx-blob fx-blob-3"
        style={{
          position: "absolute",
          bottom: "5%",
          left: "25%",
          width: "28rem",
          height: "28rem",
          borderRadius: "50%",
          background: "radial-gradient(circle, hsl(173 80% 40% / 0.12) 0%, transparent 70%)",
        }}
      />
    </div>
  );
}
