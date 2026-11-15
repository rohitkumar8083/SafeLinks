import { forwardRef, type ButtonHTMLAttributes, type HTMLAttributes, type InputHTMLAttributes, type ReactNode } from "react";
import { X } from "lucide-react";

const cn = (...values: Array<string | false | null | undefined>) => values.filter(Boolean).join(" ");

export const Button = forwardRef<HTMLButtonElement, ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "ghost" | "danger"; size?: "default" | "icon" | "lg" }>(
  ({ className, variant = "secondary", size = "default", ...props }, ref) => <button ref={ref} className={cn("button", `button-${variant}`, `button-${size}`, className)} {...props} />,
);
Button.displayName = "Button";
export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(({ className, style, ...props }, ref) => <input ref={ref} className={cn("input", className)} style={{ outline: "none", boxShadow: "none", border: "none", ...style }} {...props} />);
Input.displayName = "Input";
export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) { return <div className={cn("glass-card", className)} {...props} />; }
export function Badge({ children, tone = "neutral", className }: { children: ReactNode; tone?: string; className?: string }) { return <span className={cn("badge", `tone-${tone}`, className)}>{children}</span>; }
export function Skeleton({ className }: { className?: string }) { return <div className={cn("skeleton", className)} aria-hidden="true" />; }
export function Progress({ value, className }: { value: number; className?: string }) { return <div className="progress-track" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={value}><div className={cn("progress-value", className)} style={{ width: `${value}%` }} /></div>; }
export function Tooltip({ children, text }: { children: ReactNode; text: string }) { return <span className="tooltip-wrap" tabIndex={0}>{children}<span className="tooltip-text" role="tooltip">{text}</span></span>; }
export function Alert({ children, danger = false }: { children: ReactNode; danger?: boolean }) { return <div role="alert" className={cn("alert", danger && "alert-danger")}>{children}</div>; }
export function Modal({ open, onClose, title, children }: { open: boolean; onClose: () => void; title: string; children: ReactNode }) {
  if (!open) return null;
  return <div className="modal-backdrop" role="presentation" onMouseDown={onClose}><div className="modal" role="dialog" aria-modal="true" aria-labelledby="dialog-title" onMouseDown={(event) => event.stopPropagation()}><div className="row-between"><h2 id="dialog-title">{title}</h2><Button variant="ghost" size="icon" onClick={onClose} aria-label="Close dialog"><X /></Button></div>{children}</div></div>;
}
export { cn };
