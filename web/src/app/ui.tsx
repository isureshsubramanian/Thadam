// Small shared pieces: icon buttons (tooltip + aria-label, global UI rule), pills, states.
import type { ReactNode } from "react";
import type { Severity } from "../api/schemas";
import { cap, words } from "./format";

interface IconButtonProps {
  label: string;
  onClick: () => void;
  children: ReactNode;
  disabled?: boolean;
}

/** An icon-only button: the label is both its tooltip and its accessible name. */
export function IconButton({ label, onClick, children, disabled }: IconButtonProps) {
  return (
    <button type="button" className="ibtn" title={label} aria-label={label} onClick={onClick} disabled={disabled ?? false}>
      {children}
    </button>
  );
}

export function SeverityPill({ severity }: { severity: Severity }) {
  return <span className={`pill ${severity}`}>{cap(severity)}</span>;
}

export function FlagPills({ flags }: { flags: readonly string[] }) {
  return (
    <>
      {flags.map((f) => (
        <span key={f} className={`pill ${f === "tool_internal" || f === "rolled_up" ? "" : "flag"}`}>
          {words(f)}
        </span>
      ))}
    </>
  );
}

export function Loading() {
  return <p className="sub" aria-live="polite">Loading…</p>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="sub empty">{children}</p>;
}

export function PageHead({ title, sub, children }: { title: string; sub?: ReactNode; children?: ReactNode }) {
  return (
    <div className="pagehead">
      <div>
        <h1 className="h1">{title}</h1>
        {sub !== undefined && <p className="sub">{sub}</p>}
      </div>
      {children !== undefined && <div className="row">{children}</div>}
    </div>
  );
}
