// One boundary per view and one around the shell (ADR-008 Decision 13; global React rule):
// a failing view shows a plain fallback while the others keep working. The report names
// the area and the error type only: messages can carry row data.
import { Component, type ReactNode } from "react";

interface Props {
  area: string;
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  failed: boolean;
}

export class ErrorBoundary extends Component<Props, State> {
  override state: State = { failed: false };

  static getDerivedStateFromError(): State {
    return { failed: true };
  }

  override componentDidCatch(error: unknown): void {
    const kind = error instanceof Error ? error.name : typeof error;
    console.error(`thadam: ${this.props.area} failed (${kind})`);
  }

  override render(): ReactNode {
    if (!this.state.failed) return this.props.children;
    return (
      this.props.fallback ?? (
        <div className="card fallback" role="alert">
          <h2 className="h2">This view failed to load.</h2>
          <p className="sub">Other views still work. Reload the page to try again.</p>
        </div>
      )
    );
  }
}
