// Local sign-in (ADR-008 Decision 2). The password is sent once and never kept here; the
// collector checks it (ADR-015 Decision 1).
import { LogIn, ShieldCheck } from "lucide-react";
import { useState, type SubmitEvent } from "react";
import { api, AuditUnavailable, MustWait, NoPassword, Rejected, SignedOut } from "../api/client";

const setCommand = 'sudo "/Library/Application Support/Thadam/bin/thadam-collector" set-password';

function seconds(n: number): string {
  return n < 120 ? `${n} second${n === 1 ? "" : "s"}` : `${Math.ceil(n / 60)} minutes`;
}

export function SignIn({ onSignedIn }: { onSignedIn: () => void }) {
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState<string>();
  const [busy, setBusy] = useState(false);
  const submit = (e: SubmitEvent<HTMLFormElement>) => {
    e.preventDefault();
    setBusy(true);
    setMessage(undefined);
    api.signIn(password).then(
      () => {
        setPassword("");
        onSignedIn();
      },
      (err: unknown) => {
        setBusy(false);
        setMessage(
          err instanceof AuditUnavailable ? err.message
            : err instanceof NoPassword ? "No password is set yet. Set one in Terminal with the command below."
              : err instanceof MustWait ? `Too many wrong passwords. Try again in ${seconds(err.seconds)}.`
                : err instanceof Rejected ? "Enter your password."
                  : err instanceof SignedOut ? "That password is not right."
                    : "Sign-in failed. Try again.",
        );
      },
    );
  };
  return (
    <main className="signin">
      <form className="card pad stack" onSubmit={submit}>
        <div className="row brand">
          <ShieldCheck className="ic big" aria-hidden="true" />
          <div>
            <h1 className="h1">Thadam</h1>
            <p className="sub">AI tool audit · this Mac</p>
          </div>
        </div>
        <label htmlFor="password" className="kl">Password</label>
        <input id="password" className="field plain" type="password" autoComplete="current-password" value={password}
          onChange={(e) => { setPassword(e.target.value); }} required maxLength={256} />
        {message !== undefined && <p className="sub error" role="alert">{message}</p>}
        <button type="submit" className="btn primary" disabled={busy}><LogIn className="ic" aria-hidden="true" />Sign in</button>
        <p className="sub">Set or change the password in Terminal: <code className="mono">{setCommand}</code></p>
      </form>
    </main>
  );
}
