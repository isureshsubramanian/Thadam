// Local sign-in (ADR-008 Decision 2). The password is sent once and never kept here.
import { LogIn, ShieldCheck } from "lucide-react";
import { useState, type SubmitEvent } from "react";
import { api, ApiFailed, Rejected } from "../api/client";

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
          err instanceof ApiFailed && err.message.includes("429")
            ? "Too many attempts. Wait a minute and try again."
            : err instanceof Rejected
              ? "Enter your password."
              : "That password is not right.",
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
        <p className="sub">Set the password with <code className="mono">thadam-api set-password</code>.</p>
      </form>
    </main>
  );
}
