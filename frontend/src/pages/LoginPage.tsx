// Login + register page. On success the AuthContext holds the access token in
// memory and we redirect to the originally-requested route. Owner: Member D.
import { useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuth, useLoginMutation } from "../hooks/useAuth";
import { register as registerApi } from "../services/auth";
import { ApiRequestError } from "../services/api";

export default function LoginPage() {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [orgName, setOrgName] = useState("");
  const [error, setError] = useState<string | null>(null);

  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuth();
  const loginMutation = useLoginMutation();
  const from = (location.state as { from?: { pathname: string } } | null)?.from?.pathname ?? "/";

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      if (mode === "register") {
        await registerApi(email, password, orgName);
        await login(email, password);
      } else {
        await loginMutation.mutateAsync({ email, password });
      }
      navigate(from, { replace: true });
    } catch (err: any) {
      if (err?.name === "ApiRequestError") {
        const apiErr = err as ApiRequestError;
        setError(
          apiErr.status === 401
            ? "Invalid email or password."
            : apiErr.status === 429
              ? "Too many attempts — please wait a minute."
              : apiErr.message,
        );
      } else {
        setError("Something went wrong. Try again.");
      }
    }
  }

  const busy = loginMutation.isPending;

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm rounded-2xl border border-gray-200 bg-white p-8 shadow-sm">
        <h1 className="text-xl font-extrabold text-gray-900">FraudShield AI</h1>
        <p className="mb-6 text-sm text-gray-500">
          {mode === "login" ? "Sign in to the analyst console" : "Create an analyst account"}
        </p>

        <form onSubmit={onSubmit} className="space-y-3">
          <input
            type="email" required placeholder="Email" value={email}
            onChange={(e) => setEmail(e.target.value)} aria-label="Email"
            className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm"
          />
          <input
            type="password" required placeholder="Password (min 8 chars)" value={password}
            onChange={(e) => setPassword(e.target.value)} aria-label="Password" minLength={8}
            className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm"
          />
          {mode === "register" && (
            <input
              type="text" required placeholder="Organization (bank / NBFC)" value={orgName}
              onChange={(e) => setOrgName(e.target.value)} aria-label="Organization"
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm"
            />
          )}

          {error && <div className="rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">{error}</div>}

          <button
            type="submit" disabled={busy}
            className="w-full rounded-md bg-indigo-600 px-3 py-2 text-sm font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
          >
            {busy ? "Signing in…" : mode === "login" ? "Sign in" : "Create account"}
          </button>
        </form>

        <button
          onClick={() => { setMode(mode === "login" ? "register" : "login"); setError(null); }}
          className="mt-4 text-xs text-indigo-600 hover:underline"
        >
          {mode === "login" ? "Need an account? Register" : "Have an account? Sign in"}
        </button>
      </div>
    </div>
  );
}
