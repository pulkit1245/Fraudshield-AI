import { Link, useLocation } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";

export default function Navbar() {
  const { user, logout } = useAuth();
  const { pathname } = useLocation();
  const link = (to: string, label: string) => (
    <Link
      to={to}
      className={`px-3 py-1.5 rounded-md text-sm font-medium ${
        pathname === to ? "bg-primary-blue/10 text-primary-blue" : "text-text-muted hover:bg-background-surface"
      }`}
    >
      {label}
    </Link>
  );

  return (
    <header className="no-print flex items-center justify-between border-b border-border bg-background-elevated px-6 py-3">
      <div className="flex items-center gap-6">
        <span className="text-base font-extrabold text-text-bright">FraudShield AI</span>
        <nav className="flex items-center gap-1">
          {link("/", "Dashboard")}
          {link("/clusters", "Clusters")}
        </nav>
      </div>
      <div className="flex items-center gap-3 text-sm">
        {user && (
          <span className="text-text-muted">
            {user.email} · <span className="font-semibold">{user.role}</span>
          </span>
        )}
        <button
          onClick={logout}
          className="rounded-md border border-border px-3 py-1.5 text-text hover:bg-background-surface"
        >
          Sign out
        </button>
      </div>
    </header>
  );
}
