import { Link, useLocation } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";

export default function Navbar() {
  const { user, logout } = useAuth();
  const { pathname } = useLocation();
  const link = (to: string, label: string) => (
    <Link
      to={to}
      className={`px-3 py-1.5 rounded-md text-sm font-medium ${
        pathname === to ? "bg-indigo-100 text-indigo-800" : "text-gray-600 hover:bg-gray-100"
      }`}
    >
      {label}
    </Link>
  );

  return (
    <header className="no-print flex items-center justify-between border-b border-gray-200 bg-white px-6 py-3">
      <div className="flex items-center gap-6">
        <span className="text-base font-extrabold text-gray-900">FraudShield AI</span>
        <nav className="flex items-center gap-1">
          {link("/", "Dashboard")}
          {link("/clusters", "Clusters")}
        </nav>
      </div>
      <div className="flex items-center gap-3 text-sm">
        {user && (
          <span className="text-gray-500">
            {user.email} · <span className="font-semibold">{user.role}</span>
          </span>
        )}
        <button
          onClick={logout}
          className="rounded-md border border-gray-300 px-3 py-1.5 text-gray-700 hover:bg-gray-50"
        >
          Sign out
        </button>
      </div>
    </header>
  );
}
