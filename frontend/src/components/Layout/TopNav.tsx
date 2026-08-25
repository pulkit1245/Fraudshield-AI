import { useAuth } from "../../context/AuthContext";

export default function TopNav() {
  const { user, logout } = useAuth();

  return (
    <header className="h-16 flex items-center justify-between border-b border-border bg-background/80 backdrop-blur-md px-6 py-3 no-print sticky top-0 z-50">
      <div className="flex items-center gap-4">
        {/* Placeholder for future breadcrumbs or context indicator */}
        <div className="text-sm font-medium text-text-muted">
          Active Workspace
        </div>
      </div>
      <div className="flex items-center gap-4 text-sm">
        {user && (
          <div className="flex items-center gap-3">
            <div className="flex flex-col items-end">
              <span className="text-text-bright font-medium leading-none">{user.email}</span>
              <span className="text-xs text-primary-cyan uppercase tracking-wider mt-1">{user.role}</span>
            </div>
            <div className="w-8 h-8 rounded-full bg-background-elevated border border-border flex items-center justify-center text-text-bright">
              {user.email.charAt(0).toUpperCase()}
            </div>
          </div>
        )}
        <div className="w-px h-6 bg-border mx-2" />
        <button
          onClick={logout}
          className="text-text-muted hover:text-text-bright transition-colors duration-200"
          title="Sign out"
        >
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15M12 9l-3 3m0 0l3 3m-3-3h12.75" />
          </svg>
        </button>
      </div>
    </header>
  );
}
