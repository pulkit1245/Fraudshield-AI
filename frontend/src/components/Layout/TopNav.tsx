import { useAuth } from "../../context/AuthContext";

export default function TopNav() {
  const { user, logout } = useAuth();

  return (
    <header
      className="h-[60px] flex items-center justify-between px-6 py-3 no-print sticky top-0 z-50"
      style={{
        background: "rgba(255,255,255,0.05)",
        backdropFilter: "blur(20px)",
        borderBottom: "1px solid rgba(255,255,255,0.1)",
      }}
    >
      {/* Left: Active Workspace breadcrumb */}
      <div className="flex items-center gap-4">
        <div className="text-sm font-medium text-[#9A9DA3]">
          Active Workspace
        </div>
      </div>

      {/* Right: user info + logout */}
      <div className="flex items-center gap-4 text-sm">
        {user && (
          <div className="flex items-center gap-3">
            <div className="flex flex-col items-end">
              <span className="text-[#e5e2e3] font-medium leading-none" style={{ fontFamily: "SF Pro Display, system-ui, sans-serif" }}>
                {user.email}
              </span>
              <span className="text-[9px] text-[#9A9DA3] font-sans tracking-widest uppercase mt-1">
                {user.role}
              </span>
            </div>
            <div
              className="w-8 h-8 rounded-full flex items-center justify-center text-[#e5e2e3] text-sm font-bold"
              style={{ border: "1px solid rgba(255,255,255,0.2)" }}
            >
              {user.email.charAt(0).toUpperCase()}
            </div>
          </div>
        )}
        <div className="w-px h-6 mx-2" style={{ background: "rgba(255,255,255,0.1)" }} />
        <button
          onClick={logout}
          className="text-[#9A9DA3] hover:text-[#e5e2e3] transition-colors duration-200"
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
