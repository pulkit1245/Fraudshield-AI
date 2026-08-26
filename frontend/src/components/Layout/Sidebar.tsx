import { Link, useLocation } from "react-router-dom";

export default function Sidebar() {
  const { pathname } = useLocation();

  const navItems = [
    { to: "/", label: "Dashboard", svg: <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z" /> },
    { to: "/clusters", label: "Threat Clusters", svg: <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 13.5h3.86a2.25 2.25 0 012.012 1.244l.256.512a2.25 2.25 0 002.013 1.244h3.218a2.25 2.25 0 002.013-1.244l.256-.512a2.25 2.25 0 012.013-1.244h3.859m-19.5.338V18a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18v-4.162c0-.224-.034-.447-.1-.661L19.24 5.338a2.25 2.25 0 00-2.15-1.588H6.911a2.25 2.25 0 00-2.15 1.588L2.35 13.177a2.25 2.25 0 00-.1.661z" /> },
  ];

  return (
    <aside
      className="w-64 flex flex-col no-print shrink-0"
      style={{
        background: "rgba(13,14,15,0.80)",
        backdropFilter: "blur(20px)",
        borderRight: "1px solid rgba(255,255,255,0.1)",
      }}
    >
      {/* Logo area */}
      <div className="p-6" style={{ borderBottom: "1px solid rgba(255,255,255,0.1)" }}>
        <div className="flex items-center gap-3">
          <div
            className="w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold text-[#e5e2e3]"
            style={{ border: "1px solid rgba(255,255,255,0.2)" }}
          >
            F
          </div>
          <span className="font-bold tracking-tight text-[#e5e2e3]" style={{ fontFamily: "SF Pro Display, system-ui, sans-serif" }}>
            FraudShield
            <span className="text-[#bec2ff] ml-1">AI</span>
          </span>
        </div>
      </div>

      {/* Nav section */}
      <div className="flex-1 overflow-y-auto py-4 px-0">
        {/* Section label */}
        <div
          className="px-3 mb-2 font-sans uppercase tracking-[0.2em] text-[#9A9DA3]/60 pb-2"
          style={{ fontSize: "9px", borderBottom: "1px solid rgba(255,255,255,0.1)" }}
        >
          Analysis
        </div>

        <div className="space-y-0.5 px-0">
          {navItems.map((item) => {
            const isActive = pathname === item.to || (item.to !== "/" && pathname.startsWith(item.to));
            return (
              <Link
                key={item.to}
                to={item.to}
                className={`flex items-center gap-3 px-3 py-2 text-sm font-medium transition-all duration-200 ${
                  isActive
                    ? "bg-white/5 border-l-2 border-[#5E6BFF] text-[#bec2ff]"
                    : "text-[#9A9DA3] hover:bg-white/5 hover:text-[#e5e2e3] border-l-2 border-transparent"
                }`}
                style={{ minHeight: "40px" }}
              >
                <svg
                  className={`w-4 h-4 shrink-0 ${isActive ? "text-[#bec2ff]" : "text-[#9A9DA3]"}`}
                  fill="none"
                  viewBox="0 0 24 24"
                  strokeWidth={1.5}
                  stroke="currentColor"
                >
                  {item.svg}
                </svg>
                {item.label}
              </Link>
            );
          })}
        </div>
      </div>

      {/* System status bottom */}
      <div className="p-4" style={{ borderTop: "1px solid rgba(255,255,255,0.1)" }}>
        <div className="flex items-center gap-3 px-3 py-2">
          <div
            className="w-1.5 h-1.5 rounded-full bg-[#50d8e9]"
            style={{ boxShadow: "0 0 8px rgba(80,216,233,0.5)" }}
          />
          <span className="font-sans text-[#9A9DA3] tracking-widest uppercase" style={{ fontSize: "10px" }}>
            System Online
          </span>
        </div>
      </div>
    </aside>
  );
}
