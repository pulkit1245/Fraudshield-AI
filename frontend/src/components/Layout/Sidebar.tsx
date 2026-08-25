import { Link, useLocation } from "react-router-dom";

export default function Sidebar() {
  const { pathname } = useLocation();

  const navItems = [
    { to: "/", label: "Dashboard", svg: <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z" /> },
    { to: "/clusters", label: "Threat Clusters", svg: <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 13.5h3.86a2.25 2.25 0 012.012 1.244l.256.512a2.25 2.25 0 002.013 1.244h3.218a2.25 2.25 0 002.013-1.244l.256-.512a2.25 2.25 0 012.013-1.244h3.859m-19.5.338V18a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18v-4.162c0-.224-.034-.447-.1-.661L19.24 5.338a2.25 2.25 0 00-2.15-1.588H6.911a2.25 2.25 0 00-2.15 1.588L2.35 13.177a2.25 2.25 0 00-.1.661z" /> },
  ];

  return (
    <aside className="w-64 border-r border-border bg-background flex flex-col no-print shrink-0">
      <div className="h-16 flex items-center px-6 border-b border-border">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded bg-primary-cyan/10 border border-primary-cyan/30 flex items-center justify-center">
            <div className="w-2 h-2 rounded-full bg-primary-cyan shadow-[0_0_8px_rgba(94,231,255,0.8)]" />
          </div>
          <span className="text-sm font-bold tracking-widest text-text-bright uppercase">
            FraudShield
            <span className="text-primary-blue ml-1">AI</span>
          </span>
        </div>
      </div>
      
      <div className="flex-1 overflow-y-auto py-6 px-3 space-y-1">
        <div className="px-3 mb-2 text-xs font-semibold text-text-muted uppercase tracking-widest">
          Analysis
        </div>
        {navItems.map((item) => {
          const isActive = pathname === item.to || (item.to !== "/" && pathname.startsWith(item.to));
          return (
            <Link
              key={item.to}
              to={item.to}
              className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-all duration-200 ${
                isActive 
                  ? "bg-primary-blue/10 text-primary-cyan border border-primary-blue/20" 
                  : "text-text hover:bg-background-elevated hover:text-text-bright border border-transparent"
              }`}
            >
              <svg className={`w-4 h-4 ${isActive ? 'text-primary-cyan' : 'text-text-muted'}`} fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                {item.svg}
              </svg>
              {item.label}
            </Link>
          );
        })}
      </div>
      
      <div className="p-4 border-t border-border">
        <div className="flex items-center gap-3 px-3 py-2 rounded-md bg-background-elevated/50 border border-border">
          <div className="w-2 h-2 rounded-full bg-status-success animate-pulse" />
          <span className="text-xs font-medium text-text-muted font-mono uppercase">System Online</span>
        </div>
      </div>
    </aside>
  );
}
