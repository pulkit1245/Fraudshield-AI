import { Navigate, Outlet, Route, Routes } from "react-router-dom";
import Sidebar from "./components/Layout/Sidebar";
import TopNav from "./components/Layout/TopNav";
import { RequireAuth } from "./context/AuthContext";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import SubmissionDetailPage from "./pages/SubmissionDetailPage";
import ClustersPage from "./pages/ClustersPage";

function Layout() {
  return (
    <div className="flex h-screen w-full overflow-hidden bg-background text-text selection:bg-primary-blue/30 selection:text-text-bright">
      <Sidebar />
      <div className="flex flex-col flex-1 overflow-hidden relative">
        <TopNav />
        <main className="flex-1 overflow-y-auto bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-background-surface via-background to-background p-6">
          <div className="mx-auto max-w-7xl animate-in fade-in duration-500">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route path="/" element={<DashboardPage />} />
        <Route path="/submissions/:id" element={<SubmissionDetailPage />} />
        <Route path="/clusters" element={<ClustersPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
