import React from "react";
import { createRoot } from "react-dom/client";
import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
  useSearchParams,
} from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { authClient } from "./auth";
import { DataProvider } from "./data";
import { Loading, EmptyState } from "./ui";
import { WorkspaceShell } from "./workspace";
import { ResetPassword } from "./auth-panel";
import "./styles.css";
const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 15_000, retry: 1 } },
});
class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { failed: boolean }
> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    return this.state.failed ? (
      <div className="fatal-error">
        <h1>Something didn’t load correctly.</h1>
        <p>Your saved workspace is safe. Reload to try again.</p>
        <button
          type="button"
          className="button primary"
          onClick={() => window.location.reload()}
        >
          Reload Palisade
        </button>
      </div>
    ) : (
      this.props.children
    );
  }
}
function ChecklistApp() {
  const { data: session, isPending, error, refetch } = authClient.useSession();
  const [params] = useSearchParams();
  if (isPending && !params.has("demo")) return <Loading />;
  if (error && !session && !params.has("demo")) {
    return (
      <main className="session-error" id="main-content">
        <EmptyState
          title="Couldn’t check your session"
          description="We couldn’t connect to your account. Try again to open your checklist."
          action={
            <button
              type="button"
              className="button primary"
              onClick={() => refetch()}
            >
              Try again
            </button>
          }
        />
      </main>
    );
  }
  const demo = params.has("demo") || !session;
  const userId = demo ? "demo" : session.user.id;
  return (
    <DataProvider key={userId} userId={userId}>
      <WorkspaceShell />
    </DataProvider>
  );
}
function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <a className="skip-link" href="#main-content">
            Skip to checklist
          </a>
          <Routes>
            <Route path="/" element={<ChecklistApp />} />
            <Route path="/reset-password" element={<ResetPassword />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
