import { useEffect, type ReactNode } from "react";
import { createHashRouter, useLocation, useRouteError } from "react-router";
import { Layout } from "./components/layout";
import { Button, Card } from "./components/ui";
import { About } from "./pages/About";
import { History } from "./pages/History";
import { Home } from "./pages/Home";
import { NotFound } from "./pages/NotFound";
import { Report } from "./pages/Report";
function Title({ title, children }: { title: string; children: ReactNode }) { const location = useLocation(); useEffect(() => { document.title = `${title} | SafeLinks`; }, [title, location]); return children; }
function ErrorPage() { const error = useRouteError(); return <div className="container page"><Card className="empty-state"><h1>Something went wrong</h1><p>{error instanceof Error ? error.message : "An unexpected error interrupted this page."}</p><Button variant="primary" onClick={() => location.reload()}>Try again</Button></Card></div>; }
export const router = createHashRouter([{ path: "/", Component: Layout, ErrorBoundary: ErrorPage, children: [
  { index: true, element: <Title title="Scan"><Home /></Title> },
  { path: "scan/:scanId", element: <Title title="Report"><Report /></Title> },
  { path: "history", element: <Title title="History"><History /></Title> },
  { path: "about", element: <Title title="How it works"><About /></Title> },
  { path: "*", element: <Title title="Page not found"><NotFound /></Title> },
]}]);
