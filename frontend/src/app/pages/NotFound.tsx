import { SearchX } from "lucide-react";
import { Link } from "react-router";
import { Card } from "../components/ui";

export function NotFound() {
  return (
    <div className="container page">
      <Card className="empty-state">
        <SearchX className="empty-floating" />
        <p className="eyebrow">404 · LOST LINK</p>
        <h1>This page slipped away</h1>
        <p>The page may have moved, or the report may have expired.</p>
        <Link className="button button-primary button-lg" to="/">
          Scan a link
        </Link>
      </Card>
    </div>
  );
}
