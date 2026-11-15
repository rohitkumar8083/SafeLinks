import { RouterProvider } from "react-router";
import { Toaster } from "sonner";
import { router } from "./routes";
import { ThemeProvider } from "./theme";
export default function App() { return <ThemeProvider><RouterProvider router={router} /><Toaster richColors position="bottom-right" /></ThemeProvider>; }
