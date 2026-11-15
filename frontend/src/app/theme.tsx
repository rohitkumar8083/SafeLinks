import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
type Theme = "light" | "dark" | "system";
const ThemeContext = createContext<{ theme: Theme; setTheme: (theme: Theme) => void }>({ theme: "dark", setTheme: () => undefined });
let fallbackTheme: Theme = "dark";
function storedTheme(): Theme {
  try { const value = localStorage.getItem("safelinks-theme"); return value === "light" || value === "system" ? value : "dark"; } catch { return fallbackTheme; }
}
export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setState] = useState<Theme>(storedTheme);
  useEffect(() => {
    const apply = () => {
      const dark = theme === "dark" || (theme === "system" && matchMedia("(prefers-color-scheme: dark)").matches);
      document.documentElement.classList.toggle("dark", dark);
      document.documentElement.style.colorScheme = dark ? "dark" : "light";
    };
    apply();
    const media = matchMedia("(prefers-color-scheme: dark)");
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [theme]);
  const setTheme = (value: Theme) => { fallbackTheme = value; try { localStorage.setItem("safelinks-theme", value); } catch { /* memory fallback */ } setState(value); };
  return <ThemeContext.Provider value={{ theme, setTheme }}>{children}</ThemeContext.Provider>;
}
export const useTheme = () => useContext(ThemeContext);
