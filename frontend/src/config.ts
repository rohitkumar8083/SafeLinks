type PublicEnv = {
  VITE_USE_MOCK?: string;
  VITE_API_BASE_URL?: string;
};

let env: PublicEnv | undefined;
try {
  env = import.meta.env as PublicEnv;
} catch {
  env = undefined;
}

const mockOverride = env?.VITE_USE_MOCK?.trim().toLowerCase();

// To connect the real backend set USE_MOCK to false and API_BASE_URL to the deployed backend URL without a trailing slash.
export const CONFIG = {
  USE_MOCK: mockOverride === undefined ? true : mockOverride === "true" || mockOverride === "1",
  API_BASE_URL: env?.VITE_API_BASE_URL?.trim() || "http://localhost:8000",
} as const;

export const isMockMode = CONFIG.USE_MOCK;
