import type { ZodType } from "zod";
import { CONFIG } from "../../config";
import { ApiError } from "./errors";
import { createScanResponseSchema, errorResponseSchema, healthResponseSchema, scanResponseSchema } from "./schemas";
import type { CreateScanResponse, HealthResponse, ScanApi, ScanMode, ScanResponse } from "./types";

const apiBase = `${CONFIG.API_BASE_URL.replace(/\/+$/, "")}/api/v1`;

async function request<T>(path: string, schema: ZodType<T>, options: RequestInit = {}, timeoutMs = 10_000): Promise<T> {
  const controller = new AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${apiBase}${path}`, {
      ...options,
      cache: "no-store",
      headers: { Accept: "application/json", "Content-Type": "application/json", ...options.headers },
      signal: controller.signal,
    });
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new ApiError(response.status, "BAD_RESPONSE", "The server returned an unreadable response.");
    }
    if (!response.ok) {
      const parsedError = errorResponseSchema.safeParse(body);
      if (!parsedError.success) {
        console.error("SafeLinks API error response validation failed", parsedError.error.issues);
        throw new ApiError(response.status, "BAD_RESPONSE", "The server returned an unexpected error response.");
      }
      const { code, message, request_id } = parsedError.data.error;
      throw new ApiError(response.status, code, message, request_id ?? undefined);
    }
    const parsed = schema.safeParse(body);
    if (!parsed.success) {
      console.error("SafeLinks API response validation failed", parsed.error.issues);
      throw new ApiError(response.status, "BAD_RESPONSE", "The server response did not match the expected format.");
    }
    return parsed.data;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    const message = error instanceof DOMException && error.name === "AbortError"
      ? "The request timed out. Please try again."
      : "Could not connect to SafeLinks. Check your connection and try again.";
    throw new ApiError(0, "NETWORK", message);
  } finally {
    globalThis.clearTimeout(timeout);
  }
}

export const realClient: ScanApi = {
  createScan(url: string, mode: ScanMode = "full"): Promise<CreateScanResponse> {
    return request("/scans", createScanResponseSchema, {
      method: "POST",
      body: JSON.stringify({ url, mode }),
    });
  },
  getScan(scanId: string): Promise<ScanResponse> {
    return request(`/scans/${encodeURIComponent(scanId)}`, scanResponseSchema);
  },
  health(): Promise<HealthResponse> {
    return request("/health", healthResponseSchema, {}, 25_000);
  },
};
