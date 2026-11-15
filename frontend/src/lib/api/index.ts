import { CONFIG } from "../../config";
import { realClient } from "./client";
import { ApiError } from "./errors";
import { mockClient } from "./mock";
import type { ScanApi } from "./types";

export const scanApi: ScanApi = CONFIG.USE_MOCK ? mockClient : realClient;
export { ApiError };
export * from "./types";
