// Typed fetch client. Injects the bearer token, unwraps JSON, and normalizes the
// backend error envelope { error: { code, message, request_id } } into ApiRequestError.
// Owner: Member D.
import type { ApiError } from "../types";

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";
const PREFIX = "/api/v1";

// In-memory access token (never localStorage — matches the auth design in §1).
let accessToken: string | null = null;
export function setAccessToken(token: string | null): void {
  accessToken = token;
}
export function getAccessToken(): string | null {
  return accessToken;
}

export class ApiRequestError extends Error {
  status: number;
  code: string;
  requestId?: string;
  constructor(status: number, code: string, message: string, requestId?: string) {
    super(message);
    this.name = "ApiRequestError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  auth?: boolean;
  raw?: boolean; // body is FormData / not JSON-encoded
  signal?: AbortSignal;
}

export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const { method = "GET", body, auth = true, raw = false, signal } = opts;
  const headers: Record<string, string> = {};
  if (auth && accessToken) headers["Authorization"] = `Bearer ${accessToken}`;

  let payload: BodyInit | undefined;
  if (body !== undefined) {
    if (raw) {
      payload = body as BodyInit;
    } else {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(body);
    }
  }

  const res = await fetch(`${BASE_URL}${PREFIX}${path}`, {
    method,
    headers,
    body: payload,
    signal,
  });

  if (res.status === 204) return undefined as T;

  const text = await res.text();
  const data = text ? JSON.parse(text) : undefined;

  if (!res.ok) {
    const err = (data as ApiError)?.error;
    throw new ApiRequestError(
      res.status,
      err?.code ?? "error",
      typeof err?.message === "string" ? err.message : res.statusText,
      err?.request_id,
    );
  }
  return data as T;
}

export const api = {
  get: <T>(path: string, signal?: AbortSignal) => request<T>(path, { method: "GET", signal }),
  post: <T>(path: string, body?: unknown) => request<T>(path, { method: "POST", body }),
  patch: <T>(path: string, body?: unknown) => request<T>(path, { method: "PATCH", body }),
  del: <T>(path: string) => request<T>(path, { method: "DELETE" }),
  upload: <T>(path: string, form: FormData) =>
    request<T>(path, { method: "POST", body: form, raw: true }),
};

export const API_BASE_URL = BASE_URL;
