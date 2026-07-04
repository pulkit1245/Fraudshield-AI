// Auth API calls + token lifecycle. Access token lives in memory (api.ts);
// the refresh token is set by the backend as an HttpOnly cookie in production,
// and also returned in the body for local dev. Owner: Member D.
import { api, setAccessToken } from "./api";
import type { AccessToken, TokenPair, UserProfile } from "../types";

const REFRESH_KEY = "fs_refresh"; // dev fallback only (see note in login)

export async function register(
  email: string,
  password: string,
  orgName: string,
): Promise<UserProfile> {
  return api.post<UserProfile>("/auth/register", {
    email,
    password,
    org_name: orgName,
  });
}

export async function login(email: string, password: string): Promise<TokenPair> {
  const tokens = await api.post<TokenPair>("/auth/login", { email, password });
  setAccessToken(tokens.access_token);
  // Dev fallback: persist the refresh token so a page reload can re-auth.
  // In production the refresh token is an HttpOnly cookie and this is a no-op.
  try {
    sessionStorage.setItem(REFRESH_KEY, tokens.refresh_token);
  } catch {
    /* sessionStorage unavailable (SSR / tests) */
  }
  return tokens;
}

export async function refresh(): Promise<string | null> {
  let refreshToken: string | null = null;
  try {
    refreshToken = sessionStorage.getItem(REFRESH_KEY);
  } catch {
    refreshToken = null;
  }
  if (!refreshToken) return null;
  const res = await api.post<AccessToken>("/auth/refresh", {
    refresh_token: refreshToken,
  });
  setAccessToken(res.access_token);
  return res.access_token;
}

export async function me(): Promise<UserProfile> {
  return api.get<UserProfile>("/auth/me");
}

export function logout(): void {
  setAccessToken(null);
  try {
    sessionStorage.removeItem(REFRESH_KEY);
  } catch {
    /* ignore */
  }
}
