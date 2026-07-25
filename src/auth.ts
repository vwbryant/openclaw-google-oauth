import { google } from "googleapis";
import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import { CodeChallengeMethod, type OAuth2Client } from "google-auth-library";

export interface AuthConfig {
  credentialsPath: string;
  tokenPath: string;
}

export interface AuthState {
  clientConfigured: boolean;
  connected: boolean;
  status: "platform_setup_required" | "connection_required" | "connected";
}

interface PendingAuthorization {
  state: string;
  redirectUri: string;
  codeVerifier: string;
  expiresAt: string;
}

const AUTHORIZATION_TTL_MS = 10 * 60 * 1000;

export const SCOPES = [
  "https://www.googleapis.com/auth/gmail.modify",
  "https://www.googleapis.com/auth/gmail.send",
  "https://www.googleapis.com/auth/calendar.events",
  // Full Drive scope (not drive.file) so the agent can see folders + files
  // shared with the authorized account, not only files it created itself.
  // Per-file ACLs still apply: shared-as-reader is read-only,
  // shared-as-writer is read+write, files the app owns are full access.
  "https://www.googleapis.com/auth/drive",
  "https://www.googleapis.com/auth/documents",
  "https://www.googleapis.com/auth/spreadsheets",
  "https://www.googleapis.com/auth/presentations",
];

export function expandHome(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return resolve(homedir(), p.slice(2));
  return p;
}

interface InstalledCredentials {
  installed?: {
    client_id: string;
    client_secret: string;
    redirect_uris: string[];
  };
  web?: {
    client_id: string;
    client_secret: string;
    redirect_uris: string[];
  };
}

async function readCredentials(credentialsPath: string) {
  const raw = await readFile(expandHome(credentialsPath), "utf8");
  const parsed = JSON.parse(raw) as InstalledCredentials;
  const creds = parsed.installed ?? parsed.web;
  if (!creds) {
    throw new Error(
      `Credentials file at ${credentialsPath} is missing "installed" or "web" block`
    );
  }
  return creds;
}

export async function createOAuthClient(
  config: AuthConfig,
  redirectUri?: string
): Promise<OAuth2Client> {
  const creds = await readCredentials(config.credentialsPath);
  const client = new google.auth.OAuth2(
    creds.client_id,
    creds.client_secret,
    redirectUri ?? creds.redirect_uris[0]
  );

  try {
    const tokenRaw = await readFile(expandHome(config.tokenPath), "utf8");
    client.setCredentials(JSON.parse(tokenRaw));
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      throw err;
    }
  }

  return client;
}

export async function buildAuthUrl(
  config: AuthConfig,
  options: {
    redirectUri?: string;
    state?: string;
    codeChallenge?: string;
  } = {}
): Promise<string> {
  const client = await createOAuthClient(config, options.redirectUri);
  return client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: SCOPES,
    ...(options.state ? { state: options.state } : {}),
    ...(options.codeChallenge
      ? {
          code_challenge: options.codeChallenge,
          code_challenge_method: CodeChallengeMethod.S256
        }
      : {})
  });
}

export async function beginAuthorization(
  config: AuthConfig,
  options: { redirectUri: string; state: string },
  now = new Date()
): Promise<string> {
  assertCallbackUri(options.redirectUri);
  if (!options.state || options.state.length > 4096) {
    throw new Error("OAuth state is required and must be 4096 characters or fewer.");
  }

  const codeVerifier = randomBytes(32).toString("base64url");
  const codeChallenge = createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
  const pending: PendingAuthorization = {
    state: options.state,
    redirectUri: options.redirectUri,
    codeVerifier,
    expiresAt: new Date(now.getTime() + AUTHORIZATION_TTL_MS).toISOString()
  };
  const pendingPath = await preparePendingAuthorizationPath(config.tokenPath);
  await writeFile(pendingPath, JSON.stringify(pending), { mode: 0o600 });

  return buildAuthUrl(config, {
    redirectUri: options.redirectUri,
    state: options.state,
    codeChallenge
  });
}

export async function inspectAuthState(config: AuthConfig): Promise<AuthState> {
  try {
    await readCredentials(config.credentialsPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return {
        clientConfigured: false,
        connected: false,
        status: "platform_setup_required",
      };
    }
    throw error;
  }

  try {
    const tokenRaw = await readFile(expandHome(config.tokenPath), "utf8");
    const token = JSON.parse(tokenRaw) as { refresh_token?: unknown };
    const connected =
      typeof token.refresh_token === "string" && token.refresh_token.length > 0;

    return {
      clientConfigured: true,
      connected,
      status: connected ? "connected" : "connection_required",
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return {
        clientConfigured: true,
        connected: false,
        status: "connection_required",
      };
    }
    throw error;
  }
}

export async function exchangeCode(
  config: AuthConfig,
  code: string,
  options: {
    redirectUri?: string;
    codeVerifier?: string;
  } = {}
): Promise<{ tokenPath: string; scopes: string[] }> {
  const client = await createOAuthClient(config, options.redirectUri);
  const { tokens } = options.codeVerifier
    ? await client.getToken({ code, codeVerifier: options.codeVerifier })
    : await client.getToken(code);
  if (!tokens.refresh_token) {
    throw new Error(
      "No refresh_token returned. Revoke prior consent at " +
        "https://myaccount.google.com/permissions then retry with prompt=consent."
    );
  }
  const tokenPath = await prepareTokenPath(config.tokenPath);
  await writeFile(tokenPath, JSON.stringify(tokens, null, 2), { mode: 0o600 });
  return {
    tokenPath,
    scopes: (tokens.scope ?? "").split(" ").filter(Boolean),
  };
}

export async function exchangePendingAuthorization(
  config: AuthConfig,
  options: { code: string; state: string },
  now = new Date()
): Promise<{ tokenPath: string; scopes: string[] }> {
  const pendingPath = pendingAuthorizationPath(config.tokenPath);
  const pending = JSON.parse(
    await readFile(pendingPath, "utf8")
  ) as Partial<PendingAuthorization>;

  if (
    typeof pending.state !== "string" ||
    typeof pending.redirectUri !== "string" ||
    typeof pending.codeVerifier !== "string" ||
    typeof pending.expiresAt !== "string"
  ) {
    throw new Error("Pending Google authorization is invalid. Start the connection again.");
  }
  if (pending.state !== options.state) {
    throw new Error("Google authorization state does not match. Start the connection again.");
  }
  if (Date.parse(pending.expiresAt) <= now.getTime()) {
    await rm(pendingPath, { force: true });
    throw new Error("Google authorization expired. Start the connection again.");
  }

  await rm(pendingPath, { force: true });
  return exchangeCode(config, options.code, {
    redirectUri: pending.redirectUri,
    codeVerifier: pending.codeVerifier
  });
}

export async function prepareTokenPath(configuredTokenPath: string): Promise<string> {
  const tokenPath = expandHome(configuredTokenPath);
  await mkdir(dirname(tokenPath), { recursive: true, mode: 0o700 });
  return tokenPath;
}

async function preparePendingAuthorizationPath(configuredTokenPath: string): Promise<string> {
  const path = pendingAuthorizationPath(configuredTokenPath);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  return path;
}

function pendingAuthorizationPath(configuredTokenPath: string): string {
  return `${expandHome(configuredTokenPath)}.oauth-pending.json`;
}

function assertCallbackUri(value: string): void {
  const url = new URL(value);
  const isLoopback =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "::1";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopback)) {
    throw new Error("OAuth callback must use HTTPS, except for local loopback development.");
  }
  if (url.username || url.password || url.hash) {
    throw new Error("OAuth callback URL contains unsupported components.");
  }
}

export async function withTimeout<T>(
  promise: Promise<T>,
  label: string,
  ms = 30000
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new Error(`${label} timed out after ${ms}ms`)),
      ms
    );
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
