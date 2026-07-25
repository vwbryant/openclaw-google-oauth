import { google } from "googleapis";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import type { OAuth2Client } from "google-auth-library";

export interface AuthConfig {
  credentialsPath: string;
  tokenPath: string;
}

export interface AuthState {
  clientConfigured: boolean;
  connected: boolean;
  status: "platform_setup_required" | "connection_required" | "connected";
}

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
  config: AuthConfig
): Promise<OAuth2Client> {
  const creds = await readCredentials(config.credentialsPath);
  const client = new google.auth.OAuth2(
    creds.client_id,
    creds.client_secret,
    creds.redirect_uris[0]
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

export async function buildAuthUrl(config: AuthConfig): Promise<string> {
  const client = await createOAuthClient(config);
  return client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: SCOPES,
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
  code: string
): Promise<{ tokenPath: string; scopes: string[] }> {
  const client = await createOAuthClient(config);
  const { tokens } = await client.getToken(code);
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

export async function prepareTokenPath(configuredTokenPath: string): Promise<string> {
  const tokenPath = expandHome(configuredTokenPath);
  await mkdir(dirname(tokenPath), { recursive: true, mode: 0o700 });
  return tokenPath;
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
