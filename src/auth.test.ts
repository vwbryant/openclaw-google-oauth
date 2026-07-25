import { describe, it, expect } from "vitest";
import { homedir } from "node:os";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  beginAuthorization,
  expandHome,
  inspectAuthState,
  prepareTokenPath,
  SCOPES
} from "./auth.js";

describe("expandHome", () => {
  it("returns homedir for '~'", () => {
    expect(expandHome("~")).toBe(homedir());
  });

  it("expands '~/' prefix", () => {
    expect(expandHome("~/foo/bar")).toBe(`${homedir()}/foo/bar`);
  });

  it("does not expand mid-path tildes", () => {
    expect(expandHome("/etc/~/foo")).toBe("/etc/~/foo");
  });

  it("passes absolute paths through unchanged", () => {
    expect(expandHome("/var/log/app.log")).toBe("/var/log/app.log");
  });

  it("passes relative paths through unchanged", () => {
    expect(expandHome("./relative/path")).toBe("./relative/path");
  });
});

describe("SCOPES", () => {
  it("includes scopes for all six Workspace APIs", () => {
    const families = [
      "gmail",
      "calendar",
      "drive",
      "documents",
      "spreadsheets",
      "presentations",
    ];
    for (const family of families) {
      expect(
        SCOPES.some((s) => s.includes(family)),
        `no scope for ${family}`
      ).toBe(true);
    }
  });

  it("uses Google's HTTPS scope URLs", () => {
    for (const scope of SCOPES) {
      expect(scope).toMatch(/^https:\/\/www\.googleapis\.com\/auth\//);
    }
  });

  it("requests gmail.modify (read+label) instead of gmail.readonly", () => {
    expect(SCOPES).toContain("https://www.googleapis.com/auth/gmail.modify");
    expect(SCOPES).not.toContain("https://www.googleapis.com/auth/gmail.readonly");
  });

  it("requests full drive scope (so shared folders/files are visible)", () => {
    expect(SCOPES).toContain("https://www.googleapis.com/auth/drive");
    // drive.file is intentionally NOT requested — it only lets the app see
    // files it created itself, not files merely shared with the account.
    // That broke the "sharer controls access via Drive ACLs" mental model.
    expect(SCOPES).not.toContain("https://www.googleapis.com/auth/drive.file");
  });
});

describe("inspectAuthState", () => {
  it("reports platform, customer, and connected setup states without returning secrets", async () => {
    const directory = await mkdtemp(join(tmpdir(), "google-auth-state-"));
    const credentialsPath = join(directory, "credentials.json");
    const tokenPath = join(directory, "token.json");

    try {
      await expect(inspectAuthState({ credentialsPath, tokenPath })).resolves.toEqual({
        clientConfigured: false,
        connected: false,
        status: "platform_setup_required",
      });

      await writeFile(
        credentialsPath,
        JSON.stringify({
          installed: {
            client_id: "test.apps.googleusercontent.com",
            client_secret: "not-returned",
            redirect_uris: ["http://localhost"],
          },
        })
      );
      await expect(inspectAuthState({ credentialsPath, tokenPath })).resolves.toEqual({
        clientConfigured: true,
        connected: false,
        status: "connection_required",
      });

      await writeFile(
        tokenPath,
        JSON.stringify({ refresh_token: "not-returned", access_token: "not-returned" })
      );
      const connected = await inspectAuthState({ credentialsPath, tokenPath });
      expect(connected).toEqual({
        clientConfigured: true,
        connected: true,
        status: "connected",
      });
      expect(JSON.stringify(connected)).not.toContain("not-returned");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});

describe("OAuth token storage", () => {
  it("creates the private token directory on a fresh tenant volume", async () => {
    const directory = await mkdtemp(join(tmpdir(), "google-auth-token-"));
    const tokenPath = join(directory, "secrets", "gmail-token.json");

    try {
      await expect(prepareTokenPath(tokenPath)).resolves.toBe(tokenPath);
      await writeFile(tokenPath, "connected", { mode: 0o600 });
      await expect(readFile(tokenPath, "utf8")).resolves.toBe("connected");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("creates a state-bound PKCE authorization URL for a TaskBotz callback", async () => {
    const directory = await mkdtemp(join(tmpdir(), "google-auth-pkce-"));
    const credentialsPath = join(directory, "credentials.json");
    const tokenPath = join(directory, "token.json");

    try {
      await writeFile(
        credentialsPath,
        JSON.stringify({
          web: {
            client_id: "test.apps.googleusercontent.com",
            client_secret: "not-returned",
            redirect_uris: ["https://taskbotz.example/api/oauth/google/callback"]
          }
        })
      );
      const authUrl = new URL(await beginAuthorization(
        { credentialsPath, tokenPath },
        {
          redirectUri: "https://taskbotz.example/api/oauth/google/callback",
          state: "signed-state"
        },
        new Date("2026-07-25T12:00:00.000Z")
      ));

      expect(authUrl.searchParams.get("redirect_uri")).toBe(
        "https://taskbotz.example/api/oauth/google/callback"
      );
      expect(authUrl.searchParams.get("state")).toBe("signed-state");
      expect(authUrl.searchParams.get("code_challenge_method")).toBe("S256");
      expect(authUrl.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);

      const pending = JSON.parse(
        await readFile(`${tokenPath}.oauth-pending.json`, "utf8")
      ) as Record<string, unknown>;
      expect(pending).toMatchObject({
        state: "signed-state",
        redirectUri: "https://taskbotz.example/api/oauth/google/callback",
        expiresAt: "2026-07-25T12:10:00.000Z"
      });
      expect(pending.codeVerifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(JSON.stringify(pending)).not.toContain("not-returned");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rejects insecure non-loopback callbacks", async () => {
    await expect(beginAuthorization(
      { credentialsPath: "/unused", tokenPath: "/unused" },
      {
        redirectUri: "http://taskbotz.example/api/oauth/google/callback",
        state: "signed-state"
      }
    )).rejects.toThrow("must use HTTPS");
  });
});
