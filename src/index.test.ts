import { describe, it, expect } from "vitest";
import { getToolPluginMetadata } from "openclaw/plugin-sdk/tool-plugin";
import plugin, {
  buildGmailMessagesListRequest,
  GMAIL_MESSAGES_PAGINATION_SUPPORTED,
  resolveAuthConfig,
} from "./index.js";

const expectedTools = [
  "google_auth_start",
  "google_auth_complete",
  "gmail_messages_list",
  "gmail_message_get",
  "gmail_message_send",
  "gmail_message_modify",
  "gmail_message_trash",
  "calendar_events_list",
  "calendar_event_create",
  "calendar_event_get",
  "calendar_event_delete",
  "drive_files_list",
  "drive_file_get",
  "drive_permission_create",
  "drive_file_trash",
  "docs_create",
  "docs_get",
  "docs_append_text",
  "sheets_create",
  "sheets_get",
  "sheets_values_get",
  "sheets_values_append",
  "slides_create",
  "slides_get",
];

describe("tangleclaw-google-oauth plugin metadata", () => {
  const metadata = getToolPluginMetadata(plugin);

  it("exposes metadata via the OpenClaw SDK helper", () => {
    expect(metadata).toBeDefined();
  });

  it("declares the expected id, name, and description", () => {
    expect(metadata!.id).toBe("tangleclaw-google-oauth");
    expect(metadata!.name).toBe("TangleClaw Google OAuth");
    expect(metadata!.description).toMatch(/Google Workspace/);
    expect(metadata!.description).toMatch(/direct OAuth/i);
  });

  it("exposes every expected tool exactly once", () => {
    const names = metadata!.tools.map((t) => t.name);
    for (const expected of expectedTools) {
      expect(names).toContain(expected);
    }
    expect(new Set(names).size).toBe(names.length);
  });

  it("does not expose unexpected tools", () => {
    const names = metadata!.tools.map((t) => t.name).sort();
    expect(names).toEqual([...expectedTools].sort());
  });

  it("gives every tool a non-empty description", () => {
    for (const t of metadata!.tools) {
      expect(t.description, `tool ${t.name} missing description`).toBeTruthy();
    }
  });

  it("declares activation on startup", () => {
    expect(metadata!.activation.onStartup).toBe(true);
  });

  it("declares a configSchema with credentialsPath and tokenPath", () => {
    const props = (metadata!.configSchema as { properties?: Record<string, unknown> }).properties;
    expect(props).toHaveProperty("credentialsPath");
    expect(props).toHaveProperty("tokenPath");
  });

  it("uses an operator-mounted OAuth client without changing tenant plugin config", () => {
    const previous = process.env.GOOGLE_OAUTH_CREDENTIALS_PATH;
    process.env.GOOGLE_OAUTH_CREDENTIALS_PATH =
      "/run/secrets/taskbotz-google-oauth-client.json";

    try {
      expect(
        resolveAuthConfig({
          credentialsPath: "~/.openclaw/secrets/gmail-credentials.json",
          tokenPath: "~/.openclaw/secrets/gmail-token.json",
        })
      ).toEqual({
        credentialsPath: "/run/secrets/taskbotz-google-oauth-client.json",
        tokenPath: "~/.openclaw/secrets/gmail-token.json",
      });
    } finally {
      if (previous === undefined) {
        delete process.env.GOOGLE_OAUTH_CREDENTIALS_PATH;
      } else {
        process.env.GOOGLE_OAUTH_CREDENTIALS_PATH = previous;
      }
    }
  });

  it("exposes Gmail pagination and forwards continuation tokens", () => {
    const gmailList = metadata!.tools.find((tool) => tool.name === "gmail_messages_list");
    const properties = (gmailList!.parameters as {
      properties?: Record<string, unknown>;
    }).properties;

    expect(properties).toHaveProperty("pageToken");
    expect(GMAIL_MESSAGES_PAGINATION_SUPPORTED).toBe(true);
    expect(
      buildGmailMessagesListRequest({
        query: "is:unread",
        maxResults: 25,
        pageToken: "next-page",
      })
    ).toEqual({
      userId: "me",
      q: "is:unread",
      maxResults: 25,
      pageToken: "next-page",
    });
  });
});
