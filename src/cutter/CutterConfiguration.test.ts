import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { RetainedResourceScope } from "../application/AnalysisProvider.js";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import { readCutterConfiguration } from "./CutterConfiguration.js";
import { createCutterDiagnosticRedactor } from "./CutterMcpConnection.js";
import { cutterRegistrationDigest } from "./CutterRegistrationIdentity.js";
import { inspectCutterRegistration } from "./CutterDoctor.js";

const resourceScope: RetainedResourceScope = {
  retain: () => undefined,
  run: (operation) => operation(),
};

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});

const registration = async (value: unknown): Promise<string> => {
  const root = await createTestTempDirectory("rea-cutter-registration-");
  roots.push(root);
  const path = join(root, "registration.json");
  await writeFile(
    path,
    typeof value === "string" ? value : JSON.stringify(value),
  );
  return path;
};
const read = (path: string) => readCutterConfiguration(path, { resourceScope });

describe("Cutter registration", () => {
  it("accepts a direct registration or an upstream mcpServers entry", async () => {
    for (const input of [
      { command: "python", args: ["mcp_server.py"] },
      {
        mcpServers: {
          "cuttermcp-plus": { command: "python", args: ["mcp_server.py"] },
          unrelated: { command: "untouched" },
        },
      },
    ])
      expect(await read(await registration(input))).toMatchObject({
        ok: true,
        value: {
          command: "python",
          args: ["mcp_server.py"],
          timeoutMs: 300_000,
        },
      });
  });

  it.each([
    [{ url: "http://127.0.0.1:9000/" }, "url is not supported"],
    [{ command: "python", headers: { Authorization: "x" } }, "headers"],
    [{ command: "python", mode: "headless" }, "mode"],
    [{ command: "python", args: "mcp_server.py" }, "args"],
    [{ command: "python", timeoutMs: 0 }, "timeoutMs must be an integer"],
    [
      { command: "python", timeoutMs: 2_147_483_648 },
      "timeoutMs must be an integer",
    ],
  ])(
    "refuses an unsupported registration %#, naming the setting and not the values",
    async (input, text) => {
      const result = await read(await registration(input));
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.error.message).toContain("REA_CUTTER_MCP_CONFIG");
      expect(result.error.message).toContain(text);
      expect(result.error.message).not.toContain("Authorization");
      expect(
        result.error.settings.every(
          ({ setting }) => setting === "REA_CUTTER_MCP_CONFIG",
        ),
      ).toBe(true);
    },
  );

  it("refuses malformed JSON and a missing file without leaking contents", async () => {
    const malformed = await read(await registration("{ not json"));
    expect(malformed.ok).toBe(false);
    const root = await createTestTempDirectory("rea-cutter-registration-");
    roots.push(root);
    const missing = await read(join(root, "absent.json"));
    expect(missing).toMatchObject({
      ok: false,
      error: {
        settings: [{ setting: "REA_CUTTER_MCP_CONFIG" }],
      },
    });
  });

  it("digests marked-sensitive values out of the analysis identity", async () => {
    const base = { command: "python", env: { A: "visible", TOKEN: "one" } };
    const parse = async (env: Record<string, string>) => {
      const result = await read(
        await registration({ ...base, env, sensitive: { env: ["TOKEN"] } }),
      );
      if (!result.ok) throw result.error;
      return cutterRegistrationDigest(result.value);
    };
    expect(await parse({ A: "visible", TOKEN: "one" })).toBe(
      await parse({ A: "visible", TOKEN: "two" }),
    );
    expect(await parse({ A: "visible", TOKEN: "one" })).not.toBe(
      await parse({ A: "different", TOKEN: "one" }),
    );
  });

  it("redacts exactly the marked values, including their JSON spelling", async () => {
    const result = await read(
      await registration({
        command: "python",
        env: { TOKEN: 'se"cret', OTHER: "plain-value" },
        sensitive: { env: ["TOKEN"] },
      }),
    );
    if (!result.ok) throw result.error;
    const redact = createCutterDiagnosticRedactor(result.value);
    expect(redact('failed with se"cret and plain-value')).toBe(
      "failed with [redacted sensitive value] and plain-value",
    );
    expect(redact('{"error":"se\\"cret"}')).toBe(
      '{"error":"[redacted sensitive value]"}',
    );
  });

  it("doctor validates without launching and names the repair when unset", async () => {
    const valid = await inspectCutterRegistration(
      await registration({ command: "python" }),
      resourceScope,
    );
    expect(valid).toMatchObject({
      id: "cutter",
      configured: true,
      available: true,
    });
    const unset = await inspectCutterRegistration(undefined, resourceScope);
    expect(unset).toMatchObject({
      configured: false,
      available: false,
      registrationEnvironment: {},
      checks: [
        {
          code: "not_configured",
          remediation: expect.stringContaining("REA_CUTTER_MCP_CONFIG"),
        },
      ],
    });
  });
});
