import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { expect } from "vitest";
import { workspaceCliTest } from "../../support/cli/workspaceCliFixture.js";
import { cutterFixtureBytes } from "../../fixtures/cutterUpstream.mjs";

const upstream = fileURLToPath(
  new URL("../../fixtures/cutterUpstream.mjs", import.meta.url),
);

workspaceCliTest(
  "decompiles through the attached Cutter upstream selected with --provider cutter",
  async ({ cli, workspace }) => {
    const target = await workspace.write("target.elf", cutterFixtureBytes());
    const log = await workspace.write("calls.log", "");
    const registration = await workspace.write(
      "cutter.json",
      JSON.stringify({
        command: process.execPath,
        args: [upstream],
        env: { CUTTER_FIXTURE_CALL_LOG: log },
        timeoutMs: 20_000,
      }),
    );
    const environment = {
      ...workspace.environment,
      REA_CUTTER_MCP_CONFIG: registration,
      REA_LOG_LEVEL: "silent",
    };
    const result = await cli.run({
      arguments: [
        "decompile",
        target,
        "main",
        "--provider",
        "cutter",
        "--json",
      ],
      environment,
      timeoutMs: 30_000,
    });
    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.json).toMatchObject({
      operation: "procedure_pseudo_code",
      provider: { id: "cutter" },
      normalized_result: expect.stringContaining("sym.helper"),
    });
    const calls = (await readFile(log, "utf8")).split("\n").filter(Boolean);
    expect(calls).toContain("decompile");
    for (const mutator of [
      "rename_function",
      "set_comment",
      "rename_local_variable",
      "set_local_variable_type",
    ])
      expect(calls).not.toContain(mutator);
  },
);

workspaceCliTest(
  "reports the registration repair for an unconfigured --provider cutter selection",
  async ({ cli, workspace }) => {
    const target = await workspace.write("target.elf", cutterFixtureBytes());
    const result = await cli.run({
      arguments: [
        "decompile",
        target,
        "main",
        "--provider",
        "cutter",
        "--json",
      ],
      environment: { ...workspace.environment, REA_LOG_LEVEL: "silent" },
    });
    expect(result.exitCode, result.stderr).toBe(1);
    expect(result.json).toMatchObject({
      details: {
        selection_reason: "provider_unavailable",
        requested_provider_id: "cutter",
        rejections: expect.arrayContaining([
          expect.objectContaining({
            provider_id: "cutter",
            origin: "availability",
            remediation: expect.stringContaining("REA_CUTTER_MCP_CONFIG"),
          }),
        ]),
      },
    });
  },
);

workspaceCliTest(
  "doctor validates the Cutter registration without launching the upstream",
  async ({ cli, workspace }) => {
    const log = await workspace.write("calls.log", "");
    const registration = await workspace.write(
      "cutter.json",
      JSON.stringify({
        command: process.execPath,
        args: [upstream],
        env: { CUTTER_FIXTURE_CALL_LOG: log },
      }),
    );
    const result = await cli.run({
      arguments: ["doctor", "--provider", "cutter", "--json"],
      environment: {
        ...workspace.environment,
        REA_CUTTER_MCP_CONFIG: registration,
      },
      timeoutMs: 30_000,
    });
    expect(result.json).toMatchObject({
      providerInspections: expect.arrayContaining([
        expect.objectContaining({
          id: "cutter",
          configured: true,
          available: true,
          registrationEnvironment: { REA_CUTTER_MCP_CONFIG: registration },
        }),
      ]),
    });
    expect(await readFile(log, "utf8")).toBe("");
  },
);

workspaceCliTest(
  "doctor refuses an HTTP-shaped Cutter registration with the setting named",
  async ({ cli, workspace }) => {
    const registration = await workspace.write(
      "cutter.json",
      JSON.stringify({ url: "http://127.0.0.1:9000/" }),
    );
    const result = await cli.run({
      arguments: ["doctor", "--provider", "cutter", "--json"],
      environment: {
        ...workspace.environment,
        REA_CUTTER_MCP_CONFIG: registration,
      },
      timeoutMs: 30_000,
    });
    expect(result.exitCode, result.stderr).toBe(1);
    expect(result.json).toMatchObject({
      providerInspections: expect.arrayContaining([
        expect.objectContaining({
          id: "cutter",
          available: false,
          checks: expect.arrayContaining([
            expect.objectContaining({
              name: "registration",
              ok: false,
              detail: expect.stringContaining("REA_CUTTER_MCP_CONFIG"),
            }),
          ]),
        }),
      ]),
    });
  },
);
