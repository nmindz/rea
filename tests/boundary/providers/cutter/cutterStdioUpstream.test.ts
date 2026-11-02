import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { createCutterMcpConnection } from "../../../../src/cutter/CutterMcpConnection.js";
import {
  CUTTER_READ_TOOLS,
  type CutterReadTool,
} from "../../../../src/cutter/CutterProviderMetadata.js";
import type { CutterConfiguration } from "../../../../src/cutter/CutterConfiguration.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
  type TestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";
import {
  CUTTER_MUTATING_TOOL_NAMES,
  cutterFixtureBytes,
} from "../../../fixtures/cutterUpstream.mjs";

const upstream = fileURLToPath(
  new URL("../../../fixtures/cutterUpstream.mjs", import.meta.url),
);

const workspaces: TestWorkspace[] = [];
afterEach(async () => {
  for (const workspace of workspaces.splice(0))
    await removeTestWorkspace(workspace.root);
});

const start = async (
  options: Record<string, unknown> = {},
  overrides: Partial<CutterConfiguration> = {},
) => {
  const workspace = await createTestWorkspace("rea-cutter-stdio-");
  workspaces.push(workspace);
  const log = workspace.path("calls.log");
  const pidFile = workspace.path("upstream.pid");
  await workspace.write("calls.log", "");
  const config: CutterConfiguration = {
    command: process.execPath,
    args: [upstream],
    env: {
      CUTTER_FIXTURE_CALL_LOG: log,
      CUTTER_FIXTURE_PID_FILE: pidFile,
      CUTTER_FIXTURE_OPTIONS: JSON.stringify(options),
    },
    timeoutMs: 10_000,
    ...overrides,
  };
  const connection = createCutterMcpConnection(config, process.env);
  return {
    connection,
    config,
    calls: async () =>
      (await readFile(log, "utf8")).split("\n").filter((line) => line !== ""),
    pid: async () => Number(await readFile(pidFile, "utf8")),
  };
};

const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

describe("CutterMCP+ stdio connection", () => {
  it("decodes the wrapper's structured results from a real stdio server", async () => {
    const { connection, calls } = await start();
    try {
      const tools = await connection.connect();
      expect(tools).toEqual(expect.arrayContaining([...CUTTER_READ_TOOLS]));
      expect(connection.serverInfo()).toMatchObject({
        name: "cuttermcp-plus-fixture",
        version: "0.4.0",
      });
      // A scalar, a dictionary and a list each arrive under the wrapper's result key.
      expect(await connection.call("current_address", {})).toBe("0x401004");
      expect(
        await connection.call("list_functions", { offset: 0, limit: 2 }),
      ).toMatchObject({
        total: 4,
        items: [{ name: "main" }, { name: "sym.helper" }],
      });
      expect(
        await connection.call("list_strings", { offset: 0, limit: 10 }),
      ).toHaveLength(2);
      expect(await calls()).toEqual([
        "current_address",
        "list_functions",
        "list_strings",
      ]);
    } finally {
      await connection.close();
    }
  });

  it("never reaches a mutating upstream tool and keeps the connection usable", async () => {
    const { connection, calls } = await start();
    try {
      const tools = await connection.connect();
      for (const name of CUTTER_MUTATING_TOOL_NAMES) {
        // The upstream advertises the tool, so only REA's own boundary stops it.
        expect(tools).toContain(name);
        await expect(
          connection.call(name as CutterReadTool, { addr: "0x401000" }),
        ).rejects.toMatchObject({
          _tag: "AnalysisProtocolError",
          message: expect.stringContaining("read-only"),
        });
      }
      expect(await connection.call("current_address", {})).toBe("0x401004");
      expect(await calls()).toEqual(["current_address"]);
    } finally {
      await connection.close();
    }
  });

  it("reports an upstream tool error with its text and releases the child on close", async () => {
    const { connection, pid } = await start();
    await connection.connect();
    const child = await pid();
    expect(alive(child)).toBe(true);
    await expect(
      connection.call("list_vars" as CutterReadTool, {}),
    ).rejects.toMatchObject({ message: expect.stringContaining("read-only") });
    await connection.close();
    expect(alive(child)).toBe(false);
  });

  it("cancels an in-flight request with the caller's reason and still releases the child", async () => {
    const { connection, pid } = await start({ hangTools: ["decompile"] });
    await connection.connect();
    const child = await pid();
    const controller = new AbortController();
    const reason = new Error("caller cancelled");
    const pending = connection.call(
      "decompile",
      { addr: "0x401000" },
      { signal: controller.signal },
    );
    controller.abort(reason);
    await expect(pending).rejects.toMatchObject({
      _tag: "AnalysisCancelledError",
      cause: reason,
    });
    await connection.close();
    expect(alive(child)).toBe(false);
  });

  it("names the registration timeoutMs when a request reaches its deadline", async () => {
    const { connection, pid } = await start(
      { hangTools: ["decompile"] },
      { timeoutMs: 300 },
    );
    await connection.connect();
    const child = await pid();
    await expect(
      connection.call("decompile", { addr: "0x401000" }),
    ).rejects.toMatchObject({
      _tag: "AnalysisTimeoutError",
      timeoutMs: 300,
      remediationAction: expect.stringContaining("timeoutMs"),
    });
    await connection.close();
    expect(alive(child)).toBe(false);
  });

  it("serves the original input the simulated session maps", async () => {
    const { connection } = await start();
    try {
      await connection.connect();
      const bytes = await connection.call("read_bytes", {
        addr: "0x401000",
        size: 8,
      });
      expect(bytes).toMatchObject({
        bytes: [...cutterFixtureBytes().subarray(0x100, 0x108)],
      });
    } finally {
      await connection.close();
    }
  });
});
