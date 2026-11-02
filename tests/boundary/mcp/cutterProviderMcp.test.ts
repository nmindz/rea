import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { connectLocalToolsMcp } from "../../fixtures/localToolsMcp.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import {
  CUTTER_MUTATING_TOOL_NAMES,
  cutterFixtureBytes,
} from "../../fixtures/cutterUpstream.mjs";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../support/workspace/workspaceFixture.js";

const upstream = fileURLToPath(
  new URL("../../fixtures/cutterUpstream.mjs", import.meta.url),
);

const prepare = async (
  options: Record<string, unknown> = {},
  bytes: Buffer = cutterFixtureBytes(),
) => {
  const workspace = await createTestWorkspace("rea-cutter-mcp-");
  const target = await workspace.write("target.elf", bytes);
  const log = await workspace.write("calls.log", "");
  const registration = await workspace.write(
    "cutter.json",
    JSON.stringify({
      command: process.execPath,
      args: [upstream],
      env: {
        CUTTER_FIXTURE_CALL_LOG: log,
        CUTTER_FIXTURE_OPTIONS: JSON.stringify(options),
      },
      timeoutMs: 20_000,
    }),
  );
  return { workspace, target, log, registration };
};

it("opens the attached Cutter upstream and routes native tools to it over production MCP", async () => {
  const { workspace, target, log, registration } = await prepare();
  try {
    const { call } = await connectLocalToolsMcp({
      REA_CUTTER_MCP_CONFIG: registration,
    });
    const opened = await call("open_binary", {
      path: target,
      provider_id: "cutter",
    });
    expect(opened.isError, JSON.stringify(opened.content)).not.toBe(true);
    // Opening binds the provider without contacting the upstream.
    expect(await readFile(log, "utf8")).toBe("");
    const status = await call("binary_session", { detail: "complete" });
    expect(status.structuredContent).toMatchObject({
      result: {
        analysis_provider_candidates: expect.arrayContaining([
          expect.objectContaining({
            provider: expect.objectContaining({ id: "cutter" }),
            selected: true,
            availability: expect.objectContaining({ status: "available" }),
          }),
        ]),
      },
    });

    const procedures = await call("list_procedures", {});
    expect(procedures.isError, JSON.stringify(procedures.content)).not.toBe(
      true,
    );
    const evidence = parseEvidence(procedures.structuredContent);
    expect(evidence.provider.id).toBe("cutter");
    expect(evidence.normalized_result).toContainEqual({
      address: "0x401000",
      value: "main",
    });

    const dossier = await call("analyze_function", {
      procedure: "main",
      detail: "complete",
    });
    expect(dossier.isError, JSON.stringify(dossier.content)).not.toBe(true);
    expect(
      parseEvidence(dossier.structuredContent).normalized_result,
    ).toMatchObject({
      procedure: { address: "0x401000", name: "main" },
      pseudocode: expect.stringContaining("sym.helper"),
      facet_availability: { references: { available: false } },
    });

    const segments = await call("list_segments", {});
    expect(segments.isError, JSON.stringify(segments.content)).not.toBe(true);
    expect(
      parseEvidence(segments.structuredContent).normalized_result,
    ).toMatchObject([
      { name: ".text", provenance: "cutter-section-table" },
      { name: ".rodata" },
      { name: ".bss" },
    ]);

    const missing = await call("procedure_address", {
      procedure: "no_such_function",
    });
    expect(missing.isError).toBe(true);
    expect(parseMcpToolError(missing).error).toMatchObject({
      code: "invalid_request",
    });

    const closed = await call("close_binary", {});
    expect(closed.isError, JSON.stringify(closed.content)).not.toBe(true);

    const calls = (await readFile(log, "utf8")).split("\n").filter(Boolean);
    expect(calls).toEqual(
      expect.arrayContaining(["list_functions", "decompile"]),
    );
    for (const mutator of CUTTER_MUTATING_TOOL_NAMES)
      expect(calls).not.toContain(mutator);
  } finally {
    await removeTestWorkspace(workspace.root);
  }
});

it("fails closed before analysis when the open Cutter session maps different bytes", async () => {
  const { workspace, target, log, registration } = await prepare({
    mutateImage: true,
  });
  try {
    const { call } = await connectLocalToolsMcp({
      REA_CUTTER_MCP_CONFIG: registration,
    });
    expect(
      (await call("open_binary", { path: target, provider_id: "cutter" }))
        .isError,
    ).not.toBe(true);
    const response = await call("list_procedures", {});
    expect(response.isError).toBe(true);
    expect(parseMcpToolError(response).error).toMatchObject({
      code: "unreadable_output",
      details: { diagnostics: { identity_check: "target_probe" } },
    });
    const calls = (await readFile(log, "utf8")).split("\n").filter(Boolean);
    expect(calls).not.toContain("list_functions");
    expect(calls).not.toContain("decompile");
  } finally {
    await removeTestWorkspace(workspace.root);
  }
});

it("names the missing upstream tools when the catalog lacks the read profile", async () => {
  const { workspace, target, log, registration } = await prepare({
    hiddenTools: ["xrefs_to", "list_entry_points"],
  });
  try {
    const { call } = await connectLocalToolsMcp({
      REA_CUTTER_MCP_CONFIG: registration,
    });
    expect(
      (await call("open_binary", { path: target, provider_id: "cutter" }))
        .isError,
    ).not.toBe(true);
    const response = await call("list_procedures", {});
    expect(response.isError).toBe(true);
    expect(parseMcpToolError(response).error).toMatchObject({
      details: {
        diagnostics: {
          missing_tools: ["list_entry_points", "xrefs_to"],
          startup_operation: "initialize",
        },
      },
    });
    expect(await readFile(log, "utf8")).toBe("");
  } finally {
    await removeTestWorkspace(workspace.root);
  }
});

it("rejects an unconfigured cutter selection with the registration's repair", async () => {
  const workspace = await createTestWorkspace("rea-cutter-mcp-");
  try {
    const target = await workspace.write("target.elf", cutterFixtureBytes());
    const { call } = await connectLocalToolsMcp({});
    const response = await call("open_binary", {
      path: target,
      provider_id: "cutter",
    });
    expect(response.isError).toBe(true);
    expect(JSON.stringify(response.content)).toContain("REA_CUTTER_MCP_CONFIG");
  } finally {
    await removeTestWorkspace(workspace.root);
  }
});
