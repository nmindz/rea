import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseConfig } from "../../src/config/parseConfig.js";
import {
  createCutterTarget,
  RecordingCutterMcp,
} from "../fixtures/cutterMcp.js";
import { CutterProvider } from "../../src/cutter/CutterProvider.js";
import { CUTTER_READ_TOOLS } from "../../src/cutter/CutterProviderMetadata.js";
import { cutterFixtureBytes } from "../fixtures/cutterUpstream.mjs";
import { createTestBinarySession } from "../fixtures/binarySession.js";
import { parseBinaryTarget } from "../../src/application/BinaryTargetResolver.js";
import { fat } from "../../src/domain/binaryTarget.fixture.js";
import { projectAnalysisError } from "../../src/domain/analysisErrorProjection.js";
import type { BinarySession } from "../../src/application/binary/BinarySession.js";
import type { JsonValue } from "../../src/domain/jsonValue.js";

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});

const open = async (
  registration: Record<string, unknown> = { command: "fixture" },
  bytes?: Buffer,
) => {
  const { root, target } = await createCutterTarget(bytes);
  roots.push(root);
  const path = join(root, "registration.json");
  await writeFile(path, JSON.stringify(registration));
  const config = parseConfig({ REA_CUTTER_MCP_CONFIG: path });
  if (!config.ok) throw config.error;
  const producer = new RecordingCutterMcp();
  const provider = new CutterProvider(config.value, {}, () => producer);
  const session = createTestBinarySession(provider);
  expect((await session.open(target.path)).ok).toBe(true);
  return { root, target, producer, provider, session };
};

const run = async (
  session: BinarySession,
  operation: Parameters<BinarySession["execute"]>[0],
  parameters: Record<string, JsonValue> = {},
) => {
  const result = await session.execute(operation, parameters);
  if (!result.ok) throw result.error;
  return result.value;
};

const failure = async (
  session: BinarySession,
  operation: Parameters<BinarySession["execute"]>[0],
  parameters: Record<string, JsonValue> = {},
) => {
  const result = await session.execute(operation, parameters);
  if (result.ok) throw new Error(`Expected ${operation} to fail`);
  return result.error;
};

describe("Cutter provider discovery and profile", () => {
  it("discovers without launching and commits adapter semantics without persisting marked values", async () => {
    const { root, target } = await createCutterTarget();
    roots.push(root);
    const path = join(root, "registration.json");
    const registration = {
      command: "fixture",
      env: { CUTTER_TOKEN: "private-fixture-token" },
      sensitive: { env: ["CUTTER_TOKEN"] },
    };
    await writeFile(path, JSON.stringify(registration));
    const config = parseConfig({ REA_CUTTER_MCP_CONFIG: path });
    if (!config.ok) throw config.error;
    const producer = new RecordingCutterMcp();
    const provider = new CutterProvider(config.value, {}, () => producer);
    expect(await provider.inspectAvailability()).toMatchObject({
      status: "available",
      diagnostics: { live_connection_probed: false, transport: "stdio" },
    });
    const resolution = await provider.resolveAnalysisProfile(target);
    if (!resolution.ok) throw resolution.error;
    expect(resolution.value.profile.parameters).toMatchObject({
      engine_version: null,
      upstream_distribution_version: null,
      cache_policy: "live",
      mode: "attached",
      version_scope: "rea-cutter-adapter",
      compatibility_profile: "cuttermcp-plus-0.4",
    });
    expect(JSON.stringify(resolution)).not.toContain("private-fixture-token");
    // A rotated marked value selects a connection but does not change analysis identity.
    await writeFile(
      path,
      JSON.stringify({
        ...registration,
        env: { CUTTER_TOKEN: "rotated-fixture-token" },
      }),
    );
    const rotated = await provider.resolveAnalysisProfile(target);
    if (!rotated.ok) throw rotated.error;
    expect(rotated.value.profile.parameters.registration_digest).toBe(
      resolution.value.profile.parameters.registration_digest,
    );
    expect(producer.connects).toBe(0);
  });

  it("is unavailable with the setting named when no registration is configured", async () => {
    const config = parseConfig({});
    if (!config.ok) throw config.error;
    const snapshot = await new CutterProvider(
      config.value,
      {},
    ).inspectReadinessSnapshot();
    expect(snapshot.availability).toMatchObject({
      status: "unavailable",
      code: "not_configured",
      remediation: expect.stringContaining("REA_CUTTER_MCP_CONFIG"),
    });
    expect(snapshot.capabilities.every(({ available }) => !available)).toBe(
      true,
    );
  });

  it("refuses unsupported targets before any upstream contact", async () => {
    const { root, target } = await createCutterTarget();
    roots.push(root);
    const config = parseConfig({});
    if (!config.ok) throw config.error;
    const provider = new CutterProvider(config.value, {});
    expect(
      provider.inspectTargetSupport({
        path: target.path,
        sha256: target.sha256,
        kind: "database",
        format: "analysis-database",
      }),
    ).toMatchObject({ status: "unsupported", code: "target_kind_unsupported" });
    const universal = join(root, "universal");
    // x86_64 and arm64 slices share one whole-file digest.
    await writeFile(universal, fat([0x01000007, 0x0100000c]));
    const resolved = await parseBinaryTarget(universal);
    if (!resolved.ok) throw resolved.error;
    expect(provider.inspectTargetSupport(resolved.value)).toMatchObject({
      status: "unsupported",
      code: "target_format_unsupported",
      reason: expect.stringContaining("lipo -thin"),
    });
    expect(
      provider.inspectTargetSupport({
        ...target,
        architecture: "mips",
        availableArchitectures: ["mips"],
        mips: { bits: 32, endianness: "big" },
      } as never),
    ).toMatchObject({
      status: "unsupported",
      code: "architecture_unsupported",
    });
  });

  it("fails closed and names the missing tools when the upstream catalog is incompatible", async () => {
    const { producer, session } = await open();
    producer.tools = producer.tools.filter(
      (name) => name !== "xrefs_to" && name !== "read_bytes",
    );
    const error = await failure(session, "procedure_pseudo_code", {
      procedure: "main",
    });
    expect(error).toMatchObject({
      _tag: "ProviderAdapterError",
      userMessage: expect.stringContaining(
        "missing tools: xrefs_to, read_bytes",
      ),
    });
    expect(projectAnalysisError(error).details).toMatchObject({
      provider_id: "cutter",
      diagnostics: {
        mode: "attached",
        expected_profile: "cuttermcp-plus-0.4",
        missing_tools: ["xrefs_to", "read_bytes"],
        startup_operation: "initialize",
      },
    });
    // No analysis request ran against the incompatible upstream.
    expect(producer.calls).toEqual([]);
    expect((await session.close()).ok).toBe(true);
    expect(producer.closes).toBe(1);
  });
});

describe("Cutter provider analysis workflow", () => {
  it("answers inventory, resolution and text operations from the attached upstream", async () => {
    const { producer, session, target } = await open();
    expect((await run(session, "list_documents")).result).toEqual([
      target.path,
    ]);
    const procedures = await run(session, "list_procedures");
    expect(procedures.result).toEqual([
      { address: "0x401000", value: "main" },
      { address: "0x401040", value: "sym.helper" },
      { address: "0x401080", value: "entry0" },
      { address: "0x401100", value: "sym.imp.puts" },
    ]);
    expect(procedures.provider.id).toBe("cutter");
    expect(
      (await run(session, "search_procedures", { pattern: "HELP" })).result,
    ).toEqual([{ address: "0x401040", value: "sym.helper" }]);
    expect(
      (
        await run(session, "search_procedures", {
          pattern: "^sym\\.",
          mode: "regex",
        })
      ).result,
    ).toHaveLength(2);
    expect(
      (await run(session, "procedure_address", { procedure: "sym.helper" }))
        .result,
    ).toBe("0x401040");
    // An interior address resolves to the containing function's entry.
    expect(
      (await run(session, "procedure_address", { procedure: "0x401010" }))
        .result,
    ).toBe("0x401000");
    expect(
      (await run(session, "procedure_pseudo_code", { procedure: "main" }))
        .result,
    ).toContain("sym.imp.puts");
    expect(
      (await run(session, "procedure_assembly", { procedure: "main" })).result,
    ).toBe(
      [
        "0x401000: push rbp",
        "0x401004: call sym.helper",
        "0x401020: call sym.imp.puts",
        "0x40103f: ret",
      ].join("\n"),
    );
    expect(
      (await run(session, "read_function_instructions", { procedure: "main" }))
        .result,
    ).toMatchObject({
      procedure: { address: "0x401000", name: "main" },
      instructions: expect.arrayContaining(["0x40103f: ret"]),
    });
    await session.close();
    expect(
      producer.calls.every(({ name }) =>
        (CUTTER_READ_TOOLS as readonly string[]).includes(name),
      ),
    ).toBe(true);
  });

  it("derives relationships from CALL references and keeps coverage partial", async () => {
    const { session } = await open();
    const callers = await run(session, "procedure_callers", {
      procedure: "main",
    });
    // The DATA reference and the CALL from outside any function are not callers.
    expect(callers.result).toEqual(["0x401080"]);
    expect(callers.relationshipCoverage).toMatchObject({
      status: "partial",
      limitations: expect.arrayContaining([
        expect.stringContaining("outside any function"),
      ]),
    });
    const callees = await run(session, "procedure_callees", {
      procedure: "main",
    });
    expect(callees.result).toEqual(["0x401040", "0x401100"]);
    expect(callees.relationshipCoverage).toMatchObject({
      status: "partial",
      limitations: expect.arrayContaining([
        expect.stringContaining("not entries of a discovered function"),
      ]),
    });
    await session.close();
  });

  it("returns a dossier whose unavailable facets stay unknown", async () => {
    const { session } = await open();
    const dossier = await run(session, "analyze_function", {
      procedure: "main",
    });
    expect(dossier.result).toMatchObject({
      procedure: {
        address: "0x401000",
        name: "main",
        signature: "int main (void);",
        locals: [],
      },
      pseudocode: expect.stringContaining("return 0"),
      assembly: expect.arrayContaining(["0x401000: push rbp"]),
      callers: [{ address: "0x401080", name: "entry0" }],
      callees: [{ name: "sym.helper" }, { name: "sym.imp.puts" }],
      incoming_references: [],
      basic_blocks: [],
      facet_availability: {
        pseudocode: { available: true },
        callers: { available: true },
        references: { available: false },
        cfg: { available: false },
        comments: { available: false },
      },
    });
    expect(dossier.relationshipCoverage).toMatchObject({
      status: "partial",
      limited_directions: ["callers", "callees"],
    });
    expect(dossier.limitations.join(" ")).toContain("weaker than a digest");
    await session.close();
  });

  it("reports missing pseudocode as unavailable rather than empty source", async () => {
    const { session, producer } = await open();
    producer.world.decompiler = false;
    expect(
      (await run(session, "procedure_pseudo_code", { procedure: "main" }))
        .result,
    ).toBeNull();
    const dossier = await run(session, "analyze_function", {
      procedure: "main",
    });
    expect(dossier.result).toMatchObject({
      pseudocode: "",
      facet_availability: {
        pseudocode: { available: false, reason: expect.any(String) },
      },
    });
    await session.close();
  });
});

describe("Cutter provider inventories and navigation", () => {
  it("lists strings, names, segments and bytes through the public contracts", async () => {
    const { session, producer } = await open();
    producer.world.pageClamp = 1;
    expect((await run(session, "list_strings")).result).toEqual([
      { address: "0x402000", value: "hello" },
      { address: "0x402010", value: "a.b\nC" },
    ]);
    expect(
      (await run(session, "list_strings", { address: "0x402010" })).result,
    ).toEqual([{ address: "0x402010", value: "a.b\nC" }]);
    expect(
      (await run(session, "search_strings", { pattern: "a.b" })).result,
    ).toEqual([{ address: "0x402010", value: "a.b\nC" }]);
    expect((await run(session, "list_names")).result).toEqual([
      { address: "0x401000", value: "main" },
      { address: "0x401100", value: "sym.imp.puts" },
    ]);
    const segments = await run(session, "list_segments");
    expect(segments.result).toMatchObject([
      {
        name: ".text",
        start: "0x401000",
        end: "0x401200",
        executable: true,
        writable: false,
        permissions: { available: true, source: "cutter-section-table" },
        provenance: "cutter-section-table",
      },
      { name: ".rodata", executable: false },
      { name: ".bss", writable: true },
    ]);
    const bytes = await run(session, "read_bytes", {
      address: "0x401000",
      length: 4,
    });
    const file = cutterFixtureBytes();
    expect(bytes.result).toEqual({
      address: "0x401000",
      requested_bytes: 4,
      returned_bytes: 4,
      bytes_hex: file.subarray(0x100, 0x104).toString("hex"),
      complete: true,
    });
    // The last two mapped bytes of .text: a short reply stays explicitly incomplete.
    expect(
      (await run(session, "read_bytes", { address: "0x4011fe", length: 4 }))
        .result,
    ).toMatchObject({ returned_bytes: 2, complete: false });
    await session.close();
  });

  it("resolves containing procedures and distinguishes unmapped addresses", async () => {
    const { session } = await open();
    expect(
      (
        await run(session, "resolve_containing_procedure", {
          address: "0x401010",
        })
      ).result,
    ).toMatchObject({
      found: true,
      procedure: { address: "0x401000", name: "main" },
    });
    expect(
      (
        await run(session, "resolve_containing_procedure", {
          address: "0x4011f0",
        })
      ).result,
    ).toMatchObject({ found: false, reason: "not_in_procedure" });
    expect(
      (
        await run(session, "resolve_containing_procedure", {
          address: "0x900000",
        })
      ).result,
    ).toMatchObject({ found: false, reason: "outside_segments" });
    await session.close();
  });

  it("reports live navigation state and refuses to guess outside a function", async () => {
    const { session, producer } = await open();
    expect((await run(session, "current_address")).result).toBe("0x401004");
    expect((await run(session, "current_procedure")).result).toBe("main");
    producer.world.seek = 0x401300;
    const error = await failure(session, "current_procedure");
    expect(error).toMatchObject({ _tag: "AnalysisCapabilityUnavailableError" });
    await session.close();
  });

  it("xrefs report exact-address sources and never replay from snapshots", async () => {
    const { session } = await open();
    expect(
      (await run(session, "xrefs", { address: "0x401000" })).result,
    ).toEqual(["0x401090", "0x402008", "0x407000"]);
    expect(session.allowsSnapshotReplay("xrefs")).toBe(false);
    expect(session.allowsSnapshotReplay("procedure_pseudo_code")).toBe(false);
    await session.close();
  });
});

describe("Cutter provider input boundary", () => {
  it("distinguishes a missing function from a producer fault", async () => {
    const { session } = await open();
    const missing = await failure(session, "procedure_address", {
      procedure: "no_such_function",
    });
    expect(missing).toMatchObject({ _tag: "AnalysisInputError" });
    const interior = await failure(session, "procedure_address", {
      procedure: "0x900000",
    });
    expect(interior).toMatchObject({ _tag: "AnalysisInputError" });
    await session.close();
  });

  it("forwards only canonical hexadecimal coordinates to the upstream", async () => {
    const { session, producer } = await open();
    const hostile = "0x401000; wx 90 @ 0x401000";
    expect(
      await failure(session, "procedure_address", { procedure: hostile }),
    ).toMatchObject({ _tag: "AnalysisInputError" });
    expect(await failure(session, "xrefs", { address: hostile })).toMatchObject(
      { _tag: "AnalysisInputError" },
    );
    expect(
      await failure(session, "read_bytes", { address: "401000", length: 4 }),
    ).toMatchObject({ _tag: "AnalysisInputError" });
    expect(
      await failure(session, "read_bytes", {
        address: "0x401000",
        length: 65_537,
      }),
    ).toMatchObject({ _tag: "AnalysisInputError" });
    await run(session, "procedure_address", { procedure: "0x401010" });
    const sent = producer.calls.flatMap(({ args }) =>
      Object.values(args).filter(
        (value): value is string => typeof value === "string",
      ),
    );
    expect(sent.every((value) => /^0x[0-9a-f]+$/u.test(value))).toBe(true);
    await session.close();
  });

  it("rejects a document other than the admitted target", async () => {
    const { session } = await open();
    expect(
      await failure(session, "list_procedures", { document: "/elsewhere" }),
    ).toMatchObject({ _tag: "AnalysisInputError" });
    await session.close();
  });
});

describe("Cutter provider target identity", () => {
  it("refuses a session whose mapped bytes differ from the selected target", async () => {
    const { session, producer } = await open();
    producer.world.corrupt(0x180);
    const error = await failure(session, "list_procedures");
    expect(error).toMatchObject({ _tag: "AnalysisOutputError" });
    expect(projectAnalysisError(error).details).toMatchObject({
      diagnostics: { identity_check: "target_probe" },
    });
    // The failed binding never reached an analysis request.
    expect(
      producer.calls.filter(({ name }) => name === "list_functions"),
    ).toEqual([]);
    await session.close();
  });

  it("refuses a target that changed after admission", async () => {
    const { session, target } = await open();
    const changed = cutterFixtureBytes();
    changed[0x200] = (changed[0x200] ?? 0) ^ 0xff;
    await writeFile(target.path, changed);
    const error = await failure(session, "list_procedures");
    expect(projectAnalysisError(error).details).toMatchObject({
      diagnostics: { identity_check: "local_sha256" },
    });
    await session.close();
  });

  it("refuses when the section layout changes during the session", async () => {
    const { session, producer } = await open();
    await run(session, "list_procedures");
    const text = producer.world.sections[0];
    if (text === undefined) throw new Error("Missing fixture section");
    text.vaddr += 0x1000;
    const error = await failure(session, "list_procedures");
    expect(projectAnalysisError(error).details).toMatchObject({
      diagnostics: { identity_check: "session_layout" },
    });
    await session.close();
  });

  it("refuses when probed bytes change under an unchanged layout", async () => {
    const { session, producer } = await open();
    await run(session, "list_procedures");
    producer.world.corrupt(0x180);
    const error = await failure(session, "list_procedures");
    expect(projectAnalysisError(error).details).toMatchObject({
      diagnostics: { identity_check: "session_probe" },
    });
    await session.close();
  });

  it("detects a replacement that lands after the request reply", async () => {
    const { session, producer } = await open();
    await run(session, "list_procedures");
    producer.beforeCall = async (name) => {
      if (name === "list_functions") producer.world.corrupt(0x180);
    };
    const error = await failure(session, "list_procedures");
    expect(projectAnalysisError(error).details).toMatchObject({
      diagnostics: { identity_check: "session_probe" },
    });
    // Replies already collected are retained as partial, unverified Evidence.
    expect(error.partialObservation).toBeDefined();
    await session.close();
  });

  it("keeps identity unknown when no file-backed code can be compared", async () => {
    const { session, producer } = await open();
    producer.world.entries = [];
    producer.world.sections = producer.world.sections.filter(
      ({ perm }) => !perm.includes("x"),
    );
    const error = await failure(session, "list_procedures");
    expect(projectAnalysisError(error).details).toMatchObject({
      diagnostics: { identity_check: "no_probe" },
    });
    await session.close();
  });
});

describe("Cutter provider cancellation and cleanup", () => {
  it("retains the caller's cancellation and stays usable afterwards", async () => {
    const { session, producer } = await open();
    const controller = new AbortController();
    const reason = new Error("caller cancelled");
    producer.beforeCall = async (name) => {
      if (name === "list_functions") controller.abort(reason);
    };
    const cancelled = await session.execute(
      "list_procedures",
      {},
      {
        signal: controller.signal,
      },
    );
    expect(cancelled).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCancelledError", cause: reason },
    });
    producer.beforeCall = undefined;
    expect((await run(session, "list_procedures")).result).toHaveLength(4);
    expect((await session.close()).ok).toBe(true);
    expect(producer.closes).toBe(1);
  });

  it("does not contact the upstream for an already-cancelled request", async () => {
    const { session, producer } = await open();
    const controller = new AbortController();
    controller.abort(new Error("before start"));
    const cancelled = await session.execute(
      "list_procedures",
      {},
      {
        signal: controller.signal,
      },
    );
    expect(cancelled).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCancelledError" },
    });
    expect(producer.connects).toBe(0);
    await session.close();
  });

  it("retains a connection whose cleanup failed and releases it on retry", async () => {
    const { session, producer } = await open();
    await run(session, "list_procedures");
    producer.failClose = true;
    const first = await session.close();
    expect(first).toMatchObject({
      ok: false,
      error: { cleanupIncomplete: true },
    });
    expect(producer.detaches).toBe(1);
    producer.failClose = false;
    expect((await session.close()).ok).toBe(true);
    expect(producer.closes).toBe(2);
    if (first.ok) throw new Error("Expected the first close to fail");
    expect(first.error.cleanupIncomplete).toBe(false);
  });

  it("serves a reopened session from a fresh upstream connection", async () => {
    const { session, producer, target } = await open();
    await run(session, "list_procedures");
    expect((await session.close()).ok).toBe(true);
    expect((await session.open(target.path)).ok).toBe(true);
    await run(session, "list_procedures");
    expect(producer.connects).toBe(2);
    await session.close();
  });
});

describe("Cutter registration file", () => {
  it("reads the file from disk when the provider resolves a profile", async () => {
    const { root, target } = await createCutterTarget();
    roots.push(root);
    const path = join(root, "registration.json");
    await writeFile(path, JSON.stringify({ command: "first" }));
    const config = parseConfig({ REA_CUTTER_MCP_CONFIG: path });
    if (!config.ok) throw config.error;
    const registrations: string[] = [];
    const provider = new CutterProvider(config.value, {}, (registration) => {
      registrations.push(registration.command);
      return new RecordingCutterMcp();
    });
    const session = createTestBinarySession(provider);
    expect((await session.open(target.path)).ok).toBe(true);
    await run(session, "list_procedures");
    expect(await readFile(path, "utf8")).toContain("first");
    expect(registrations).toEqual(["first"]);
    await session.close();
  });
});
