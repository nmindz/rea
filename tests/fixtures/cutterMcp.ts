import { createHash } from "node:crypto";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { BinaryTarget } from "../../src/domain/binaryTargetTypes.js";
import type { JsonValue } from "../../src/domain/jsonValue.js";
import type { CutterMcpConnection } from "../../src/cutter/CutterMcpConnection.js";
import {
  CUTTER_MUTATING_TOOL_NAMES,
  CUTTER_READ_TOOL_NAMES,
  CutterWorld,
  cutterFixtureBytes,
} from "./cutterUpstream.mjs";

/** Create a test-owned executable without invoking an engine. */
export const createCutterTarget = async (
  bytes: Buffer = cutterFixtureBytes(),
) => {
  const root = await mkdtemp(join(tmpdir(), "rea-cutter-test-"));
  const path = join(root, "target.elf");
  await writeFile(path, bytes);
  const target: BinaryTarget = {
    path,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    kind: "executable",
    format: "elf",
    architecture: "x86_64",
    availableArchitectures: ["x86_64"],
  };
  return { root, target };
};

/** Full tool catalog the simulated 0.4.0 wrapper advertises. */
export const CUTTER_ADVERTISED_TOOLS: readonly string[] = [
  ...CUTTER_READ_TOOL_NAMES,
  ...CUTTER_MUTATING_TOOL_NAMES,
];

/** Stateful upstream fixture at the real connection seam; no module mocking. */
export class RecordingCutterMcp implements CutterMcpConnection {
  readonly world = new CutterWorld();
  readonly calls: {
    name: string;
    args: Readonly<Record<string, JsonValue>>;
  }[] = [];
  connects = 0;
  closes = 0;
  detaches = 0;
  failClose = false;
  tools: readonly string[] = CUTTER_ADVERTISED_TOOLS;
  beforeCall:
    | ((
        name: string,
        args: Readonly<Record<string, JsonValue>>,
      ) => Promise<void>)
    | undefined;

  async connect() {
    this.connects += 1;
    return this.tools;
  }
  serverInfo() {
    return { name: "cuttermcp-plus-fixture", version: "0.4.0" };
  }
  async close() {
    this.closes += 1;
    if (this.failClose) throw new Error("Upstream release failed");
  }
  detach() {
    this.detaches += 1;
  }
  async call(
    name: string,
    args: Readonly<Record<string, JsonValue>>,
  ): Promise<JsonValue> {
    this.calls.push({ name, args: structuredClone(args) });
    await this.beforeCall?.(name, args);
    // The simulated world returns exactly what FastMCP would place under `result`.
    return structuredClone(this.world.call(name, args)) as JsonValue;
  }
}
