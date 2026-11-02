import { appendFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

/**
 * A simulated CutterMCP+ upstream. Its tool names, argument names and result
 * shapes follow the 0.4.0 `mcp_server.py` wrapper as observed through FastMCP
 * (`structuredContent: {result: ...}`), but nothing here is a real Cutter,
 * Rizin or plugin. It establishes REA's adapter behavior only.
 */

export const FILE_SIZE = 4096;
const TEXT_PADDR = 0x100;
const TEXT_VADDR = 0x401000;
const ENTRY_VADDR = 0x401080;

/** The "original input": a minimal x86_64 ELF header followed by deterministic bytes. */
export const cutterFixtureBytes = () => {
  const bytes = Buffer.alloc(FILE_SIZE);
  for (let index = 0; index < bytes.length; index++)
    bytes[index] = (index * 31 + 7) & 0xff;
  bytes.fill(0, 0, 64);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  bytes.writeUInt16LE(62, 18);
  bytes.writeUInt32LE(1, 20);
  bytes.writeUInt16LE(64, 52);
  return bytes;
};

const hex = (value) => `0x${value.toString(16)}`;

const sections = () => [
  {
    name: ".text",
    vaddr: TEXT_VADDR,
    paddr: TEXT_PADDR,
    size: 0x200,
    perm: "-r-x",
  },
  { name: ".rodata", vaddr: 0x402000, paddr: 0x300, size: 0x100, perm: "-r--" },
  { name: ".bss", vaddr: 0x403000, paddr: 0, size: 0x100, perm: "-rw-" },
];

const functions = () => [
  { addr: 0x401000, name: "main", size: 0x40, n_bb: 2 },
  { addr: 0x401040, name: "sym.helper", size: 0x20, n_bb: 1 },
  { addr: 0x401080, name: "entry0", size: 0x30, n_bb: 1 },
  { addr: 0x401100, name: "sym.imp.puts", size: 0x10, n_bb: 1 },
];

const ops = {
  0x401000: [
    { offset: 0x401000, disasm: "push rbp", bytes: "55", type: "rpush" },
    {
      offset: 0x401004,
      disasm: "call sym.helper",
      bytes: "e837000000",
      type: "call",
      jump: 0x401040,
    },
    {
      offset: 0x401020,
      disasm: "call sym.imp.puts",
      bytes: "e8db000000",
      type: "call",
      jump: 0x401100,
    },
    { offset: 0x40103f, disasm: "ret", bytes: "c3", type: "ret" },
  ],
  0x401040: [{ offset: 0x401040, disasm: "ret", bytes: "c3", type: "ret" }],
  0x401080: [
    { offset: 0x401080, disasm: "xor ebp, ebp", bytes: "31ed", type: "xor" },
    {
      offset: 0x401090,
      disasm: "call main",
      bytes: "e86bffffff",
      type: "call",
      jump: 0x401000,
    },
  ],
  0x401100: [
    {
      offset: 0x401100,
      disasm: "jmp qword [reloc.puts]",
      bytes: "ff25",
      type: "ujmp",
    },
  ],
};

const callrefs = {
  0x401000: [
    { addr: 0x401040, type: "CALL", at: 0x401004 },
    { addr: 0x401100, type: "CALL", at: 0x401020 },
    { addr: 0x402000, type: "DATA", at: 0x40101c },
    { addr: 0x409999, type: "CALL", at: 0x401030 },
  ],
  0x401040: [],
  0x401080: [{ addr: 0x401000, type: "CALL", at: 0x401090 }],
  0x401100: [],
};

const xrefs = {
  0x401000: [
    { from: 0x401090, type: "CALL", fcn_addr: 0x401080, fcn_name: "entry0" },
    { from: 0x402008, type: "DATA" },
    { from: 0x407000, type: "CALL" },
  ],
  0x401040: [
    { from: 0x401004, type: "CALL", fcn_addr: 0x401000, fcn_name: "main" },
  ],
  0x401100: [
    { from: 0x401020, type: "CALL", fcn_addr: 0x401000, fcn_name: "main" },
  ],
};

const decompilations = {
  0x401000:
    'int main(void) {\n  sym.helper();\n  sym.imp.puts("hello");\n  return 0;\n}',
  0x401040: "void sym.helper(void) {\n  return;\n}",
};

/** Mutable simulated session state shared by tests. */
export class CutterWorld {
  /** Bytes the session maps for file-backed sections; tests mutate this to simulate a different file. */
  fileBytes = cutterFixtureBytes();
  sections = sections();
  entries = [
    { vaddr: ENTRY_VADDR, paddr: ENTRY_VADDR - TEXT_VADDR + TEXT_PADDR },
  ];
  seek = 0x401004;
  /** Largest page the plugin serves; a smaller value simulates a clamped upstream. */
  pageClamp = 1000;
  /** Replace a section's content type for decompile output; false simulates a missing decompiler. */
  decompiler = true;
  /** Observed tool names, in order. */
  calls = [];

  /** Flip every bit of one mapped file byte, as if Cutter had loaded a different file. */
  corrupt(index) {
    this.fileBytes[index] ^= 0xff;
  }

  #containing(address) {
    return functions().find(
      ({ addr, size }) => addr <= address && address < addr + size,
    );
  }

  #page(rows, args) {
    const offset = Number(args.offset ?? 0);
    const limit = Math.min(Number(args.limit ?? 100), this.pageClamp);
    return rows.slice(offset, offset + limit);
  }

  /** The mapped byte at an address, or undefined past the last mapped byte. */
  #byteAt(address) {
    const section = this.sections.find(
      ({ vaddr, size }) => vaddr <= address && address < vaddr + size,
    );
    if (section === undefined) return undefined;
    if (section.paddr === 0) return 0;
    return this.fileBytes[section.paddr + (address - section.vaddr)];
  }

  /** Handle one tool call and return the value FastMCP would place under `result`. */
  call(tool, args = {}) {
    this.calls.push(tool);
    const address =
      args.addr === undefined ? undefined : Number(BigInt(args.addr));
    switch (tool) {
      case "list_functions": {
        const rows = functions().map(({ addr, name, size, n_bb }) => ({
          addr: hex(addr),
          name,
          size,
          n_bb,
        }));
        const offset = Number(args.offset ?? 0);
        const limit = Math.min(Number(args.limit ?? 50), this.pageClamp);
        return {
          items: rows.slice(offset, offset + limit),
          total: rows.length,
          offset,
          limit,
        };
      }
      case "function_detail": {
        const fn = this.#containing(address);
        if (fn === undefined) return { info: {}, xrefs_in: [] };
        return {
          info: {
            offset: fn.addr,
            name: fn.name,
            size: fn.size,
            signature: fn.name === "main" ? "int main (void);" : "",
            callrefs: callrefs[fn.addr] ?? [],
          },
          xrefs_in: address === fn.addr ? (xrefs[fn.addr] ?? []) : [],
        };
      }
      case "list_strings":
        return this.#page(
          [
            { addr: "0x402000", length: 5, type: "ascii", string: "hello" },
            { addr: "0x402010", length: 5, type: "ascii", string: "a.b\nC" },
          ],
          args,
        );
      case "list_segments":
        return this.#page(
          this.sections.map(({ name, vaddr, paddr, size, perm }) => ({
            name,
            vaddr: hex(vaddr),
            paddr: hex(paddr),
            size,
            perm,
          })),
          args,
        );
      case "list_globals":
        return this.#page(
          [
            {
              name: "main",
              addr: "0x401000",
              paddr: "0x0",
              size: 64,
              bind: "GLOBAL",
              type: "FUNC",
            },
            {
              name: "sym.imp.puts",
              addr: "0x401100",
              paddr: "0x0",
              size: 16,
              bind: "GLOBAL",
              type: "FUNC",
            },
          ],
          args,
        );
      case "list_entry_points":
        return this.entries.map(({ vaddr, paddr }) => ({
          vaddr,
          paddr,
          baddr: 0x400000,
          type: "program",
        }));
      case "decompile":
        return this.decompiler ? (decompilations[address] ?? "") : "";
      case "disasm_by_func_json": {
        const list = ops[address];
        if (list === undefined) return {};
        const fn = this.#containing(address);
        return { name: fn.name, size: fn.size, addr: fn.addr, ops: list };
      }
      case "xrefs_to":
        return xrefs[address] ?? [];
      case "read_bytes": {
        const size = Number(args.size ?? 64);
        const bytes = [];
        // A read stops at the first unmapped byte, like an upstream that returns a short reply.
        for (let index = 0; index < size; index++) {
          const value = this.#byteAt(address + index);
          if (value === undefined) break;
          bytes.push(value);
        }
        return { addr: args.addr, size, bytes };
      }
      case "current_address":
        return hex(this.seek);
      case "current_function": {
        const fn = this.#containing(this.seek);
        return fn === undefined
          ? {}
          : { offset: fn.addr, name: fn.name, size: fn.size, callrefs: [] };
      }
      default:
        throw new Error(`Unimplemented upstream tool ${tool}`);
    }
  }
}

/** Every tool the 0.4.0 wrapper registers; mutators exist so tests can prove they are never called. */
export const CUTTER_READ_TOOL_NAMES = [
  "list_functions",
  "function_detail",
  "disasm_by_func_text",
  "disasm_by_func_json",
  "decompile",
  "disasm_text",
  "disasm_json",
  "list_strings",
  "list_segments",
  "read_bytes",
  "list_vars",
  "current_address",
  "current_function",
  "xrefs_to",
  "list_globals",
  "list_entry_points",
];
export const CUTTER_MUTATING_TOOL_NAMES = [
  "rename_function",
  "set_comment",
  "rename_local_variable",
  "set_local_variable_type",
];

const content = (value) => {
  if (typeof value === "string") return [{ type: "text", text: value }];
  // FastMCP emits one text block per list element, so only structuredContent is complete.
  if (Array.isArray(value))
    return value.map((item) => ({ type: "text", text: JSON.stringify(item) }));
  return [{ type: "text", text: JSON.stringify(value) }];
};

/** Serve the simulated upstream over stdio MCP when this file is the entry point. */
const serve = () => {
  const options = JSON.parse(process.env.CUTTER_FIXTURE_OPTIONS ?? "{}");
  const log = process.env.CUTTER_FIXTURE_CALL_LOG;
  const world = new CutterWorld();
  if (options.mutateImage === true) world.corrupt(0x180);
  if (options.pageClamp !== undefined) world.pageClamp = options.pageClamp;
  if (options.decompiler === false) world.decompiler = false;
  const hidden = new Set(options.hiddenTools ?? []);
  const hang = new Set(options.hangTools ?? []);
  if (process.env.CUTTER_FIXTURE_PID_FILE !== undefined)
    writeFileSync(process.env.CUTTER_FIXTURE_PID_FILE, String(process.pid));
  const advertised = [
    ...CUTTER_READ_TOOL_NAMES,
    ...CUTTER_MUTATING_TOOL_NAMES,
  ].filter((name) => !hidden.has(name));
  const send = (message) =>
    process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", ...message })}\n`);
  createInterface({ input: process.stdin }).on("line", (line) => {
    const request = JSON.parse(line);
    if (request.id === undefined) return;
    if (request.method === "initialize")
      return send({
        id: request.id,
        result: {
          protocolVersion: request.params.protocolVersion,
          capabilities: { tools: {} },
          serverInfo: { name: "cuttermcp-plus-fixture", version: "0.4.0" },
        },
      });
    if (request.method === "tools/list")
      return send({
        id: request.id,
        result: {
          tools: advertised.map((name) => ({
            name,
            description: `${name} (fixture)`,
            inputSchema: { type: "object", properties: {} },
          })),
        },
      });
    if (request.method === "tools/call") {
      const { name, arguments: args } = request.params;
      if (log !== undefined) appendFileSync(log, `${name}\n`);
      // A held reply lets a test cancel or time out an in-flight request.
      if (hang.has(name)) return;
      if (CUTTER_MUTATING_TOOL_NAMES.includes(name))
        return send({
          id: request.id,
          result: {
            content: content("ok"),
            structuredContent: { result: "ok" },
          },
        });
      try {
        const value = world.call(name, args);
        return send({
          id: request.id,
          result: {
            content: content(value),
            structuredContent: { result: value },
          },
        });
      } catch (cause) {
        return send({
          id: request.id,
          result: { isError: true, content: content(String(cause.message)) },
        });
      }
    }
    return send({
      id: request.id,
      error: { code: -32601, message: "Method not found" },
    });
  });
};

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
)
  serve();
