import { z } from "zod";
import type { RegexMatchingDeadline } from "../config/regexMatchingDeadline.js";
import type { RegexWorkerHeapRequest } from "../config/regexWorkerHeapRequest.js";
import {
  analysisSearchPredicate,
  analysisSearchQuerySchema,
  type AnalysisSearchQuery,
} from "../domain/analysisSearch.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import type { EvidenceLocation } from "../domain/evidence.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { combineFunctionRelationshipCoverage } from "../domain/functionCallCoverage.js";
import {
  functionDossierSchema,
  functionInstructionWindowSchema,
} from "../domain/native/functionDossier.js";
import type { RelationshipCoverage } from "../domain/relationshipCoverage.js";
import {
  launchRegexMatchingLimitation,
  matchRegexValues,
} from "../process/RegexMatcher.js";
import type { CutterMcpConnection } from "./CutterMcpConnection.js";
import {
  CUTTER_LIMITATIONS,
  CUTTER_PSEUDOCODE_LIMITATION,
  CUTTER_RELATIONSHIP_LIMITATION,
  type CutterOperation,
} from "./CutterProviderCapabilities.js";
import type { CutterReadTool } from "./CutterProviderMetadata.js";
import { CUTTER_MAX_READ_BYTES, isCutterHexAddress } from "./CutterInput.js";
import {
  assertCutterPageAdvanced,
  cutterAddressSchema,
  cutterAddressValue,
  cutterBytesSchema,
  cutterCurrentAddressSchema,
  cutterDisassemblySchema,
  cutterDisassemblyUnavailable,
  cutterFunctionDetailSchema,
  cutterFunctionInfoSchema,
  cutterFunctionsPageSchema,
  cutterGlobalsPageSchema,
  cutterInstructionText,
  isCutterFunctionEntry,
  cutterPseudocodeSchema,
  cutterRequestAddress,
  cutterSegmentsPageSchema,
  cutterStringsPageSchema,
  cutterXrefsSchema,
  type CutterDisassembly,
  type CutterFunctionEntryInfo,
  type CutterFunctionInfo,
  type CutterReference,
} from "./CutterProtocol.js";
import { cutterPermissionFlags } from "./CutterSections.js";

/** Largest page the CutterMCP+ plugin serves. */
const PAGE_SIZE = 1000;

/** One operation's raw source observations, retained alongside normalized results. */
export interface CutterRawObservation {
  readonly tool: CutterReadTool;
  readonly arguments: Readonly<Record<string, JsonValue>>;
  readonly result: JsonValue;
}

/** Function identity reported by Cutter: entry address and name. */
export interface CutterFunction {
  readonly address: string;
  readonly name: string;
}

const unknownBody = {
  available: false,
  reason: "Cutter MCP does not report complete function body ranges.",
} as const;
const identity = (fn: CutterFunction) => ({
  address: fn.address,
  name: fn.name,
  symbol: null,
  classification: null,
  body: unknownBody,
});
interface CutterRelationships {
  readonly items: ReturnType<typeof identity>[];
  readonly coverage: RelationshipCoverage;
}
interface CutterFunctionDetail {
  readonly info: CutterFunctionInfo;
  readonly xrefsIn: readonly CutterReference[];
}

const isCall = (type: string): boolean => type.toLowerCase() === "call";
const lines = (assembly: CutterDisassembly): string[] =>
  assembly.ops.map((op) => `${op.offset}: ${cutterInstructionText(op)}`);
const hex = (value: bigint): string => `0x${value.toString(16)}`;

/** Translate explicit analyst questions into a closed set of read-only upstream requests. */
export class CutterOperationRunner {
  readonly raw: CutterRawObservation[] = [];
  readonly locations: EvidenceLocation[] = [];
  readonly limitations: string[] = [];
  relationshipCoverage: RelationshipCoverage | undefined;
  #inventory: Promise<CutterFunction[]> | undefined;
  readonly #details = new Map<string, Promise<CutterFunctionDetail>>();

  constructor(
    private readonly connection: CutterMcpConnection,
    private readonly options: {
      readonly signal?: AbortSignal | undefined;
      readonly regexMatchingDeadline?: RegexMatchingDeadline | undefined;
      readonly regexWorkerHeapRequest?: RegexWorkerHeapRequest | undefined;
      readonly selectorOrigin?: "provider" | undefined;
      /** The program identity REA admitted, reported by `list_documents`. */
      readonly admittedDocument: string;
    },
  ) {}

  async call(
    tool: CutterReadTool,
    args: Readonly<Record<string, JsonValue>>,
  ): Promise<JsonValue> {
    const signal = this.options.signal;
    if (signal?.aborted === true)
      throw new AnalysisCancelledError(tool, { cause: signal.reason });
    const result = await this.connection.call(tool, args, { signal });
    this.raw.push({ tool, arguments: args, result });
    if (this.options.signal?.aborted === true)
      throw new AnalysisCancelledError(tool, {
        cause: this.options.signal.reason,
      });
    return result;
  }

  /** The plugin's cursorless inventories end at the first empty page. */
  async #pages<Row>(
    tool: "list_strings" | "list_segments" | "list_globals",
    parse: (raw: JsonValue) => readonly Row[],
  ): Promise<Row[]> {
    const rows: Row[] = [];
    let previous: JsonValue | undefined;
    for (let offset = 0; ;) {
      const raw = await this.call(tool, { offset, limit: PAGE_SIZE });
      const page = parse(raw);
      if (page.length === 0) return rows;
      if (previous !== undefined) assertCutterPageAdvanced(previous, raw, tool);
      previous = raw;
      rows.push(...page);
      offset += page.length;
    }
  }

  #functions(): Promise<CutterFunction[]> {
    this.#inventory ??= (async () => {
      const result: CutterFunction[] = [];
      for (let offset = 0; ;) {
        const page = cutterFunctionsPageSchema.parse(
          await this.call("list_functions", { offset, limit: PAGE_SIZE }),
        );
        if (page.offset !== offset)
          throw new AnalysisProtocolError(
            "Cutter MCP list_functions answered for a different offset than requested.",
          );
        result.push(
          ...page.items.map(({ addr, name }) => ({ address: addr, name })),
        );
        offset += page.items.length;
        if (offset >= page.total) return result;
        if (page.items.length === 0)
          throw new AnalysisProtocolError(
            "Cutter MCP list_functions pagination did not advance its offset.",
          );
      }
    })();
    return this.#inventory;
  }

  #missing(requestedBy: string, message: string): AnalysisInputError {
    return new AnalysisInputError(requestedBy, undefined, [
      { path: ["procedure"], reason: "invalid_value", message },
    ]);
  }

  /**
   * Resolve a procedure. A caller-supplied selector that names no function is
   * reported as invalid input; `requestedBy` is omitted for provider-derived
   * selectors, whose failure is a producer fault.
   */
  async resolve(query: string, requestedBy?: string): Promise<CutterFunction> {
    const missing = (message: string): Error =>
      requestedBy === undefined
        ? new AnalysisProtocolError(message)
        : this.#missing(requestedBy, message);
    if (query.startsWith("file-offset:"))
      throw this.#missing(
        requestedBy ?? "procedure_address",
        "Cutter does not support file-offset: procedure selectors. Select Ghidra for source-file coordinates or supply a Cutter analysis address or exact function name.",
      );
    if (isCutterHexAddress(query)) {
      const detail = await this.#detailAt(cutterAddressSchema.parse(query));
      if (!isCutterFunctionEntry(detail.info))
        throw missing(
          `Cutter could not resolve procedure ${JSON.stringify(query)}: the address is inside no function.`,
        );
      return { address: detail.info.offset, name: detail.info.name };
    }
    const matches = (await this.#functions()).filter(
      ({ name }) => name === query,
    );
    if (matches.length === 1) return matches[0]!;
    throw missing(
      matches.length === 0
        ? `Cutter could not resolve procedure ${JSON.stringify(query)}: no function has that exact name. Use list_procedures or search_procedures, or select it by address.`
        : `Cutter function name ${JSON.stringify(query)} is ambiguous (${matches.map(({ address }) => address).join(", ")}); select it by address.`,
    );
  }

  /** One `function_detail` read per entry, shared by every facet of an operation. */
  #detailAt(address: string): Promise<CutterFunctionDetail> {
    const cached = this.#details.get(address);
    if (cached !== undefined) return cached;
    const detail = this.call("function_detail", {
      addr: cutterRequestAddress(address),
    }).then((raw): CutterFunctionDetail => {
      const parsed = cutterFunctionDetailSchema.parse(raw);
      return { info: parsed.info, xrefsIn: parsed.xrefs_in };
    });
    this.#details.set(address, detail);
    return detail;
  }

  async #entryDetail(fn: CutterFunction): Promise<{
    readonly info: CutterFunctionEntryInfo;
    readonly xrefsIn: readonly CutterReference[];
  }> {
    const { info, xrefsIn } = await this.#detailAt(fn.address);
    if (!isCutterFunctionEntry(info) || info.offset !== fn.address)
      throw new AnalysisProtocolError(
        "Cutter function detail identifies a different function than the resolved entry.",
      );
    return { info, xrefsIn };
  }

  async assembly(fn: CutterFunction): Promise<CutterDisassembly> {
    const raw = await this.call("disasm_by_func_json", {
      addr: cutterRequestAddress(fn.address),
    });
    if (cutterDisassemblyUnavailable(raw))
      throw new AnalysisProtocolError(
        `Cutter returned no disassembly for ${fn.name}.`,
      );
    const assembly = cutterDisassemblySchema.parse(raw);
    if (assembly.addr !== fn.address)
      throw new AnalysisProtocolError(
        "Cutter disassembly identifies a different function than the resolved entry.",
      );
    return assembly;
  }

  async pseudocode(fn: CutterFunction): Promise<string | null> {
    const text = cutterPseudocodeSchema.parse(
      await this.call("decompile", { addr: cutterRequestAddress(fn.address) }),
    );
    if (text.trim().length > 0) return text;
    this.limitations.push(
      "Cutter returned no pseudocode; its decompiler plugin may be missing or the function may be undecompilable.",
    );
    return null;
  }

  async #xrefsTo(address: string): Promise<CutterReference[]> {
    return cutterXrefsSchema.parse(
      await this.call("xrefs_to", { addr: cutterRequestAddress(address) }),
    );
  }

  async relationships(
    fn: CutterFunction,
    direction: "callers" | "callees",
  ): Promise<CutterRelationships> {
    const { info, xrefsIn } = await this.#entryDetail(fn);
    const result = new Map<string, ReturnType<typeof identity>>();
    const limitations = [CUTTER_RELATIONSHIP_LIMITATION];
    if (direction === "callers") {
      let outside = 0;
      for (const ref of xrefsIn) {
        if (!isCall(ref.type)) continue;
        if (ref.fcn_addr === undefined || ref.fcn_name === undefined) {
          outside += 1;
          continue;
        }
        result.set(
          ref.fcn_addr,
          identity({ address: ref.fcn_addr, name: ref.fcn_name }),
        );
      }
      if (outside > 0)
        limitations.push(
          `${String(outside)} CALL reference(s) originate outside any function Cutter recognized and are not listed as callers.`,
        );
    } else {
      const inventory = new Map(
        (await this.#functions()).map((entry) => [entry.address, entry]),
      );
      let unresolved = 0;
      for (const ref of info.callrefs ?? []) {
        if (!isCall(ref.type) || result.has(ref.addr)) continue;
        const callee = inventory.get(ref.addr);
        if (callee === undefined) {
          unresolved += 1;
          continue;
        }
        result.set(callee.address, identity(callee));
      }
      if (unresolved > 0)
        limitations.push(
          `${String(unresolved)} CALL target(s) are not entries of a discovered function and are not listed as callees.`,
        );
    }
    this.limitations.push(...limitations.slice(1));
    return {
      items: [...result.values()],
      coverage: { status: "partial", limitations },
    };
  }

  async #searchItems<Row extends { readonly value: string }>(
    operation: CutterOperation,
    items: Row[],
    query: AnalysisSearchQuery | undefined,
  ): Promise<Row[]> {
    if (query === undefined) return items;
    if (query.mode === "literal") {
      const matches = analysisSearchPredicate(query);
      return items.filter(({ value }) => matches(value));
    }
    this.limitations.push(
      launchRegexMatchingLimitation(
        this.options.regexMatchingDeadline,
        this.options.regexWorkerHeapRequest,
      ),
    );
    const matched = await matchRegexValues({
      operation,
      pattern: query.pattern,
      caseSensitive: query.case_sensitive,
      values: items.map(({ value }) => value),
      deadline: this.options.regexMatchingDeadline,
      heapRequest: this.options.regexWorkerHeapRequest,
      signal: this.options.signal,
    });
    if (!matched.ok) throw matched.error;
    const indices = new Set(matched.value);
    return items.filter((_, index) => indices.has(index));
  }

  async #sections() {
    return (
      await this.#pages("list_segments", (raw) =>
        cutterSegmentsPageSchema.parse(raw),
      )
    ).map((section) => {
      const flags = cutterPermissionFlags(section.perm);
      const start = cutterAddressValue(section.vaddr);
      const region = {
        name: section.name,
        start: section.vaddr,
        end: hex(start + BigInt(section.size)),
        readable: flags?.readable ?? null,
        writable: flags?.writable ?? null,
        executable: flags?.executable ?? null,
        permissions:
          flags === undefined
            ? {
                available: false,
                reason:
                  "Cutter reported no permission string for this section.",
              }
            : { available: true, source: "cutter-section-table" },
        provenance: "cutter-section-table",
      };
      return { ...region, sections: [] };
    });
  }

  /** The containing function of an address, or why none contains it. */
  async #containingProcedure(address: string): Promise<JsonValue> {
    const detail = await this.#detailAt(address);
    if (isCutterFunctionEntry(detail.info))
      return {
        query_address: address,
        found: true,
        procedure: identity({
          address: detail.info.offset,
          name: detail.info.name,
        }),
      };
    const value = cutterAddressValue(address);
    const mapped = (await this.#sections()).some(
      ({ start, end }) =>
        cutterAddressValue(start) <= value && value < cutterAddressValue(end),
    );
    return {
      query_address: address,
      found: false,
      procedure: null,
      reason: mapped ? "not_in_procedure" : "outside_segments",
    };
  }

  async #bytes(address: string, length: number): Promise<JsonValue> {
    const value = cutterBytesSchema.parse(
      await this.call("read_bytes", {
        addr: cutterRequestAddress(address),
        size: length,
      }),
    );
    if (value.bytes.length > length)
      throw new AnalysisProtocolError(
        "Cutter returned more bytes than the request selected.",
      );
    return {
      address,
      requested_bytes: length,
      returned_bytes: value.bytes.length,
      bytes_hex: Buffer.from(value.bytes).toString("hex"),
      complete: value.bytes.length === length,
    };
  }

  async run(
    operation: CutterOperation,
    parameters: Readonly<Record<string, JsonValue>>,
  ): Promise<JsonValue> {
    const query =
      operation === "search_procedures" || operation === "search_strings"
        ? analysisSearchQuerySchema.parse(parameters)
        : undefined;
    switch (operation) {
      case "list_documents":
        return [this.options.admittedDocument];
      case "list_procedures":
      case "search_procedures": {
        const items = (await this.#functions()).map((fn) => ({
          address: fn.address,
          value: fn.name,
        }));
        return this.#searchItems(operation, items, query);
      }
      case "list_strings":
      case "search_strings": {
        const selected =
          query === undefined && parameters.address !== undefined
            ? cutterAddressSchema.parse(parameters.address)
            : undefined;
        const items = (
          await this.#pages("list_strings", (raw) =>
            cutterStringsPageSchema.parse(raw),
          )
        ).map((row) => ({ address: row.addr, value: row.string }));
        return query !== undefined
          ? this.#searchItems(operation, items, query)
          : selected === undefined
            ? items
            : items.filter(({ address }) => address === selected);
      }
      case "list_names": {
        const selected =
          parameters.address === undefined
            ? undefined
            : cutterAddressSchema.parse(parameters.address);
        const items = (
          await this.#pages("list_globals", (raw) =>
            cutterGlobalsPageSchema.parse(raw),
          )
        ).map((row) => ({ address: row.addr, value: row.name }));
        return selected === undefined
          ? items
          : items.filter(({ address }) => address === selected);
      }
      case "list_segments":
        return this.#sections();
      case "resolve_containing_procedure": {
        const queried = cutterAddressSchema.parse(parameters.address);
        this.locations.push({ kind: "address", address: queried });
        return this.#containingProcedure(queried);
      }
      case "xrefs": {
        const inspected = cutterAddressSchema.parse(parameters.address);
        this.locations.push({ kind: "address", address: inspected });
        return [
          ...new Set((await this.#xrefsTo(inspected)).map(({ from }) => from)),
        ];
      }
      case "read_bytes": {
        const address = cutterAddressSchema.parse(parameters.address);
        this.locations.push({ kind: "address", address });
        return this.#bytes(
          address,
          z.int().min(1).max(CUTTER_MAX_READ_BYTES).parse(parameters.length),
        );
      }
      case "current_address":
        return cutterCurrentAddressSchema.parse(
          await this.call("current_address", {}),
        );
      case "current_procedure": {
        const info = cutterFunctionInfoSchema.parse(
          await this.call("current_function", {}),
        );
        if (!isCutterFunctionEntry(info))
          throw new AnalysisCapabilityUnavailableError(
            "cutter",
            operation,
            "Cutter's current address is inside no recognized function.",
            {
              retryable: true,
              remediationAction:
                "Move Cutter's cursor into a function, or select a procedure explicitly with procedure_address.",
            },
          );
        this.locations.push({ kind: "address", address: info.offset });
        return info.name;
      }
    }
    const fn = await this.resolve(
      z.string().min(1).parse(parameters.procedure),
      this.options.selectorOrigin === "provider" ? undefined : operation,
    );
    this.locations.push({ kind: "address", address: fn.address });
    switch (operation) {
      case "procedure_address":
        return fn.address;
      case "procedure_pseudo_code":
        return this.pseudocode(fn);
      case "procedure_assembly":
        return lines(await this.assembly(fn)).join("\n");
      case "procedure_callers":
      case "procedure_callees": {
        const relationships = await this.relationships(
          fn,
          operation === "procedure_callers" ? "callers" : "callees",
        );
        this.relationshipCoverage = relationships.coverage;
        return relationships.items.map(({ address }) => address);
      }
      case "read_function_instructions":
        return functionInstructionWindowSchema.parse({
          procedure: identity(fn),
          instructions: lines(await this.assembly(fn)),
          limitations: CUTTER_LIMITATIONS,
        });
      case "analyze_function":
        return this.#dossier(fn);
    }
  }

  async #dossier(fn: CutterFunction): Promise<JsonValue> {
    const assembly = await this.assembly(fn);
    const pseudocode = await this.pseudocode(fn);
    const callers = await this.relationships(fn, "callers");
    const callees = await this.relationships(fn, "callees");
    this.relationshipCoverage = combineFunctionRelationshipCoverage(
      callers.coverage,
      callees.coverage,
    );
    const { info } = await this.#entryDetail(fn);
    const signature = info.signature?.trim();
    return functionDossierSchema.parse({
      procedure: {
        ...identity(fn),
        signature:
          signature === undefined || signature.length === 0 ? null : signature,
        locals: [],
      },
      pseudocode: pseudocode ?? "",
      assembly: lines(assembly),
      comments: [],
      callers: callers.items,
      callees: callees.items,
      incoming_references: [],
      outgoing_references: [],
      referenced_strings: [],
      referenced_names: [],
      basic_blocks: [],
      native_api: null,
      native_value_flow: null,
      facet_availability: {
        pseudocode:
          pseudocode === null
            ? { available: false, reason: "Cutter did not supply pseudocode." }
            : { available: true },
        assembly: { available: true },
        comments: {
          available: false,
          reason: "Cutter MCP does not expose comments.",
        },
        callers: { available: true },
        callees: { available: true },
        references: {
          available: false,
          reason: "Cutter MCP does not expose typed reference edges.",
        },
        strings_names: {
          available: false,
          reason:
            "Cutter MCP does not expose function-referenced strings and names.",
        },
        cfg: {
          available: false,
          reason: "Cutter MCP does not expose basic blocks.",
        },
      },
      limitations: [
        ...CUTTER_LIMITATIONS,
        CUTTER_PSEUDOCODE_LIMITATION,
        ...this.limitations,
        "Local variables are not reported; an empty locals list is unknown, not observed absence.",
        ...(pseudocode === null ? ["Pseudocode is unavailable."] : []),
      ],
    });
  }
}
