import type { AnalysisOperation } from "../application/AnalysisProvider.js";

/** This version identifies REA's adapter, not Cutter or the CutterMCP+ server. */
export const CUTTER_ANALYSIS_PROVIDER_IDENTITY = Object.freeze({
  id: "cutter",
  name: "Cutter MCP adapter",
  version: "1",
});

/** Read-only analyst outcomes the CutterMCP+ read tools can answer. */
export const CUTTER_ANALYSIS_OPERATIONS = Object.freeze([
  "list_documents",
  "list_procedures",
  "search_procedures",
  "list_strings",
  "search_strings",
  "list_names",
  "list_segments",
  "procedure_address",
  "procedure_pseudo_code",
  "procedure_assembly",
  "procedure_callers",
  "procedure_callees",
  "read_function_instructions",
  "resolve_containing_procedure",
  "xrefs",
  "read_bytes",
  "current_address",
  "current_procedure",
  "analyze_function",
] as const satisfies readonly Exclude<AnalysisOperation, "health">[]);

/** Upstream tools REA calls. Mutating upstream tools are never admitted. */
export const CUTTER_READ_TOOLS = Object.freeze([
  "list_functions",
  "function_detail",
  "list_globals",
  "list_strings",
  "list_segments",
  "list_entry_points",
  "decompile",
  "disasm_by_func_json",
  "xrefs_to",
  "read_bytes",
  "current_address",
  "current_function",
] as const);

export type CutterReadTool = (typeof CUTTER_READ_TOOLS)[number];
