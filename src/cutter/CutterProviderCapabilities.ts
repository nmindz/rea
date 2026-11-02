import type { CapabilityDescriptor } from "../application/AnalysisProvider.js";
import { REGEX_MATCHING_LIMITATION } from "../process/RegexMatcher.js";
import {
  CUTTER_ANALYSIS_OPERATIONS,
  CUTTER_ANALYSIS_PROVIDER_IDENTITY,
} from "./CutterProviderMetadata.js";

export type CutterOperation = (typeof CUTTER_ANALYSIS_OPERATIONS)[number];

/** Shared limitations of observations from a live, externally mutable Cutter session. */
export const CUTTER_LIMITATIONS = Object.freeze([
  "Provider version identifies the REA Cutter adapter. Cutter, Rizin and CutterMCP+ versions are unknown unless separately observed; MCP serverInfo is reported independently.",
  "Results describe the live Cutter session. CutterMCP+ reports neither the input path or digest nor a database revision, so REA binds the target with byte probes of file-backed mapped ranges and the section layout. That check is weaker than a digest and does not prove an unpatched session, complete analysis, or the loaded slice of a multi-image file.",
  "Live results are never replayed from analysis snapshots. Target checks before and after a request provide no atomic lock against external GUI changes.",
  "Caller cancellation drains the in-flight MCP request before cleanup; it does not prove that Cutter engine work was interrupted.",
  "Complete function body ranges, typed reference edges, referenced strings and names, comments, local variables and basic blocks are unavailable in this adapter. Empty unsupported dossier facets are unknown, not observed absence.",
]);

export const CUTTER_RELATIONSHIP_LIMITATION =
  "Cutter relationships are CALL-type references it recorded. Indirect and unresolved calls, and references it did not analyze, remain unknown.";
export const CUTTER_PSEUDOCODE_LIMITATION =
  "Pseudocode is the text of Cutter's `pdg` command, which needs its Ghidra decompiler plugin; empty output is reported as unavailable. It is a reconstruction, never original source, and is not comparable with another provider's text.";
const OPERATION_LIMITATIONS: Partial<Record<CutterOperation, string>> = {
  list_strings:
    "Strings are Cutter's `izj` string table; encoding, termination and referencing code are not reported, and text outside that table can be missing.",
  search_strings:
    "Strings are Cutter's `izj` string table; encoding, termination and referencing code are not reported, and text outside that table can be missing.",
  list_names:
    "Names are Cutter's `isj` symbol table (symbols, imports and exports), not every flag or label.",
  list_segments:
    "Rows are Cutter's `iSj` sections. Size is the virtual size when Cutter reports one, and permissions are the upstream permission string.",
  read_bytes:
    "Bytes come from `pxj` through Cutter's I/O layer, so patches and engine-filled unmapped ranges are indistinguishable from file contents. One request reads at most 65536 bytes.",
  current_address:
    "The address is Cutter's seek position at read time and can change between requests.",
  current_procedure:
    "The procedure contains Cutter's seek position at read time and can change between requests.",
  procedure_pseudo_code: CUTTER_PSEUDOCODE_LIMITATION,
  analyze_function: CUTTER_PSEUDOCODE_LIMITATION,
  procedure_callers: CUTTER_RELATIONSHIP_LIMITATION,
  procedure_callees: CUTTER_RELATIONSHIP_LIMITATION,
  xrefs:
    "References are Cutter's `axtj` results for exactly the requested address; indirect references can be missing and the upstream reports no truncation marker.",
};

/** Advertise live observations and the stdio lifecycle effects truthfully. */
export const cutterCapabilities = (
  regexLimitation = REGEX_MATCHING_LIMITATION,
): readonly CapabilityDescriptor[] =>
  CUTTER_ANALYSIS_OPERATIONS.map((operation) => {
    const specific = OPERATION_LIMITATIONS[operation];
    return {
      provider: CUTTER_ANALYSIS_PROVIDER_IDENTITY,
      operation,
      available: true,
      reason: null,
      cachePolicy: "live",
      effects: {
        mutatesArtifact: false,
        launchesProcess: true,
        mayShowUi: false,
        mayAccessNetwork: true,
        mayWriteFilesystem: true,
        changesPermissions: false,
        requiresRoot: false,
      },
      limitations: [
        ...CUTTER_LIMITATIONS,
        ...(specific === undefined ? [] : [specific]),
        ...(operation === "search_procedures" || operation === "search_strings"
          ? [regexLimitation]
          : []),
      ],
    };
  });
