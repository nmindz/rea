import { z } from "zod";
import { AnalysisProtocolError } from "../domain/analysisErrorCore.js";

const hex = (value: bigint): string => `0x${value.toString(16)}`;

/**
 * Normalize an upstream coordinate without passing through a JavaScript
 * number beyond its exact integer range. Rizin JSON prints decimal integers;
 * a value JSON.parse could not represent exactly is refused, never rounded.
 */
export const cutterAddressSchema = z
  .union([
    z.string().regex(/^0x[0-9a-f]+$/iu),
    z
      .number()
      .int()
      .nonnegative()
      .refine(Number.isSafeInteger, "address exceeds the exact integer range"),
  ])
  .transform((value) => hex(BigInt(value)));

/** Format a validated address for an upstream request; only this spelling is ever sent. */
export const cutterRequestAddress = (value: string): string =>
  hex(BigInt(value));

/** Compare normalized coordinates. */
export const cutterAddressValue = (value: string): bigint => BigInt(value);

const functionRowSchema = z.looseObject({
  addr: cutterAddressSchema,
  name: z.string().min(1),
});
/** `list_functions` passes the plugin's pagination envelope through unchanged. */
export const cutterFunctionsPageSchema = z.looseObject({
  items: z.array(functionRowSchema),
  total: z.int().nonnegative(),
  offset: z.int().nonnegative(),
  limit: z.int().positive(),
});

const stringRowSchema = z.looseObject({
  addr: cutterAddressSchema,
  string: z.string(),
});
export const cutterStringsPageSchema = z.array(stringRowSchema);

const sectionRowSchema = z
  .looseObject({
    name: z.string().nullable(),
    vaddr: cutterAddressSchema,
    paddr: cutterAddressSchema,
    size: z.int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    perm: z.union([z.string(), z.int().nonnegative()]).nullable(),
  })
  .transform((row) => ({ ...row, name: row.name ?? "" }));
export const cutterSegmentsPageSchema = z.array(sectionRowSchema);

const symbolRowSchema = z.looseObject({
  name: z.string().min(1),
  addr: cutterAddressSchema,
});
export const cutterGlobalsPageSchema = z.array(symbolRowSchema);

const entryRowSchema = z.looseObject({
  vaddr: cutterAddressSchema,
  paddr: cutterAddressSchema,
});
export const cutterEntryPointsSchema = z.array(entryRowSchema);

const referenceSchema = z.looseObject({
  from: cutterAddressSchema,
  type: z.string(),
  fcn_addr: cutterAddressSchema.optional(),
  fcn_name: z.string().min(1).optional(),
});
export const cutterXrefsSchema = z.array(referenceSchema);
export type CutterReference = z.infer<typeof referenceSchema>;

const callReferenceSchema = z.looseObject({
  addr: cutterAddressSchema,
  type: z.string(),
});

const functionInfoSchema = z.looseObject({
  offset: cutterAddressSchema,
  name: z.string().min(1),
  signature: z.string().optional(),
  callrefs: z.array(callReferenceSchema).optional(),
});
/** An empty `info` object is the plugin's answer for an address inside no function. */
const noFunctionSchema = z.strictObject({});
export const cutterFunctionInfoSchema = z.union([
  functionInfoSchema,
  noFunctionSchema,
]);

/** Function facts for an address; the empty variant means it is inside no function. */
export type CutterFunctionInfo = z.infer<typeof cutterFunctionInfoSchema>;
/** Function facts for an address that is inside a function. */
export type CutterFunctionEntryInfo = z.infer<typeof functionInfoSchema>;

/** Narrow function facts to the variant that identifies a function. */
export const isCutterFunctionEntry = (
  info: CutterFunctionInfo,
): info is CutterFunctionEntryInfo => "offset" in info;

export const cutterFunctionDetailSchema = z.looseObject({
  info: cutterFunctionInfoSchema,
  xrefs_in: cutterXrefsSchema,
});

const instructionSchema = z
  .looseObject({
    offset: cutterAddressSchema,
    disasm: z.string().optional(),
    opcode: z.string().optional(),
  })
  .refine(
    ({ disasm, opcode }) => disasm !== undefined || opcode !== undefined,
    "instruction omits its disassembly text",
  );
export const cutterDisassemblySchema = z.looseObject({
  name: z.string().min(1),
  addr: cutterAddressSchema,
  ops: z.array(instructionSchema),
});
export type CutterDisassembly = z.infer<typeof cutterDisassemblySchema>;

export const cutterBytesSchema = z.looseObject({
  bytes: z.array(z.int().min(0).max(255)),
});

export const cutterPseudocodeSchema = z.string();
export const cutterCurrentAddressSchema = cutterAddressSchema;

/** The wrapper reports a function with no recoverable disassembly as `{}` or `{addr, json: null}`. */
export const cutterDisassemblyUnavailable = (value: unknown): boolean =>
  typeof value === "object" &&
  value !== null &&
  !Array.isArray(value) &&
  (Object.keys(value).length === 0 ||
    (Object.hasOwn(value, "json") && Reflect.get(value, "json") === null));

/** The page cap guard shared by every cursorless upstream inventory. */
export const assertCutterPageAdvanced = (
  previous: unknown,
  current: unknown,
  tool: string,
): void => {
  if (JSON.stringify(previous) === JSON.stringify(current))
    throw new AnalysisProtocolError(
      `Cutter MCP ${tool} returned the same page twice; its pagination did not advance.`,
    );
};

/** Instruction text in the upstream's own spelling. */
export const cutterInstructionText = (
  instruction: CutterDisassembly["ops"][number],
): string => instruction.disasm ?? instruction.opcode ?? "";
