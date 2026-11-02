import { TOOL_CONTRACTS } from "../contracts/toolContracts.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import { projectInputIssues } from "../domain/inputIssueProjection.js";
import { jsonObjectSchema, type JsonValue } from "../domain/jsonValue.js";
import { err, ok } from "../domain/result.js";
import { cutterAddressSchema } from "./CutterProtocol.js";

/** The CutterMCP+ plugin reads at most this many bytes per request. */
export const CUTTER_MAX_READ_BYTES = 65_536;

const HEX_ADDRESS = /^0x[0-9a-f]+$/iu;

/** True for the only spelling REA forwards to the upstream as a coordinate. */
export const isCutterHexAddress = (value: string): boolean =>
  HEX_ADDRESS.test(value);

/**
 * Apply the named public contract and Cutter's explicit-address boundary before
 * startup. The upstream interpolates coordinates into Rizin commands, so only
 * canonical hexadecimal addresses and integers ever leave REA.
 */
export const parseCutterInput = (
  operation: string,
  parameters: Readonly<Record<string, JsonValue>>,
) => {
  const contract = TOOL_CONTRACTS.find(({ name }) => name === operation);
  const parsed = contract?.inputSchema.safeParse(parameters);
  if (parsed?.success !== true)
    return err(
      new AnalysisInputError(
        operation,
        { cause: parsed?.error },
        parsed?.error === undefined
          ? []
          : projectInputIssues(parsed.error.issues, parameters),
      ),
    );
  const required = operation === "xrefs" || operation === "read_bytes";
  if (required && typeof parameters.address !== "string")
    return err(
      new AnalysisInputError(operation, undefined, [
        {
          path: ["address"],
          reason: "missing_argument",
          message: "Cutter requires an explicit hexadecimal address.",
        },
      ]),
    );
  if (
    parameters.address !== undefined &&
    !cutterAddressSchema.safeParse(parameters.address).success
  )
    return err(
      new AnalysisInputError(operation, undefined, [
        {
          path: ["address"],
          reason: "invalid_format",
          message: "Cutter requires a 0x-prefixed hexadecimal address.",
        },
      ]),
    );
  if (
    typeof parameters.procedure === "string" &&
    parameters.procedure.length === 0
  )
    return err(
      new AnalysisInputError(operation, undefined, [
        {
          path: ["procedure"],
          reason: "invalid_value",
          message: "Supply a function name or address.",
        },
      ]),
    );
  if (
    operation === "read_bytes" &&
    typeof parameters.length === "number" &&
    parameters.length > CUTTER_MAX_READ_BYTES
  )
    return err(
      new AnalysisInputError(operation, undefined, [
        {
          path: ["length"],
          reason: "out_of_range",
          maximum: CUTTER_MAX_READ_BYTES,
          message: `CutterMCP+ reads at most ${String(CUTTER_MAX_READ_BYTES)} bytes per request.`,
        },
      ]),
    );
  if (parameters.mode === "regex" && typeof parameters.pattern === "string") {
    try {
      new RegExp(
        parameters.pattern,
        parameters.case_sensitive === true ? "u" : "iu",
      );
    } catch (cause: unknown) {
      return err(
        new AnalysisInputError(operation, { cause }, [
          {
            path: ["pattern"],
            reason: "invalid_format",
            message: "Supply a valid regular expression.",
          },
        ]),
      );
    }
  }
  return ok(jsonObjectSchema.parse(parsed.data));
};
