import { z } from "zod";
import { jsonRecordSchema } from "../domain/jsonRecord.js";
import type { RetainedResourceScope } from "../application/AnalysisProvider.js";
import type { ConfigurationError } from "../domain/configurationErrors.js";
import type { AnalysisInputIssue } from "../domain/analysisErrorCore.js";
import type { Result } from "../domain/result.js";
import {
  mcpRegistrationConfigurationError,
  readMcpRegistrationFile,
  type McpRegistrationOwner,
} from "../providers/McpRegistrationFile.js";

/** Omitted registration `timeoutMs` for each upstream CutterMCP+ request. */
export const DEFAULT_CUTTER_REQUEST_TIMEOUT_MS = 300_000;
const MIN_CUTTER_REQUEST_TIMEOUT_MS = 1;
/** Node timer ceiling; larger values would be clamped instead of honored. */
export const MAX_CUTTER_REQUEST_TIMEOUT_MS = 2_147_483_647;

const CUTTER_SETTING = "REA_CUTTER_MCP_CONFIG";

const registrationSchema = z
  .object({
    type: z.literal("stdio").optional(),
    command: z.string().min(1),
    args: z.array(z.string()).default([]),
    env: jsonRecordSchema(z.string()).default({}),
    sensitive: z
      .strictObject({ env: z.array(z.string().min(1)).default([]) })
      .optional(),
    timeoutMs: z
      .int()
      .min(MIN_CUTTER_REQUEST_TIMEOUT_MS)
      .max(MAX_CUTTER_REQUEST_TIMEOUT_MS)
      .default(DEFAULT_CUTTER_REQUEST_TIMEOUT_MS),
  })
  .strict();

/** An upstream stdio MCP registration for the attached CutterMCP+ profile. */
export type CutterConfiguration = z.infer<typeof registrationSchema>;

/** Render only schema-owned constraints, never rejected registration values. */
const registrationConstraint = (
  issue: AnalysisInputIssue,
): string | undefined => {
  const field = issue.path.join(".");
  if (issue.reason === "unknown_argument")
    return issue.path[0] === "url" || issue.path[0] === "headers"
      ? `${field} is not supported: the Cutter profile launches the upstream stdio server (command, args, env), not an HTTP endpoint`
      : `${field} is not a supported registration field; use command, args, env, sensitive.env and timeoutMs`;
  if (issue.path.length === 1 && issue.path[0] === "timeoutMs")
    return `timeoutMs must be an integer from ${String(MIN_CUTTER_REQUEST_TIMEOUT_MS)} to ${String(MAX_CUTTER_REQUEST_TIMEOUT_MS)} milliseconds`;
  return issue.message === undefined
    ? undefined
    : `${field || "registration"}: ${issue.message}`;
};

const cutterRegistrationOwner = {
  setting: CUTTER_SETTING,
  subject: "Cutter MCP registration",
  operation: "cutter:registration",
  guide: "docs/cutter-provider.md",
  acceptedShapes: "a CutterMCP+ stdio command/args registration",
  envelopeKey: "cuttermcp-plus",
  schema: registrationSchema,
  constraint: registrationConstraint,
} satisfies McpRegistrationOwner<CutterConfiguration>;

/** Read one explicit registration without starting or installing a provider. */
export const readCutterConfiguration = (
  path: string,
  options: {
    readonly signal?: AbortSignal;
    readonly resourceScope: RetainedResourceScope;
  },
): Promise<Result<CutterConfiguration, ConfigurationError>> =>
  readMcpRegistrationFile(cutterRegistrationOwner, path, options);

/** A REA_CUTTER_MCP_CONFIG rejection that names the setting it concerns. */
export const cutterConfigurationError = (
  constraint: string,
  cause?: unknown,
): ConfigurationError =>
  mcpRegistrationConfigurationError(CUTTER_SETTING, constraint, cause);

/** Name the registration key that sets a Cutter request deadline. */
export const cutterRegistrationTimeoutGuidance = (
  timeoutMs: number,
  ceilingMs: number = timeoutMs,
): { readonly userMessage: string; readonly remediationAction: string } => ({
  userMessage:
    ceilingMs === timeoutMs
      ? `This Cutter request reached the registration timeoutMs deadline of ${String(timeoutMs)} ms (deadlineExpired).`
      : `This Cutter request reached its ${String(timeoutMs)} ms deadline (deadlineExpired), within the registration timeoutMs ceiling of ${String(ceilingMs)} ms.`,
  remediationAction: `Set timeoutMs in the JSON file named by ${CUTTER_SETTING} to an integer from 1 to ${String(MAX_CUTTER_REQUEST_TIMEOUT_MS)} (omitted means ${String(DEFAULT_CUTTER_REQUEST_TIMEOUT_MS)}). REA applies the edited file on the next Cutter connection after it re-reads the registration; an already open session keeps the timeout it connected with. The upstream wrapper also enforces its own short HTTP deadline to the Cutter plugin. Allow execution, cleanup and delivery headroom in the outer MCP client deadline.`,
});

/** Values explicitly marked sensitive by the registration, never name-pattern guesses. */
export const cutterExplicitSensitiveValues = (
  config: CutterConfiguration | undefined,
): readonly string[] =>
  config === undefined
    ? []
    : Object.entries(config.env)
        .filter(([name]) => config.sensitive?.env.includes(name))
        .map(([, value]) => value);
