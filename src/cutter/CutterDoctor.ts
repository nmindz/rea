import type { RetainedResourceScope } from "../application/AnalysisProvider.js";
import type { DoctorProviderInspection } from "../application/Doctor.js";
import type { ConfigurationError } from "../domain/configurationErrors.js";
import type { Result } from "../domain/result.js";
import {
  readCutterConfiguration,
  type CutterConfiguration,
} from "./CutterConfiguration.js";

/** Check the registration without launching Cutter, and retain only the configuration file reference. */
export const inspectCutterRegistration = async (
  path: string | undefined,
  resourceScope: RetainedResourceScope,
  signal?: AbortSignal,
  registration?: Promise<Result<CutterConfiguration, ConfigurationError>>,
): Promise<DoctorProviderInspection> => {
  const parsed =
    path === undefined
      ? undefined
      : await (registration ??
          readCutterConfiguration(path, {
            resourceScope,
            ...(signal === undefined ? {} : { signal }),
          }));
  const valid = parsed?.ok === true;
  return {
    id: "cutter",
    configured: path !== undefined,
    available: valid,
    providerVersion: null,
    registrationEnvironment:
      valid && path !== undefined ? { REA_CUTTER_MCP_CONFIG: path } : {},
    checks: [
      {
        name: "registration",
        ok: valid,
        code: valid
          ? null
          : path === undefined
            ? "not_configured"
            : "invalid_configuration",
        detail: valid
          ? "Cutter MCP registration is valid. Upstream availability, tool catalog, and target binding are checked when analysis starts; no Cutter process was launched."
          : parsed !== undefined && !parsed.ok
            ? parsed.error.message
            : "Cutter MCP registration is not configured.",
        remediation: valid
          ? null
          : "Set REA_CUTTER_MCP_CONFIG to your CutterMCP+ stdio registration JSON; see docs/cutter-provider.md.",
        classification:
          path === undefined ? "missing_analysis_engine" : "config_drift",
      },
    ],
  };
};
