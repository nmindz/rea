import { isDeepStrictEqual } from "node:util";
import type {
  AnalysisClient,
  AnalysisProfileResolutionOptions,
  AnalysisProviderBoundClientFactory,
  AnalysisProviderCandidate,
  AnalysisProviderInspectionOptions,
  AnalysisProviderReadinessSnapshot,
  CapabilityDescriptor,
  ProviderAvailability,
  ProviderTargetSupport,
  RetainedResourceScope,
} from "../application/AnalysisProvider.js";
import type { ProviderInspectionScope } from "../application/ProviderInspectionScope.js";
import { AnalysisCleanupLease } from "../artifacts/AnalysisCleanupLease.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { bindArtifactFileCleanup } from "../artifacts/ArtifactFileOperation.js";
import type { AppConfig } from "../config/types.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import {
  analysisProfilesEqual,
  createAnalysisProfile,
  type AnalysisProfileCommitment,
} from "../domain/analysisProfile.js";
import {
  isElfMetadataArchitecture,
  type BinaryArchitecture,
  type BinaryTarget,
} from "../domain/binaryTargetTypes.js";
import type { ConfigurationError } from "../domain/configurationErrors.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";
import { launchRegexMatchingLimitation } from "../process/RegexMatcher.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import {
  cutterConfigurationError,
  readCutterConfiguration,
  type CutterConfiguration,
} from "./CutterConfiguration.js";
import {
  createCutterMcpConnection,
  type CutterMcpConnection,
} from "./CutterMcpConnection.js";
import { cutterCapabilities } from "./CutterProviderCapabilities.js";
import { CUTTER_ANALYSIS_PROVIDER_IDENTITY } from "./CutterProviderMetadata.js";
import { cutterRegistrationDigest } from "./CutterRegistrationIdentity.js";
import { CutterSessionClient } from "./CutterSessionClient.js";

/** Compatibility profile identity committed to every Cutter observation. */
export const CUTTER_COMPATIBILITY_PROFILE = "cuttermcp-plus-0.4";

/**
 * Families Cutter admits today. Every other family is refused, including
 * families that REA recognizes after this list was written.
 */
const CUTTER_ARCHITECTURES = new Set<BinaryArchitecture>([
  "x86",
  "x86_64",
  "arm",
  "arm64",
]);

const notConfigured = () =>
  err(
    cutterConfigurationError(
      "Set REA_CUTTER_MCP_CONFIG to a CutterMCP+ stdio MCP JSON registration; see docs/cutter-provider.md.",
    ),
  );

/** Bring-your-own CutterMCP+ candidate; discovery performs no provider startup. */
export class CutterProvider implements AnalysisProviderCandidate {
  readonly #ownedResources = new ArtifactResourceScope();
  readonly #inspectionOwner: RetainedResourceScope = {
    retain: (owner, resource) =>
      this.#ownedResources.retain({
        kind: "lease",
        resource,
        lease: AnalysisCleanupLease.forCloseOwner(owner, resource),
      }),
    run: (operation) => this.#ownedResources.run(operation),
  };
  readonly #registrationByScope = new WeakMap<
    ProviderInspectionScope,
    Promise<Result<CutterConfiguration, ConfigurationError>>
  >();
  private readonly environment: NodeJS.ProcessEnv;

  constructor(
    private readonly config: AppConfig,
    environment: Readonly<NodeJS.ProcessEnv>,
    private readonly connectionFactory: (
      config: CutterConfiguration,
      environment: Readonly<NodeJS.ProcessEnv>,
    ) => CutterMcpConnection = createCutterMcpConnection,
  ) {
    this.environment = snapshotEnvironment(environment);
  }

  identity() {
    return CUTTER_ANALYSIS_PROVIDER_IDENTITY;
  }

  capabilities(): readonly CapabilityDescriptor[] {
    return cutterCapabilities(this.#regexLimitation());
  }

  hasPendingOwnedResources() {
    return this.#ownedResources.hasPending;
  }

  async closeOwnedResources() {
    try {
      await this.#ownedResources.close();
      return ok(null);
    } catch (cause: unknown) {
      const failure = new ProviderCleanupError(
        CUTTER_ANALYSIS_PROVIDER_IDENTITY.id,
        this.#ownedResources.cleanupResources,
        { cause: cause instanceof Error ? cause.message : String(cause) },
        { cause, operation: "close_owned_resources" },
      );
      bindArtifactFileCleanup(cause, failure);
      return err(failure);
    }
  }

  async inspectAvailability(
    options?: AnalysisProviderInspectionOptions,
  ): Promise<ProviderAvailability> {
    return (await this.inspectReadinessSnapshot(options)).availability;
  }

  async inspectReadinessSnapshot(
    options?: AnalysisProviderInspectionOptions,
  ): Promise<AnalysisProviderReadinessSnapshot> {
    const config = await this.#configuration(options);
    const capabilities = this.capabilities();
    const registrationDiagnostics = {
      configured: this.config.cutterMcpConfigPath !== undefined,
      registration_path: this.config.cutterMcpConfigPath ?? null,
      live_connection_probed: false,
    };
    if (!config.ok) {
      const failure = projectAnalysisError(config.error);
      const availability: Extract<
        ProviderAvailability,
        { status: "unavailable" }
      > = {
        status: "unavailable",
        code:
          this.config.cutterMcpConfigPath === undefined
            ? "not_configured"
            : "open_options_invalid",
        reason: failure.message,
        remediation: failure.remediation.action,
        diagnostics: {
          ...registrationDiagnostics,
          configuration_details: failure.details ?? null,
        },
      };
      // Readiness-gated operations carry the same owner observation and repair.
      return {
        availability,
        capabilities: capabilities.map((capability) =>
          capability.available
            ? {
                ...capability,
                available: false as const,
                reason: availability.reason,
                availabilityCode: availability.code,
                remediation: availability.remediation,
              }
            : capability,
        ),
      };
    }
    return {
      availability: {
        status: "available",
        code: null,
        reason: null,
        diagnostics: {
          ...registrationDiagnostics,
          mode: "attached",
          transport: "stdio",
        },
      },
      capabilities,
    };
  }

  inspectTargetSupport(target: BinaryTarget): ProviderTargetSupport {
    const diagnostics = {
      target_kind: target.kind,
      target_format: target.format,
    };
    const unsupported = (
      code: Extract<ProviderTargetSupport, { status: "unsupported" }>["code"],
      reason: string,
    ): ProviderTargetSupport => ({
      status: "unsupported",
      code,
      reason,
      diagnostics,
    });
    if (target.format === "gamecube-dol")
      return unsupported(
        "target_format_unsupported",
        "Cutter does not admit caller-selected GameCube DOL images. Open the target with Ghidra and select format gamecube-dol.",
      );
    if (target.kind !== "executable")
      return unsupported(
        "target_kind_unsupported",
        "Cutter MCP integration admits executable inputs, not analysis databases. Select the original input binary.",
      );
    if (target.format === "raw-binary")
      return unsupported(
        "target_format_unsupported",
        "Cutter does not admit headerless raw binaries. Open the target with Ghidra and supply architecture and entry_point.",
      );
    if (target.format === "mach-o-universal")
      return unsupported(
        "target_format_unsupported",
        `CutterMCP+ cannot report which slice of a universal Mach-O is loaded, so REA cannot verify that the open session is its ${target.architecture} slice. Extract that slice with lipo -thin and open the thin file in both Cutter and REA.`,
      );
    if (!CUTTER_ARCHITECTURES.has(target.architecture))
      return unsupported(
        "architecture_unsupported",
        // Header-declared families that Ghidra admits keep the pointer there.
        isElfMetadataArchitecture(target.architecture) ||
          target.architecture === "hexagon"
          ? `REA's Cutter adapter has no verified ${target.architecture} lane. Select a supported Ghidra profile instead.`
          : `REA's Cutter adapter has no verified ${target.architecture} lane.`,
      );
    return { status: "supported", code: null, reason: null, diagnostics };
  }

  async resolveAnalysisProfile(
    target: BinaryTarget,
    options?: AnalysisProfileResolutionOptions,
  ) {
    if (options?.signal?.aborted === true)
      return err(
        new AnalysisCancelledError("cutter:profile", {
          cause: options.signal.reason,
        }),
      );
    const config = await this.#configuration(options);
    if (!config.ok) return config;
    const profile = createAnalysisProfile(CUTTER_ANALYSIS_PROVIDER_IDENTITY, {
      version_scope: "rea-cutter-adapter",
      engine_version: null,
      upstream_distribution_version: null,
      mode: "attached",
      compatibility_profile: CUTTER_COMPATIBILITY_PROFILE,
      database_revision: null,
      cache_policy: "live",
      registration_digest: cutterRegistrationDigest(config.value),
    });
    if (options?.scope !== undefined)
      this.#registrationByScope.delete(options.scope);
    const registration = config.value;
    const createClient: AnalysisProviderBoundClientFactory = (
      requestedTarget,
      requestedProfile,
    ) =>
      isDeepStrictEqual(requestedTarget, target) &&
      analysisProfilesEqual(requestedProfile, profile)
        ? this.#createBoundClient(registration, target, profile)
        : this.#unboundClient(
            "Cutter client factory received a target or profile different from the resolved binding.",
          );
    return ok({ profile, createClient });
  }

  createClient(
    _target: BinaryTarget,
    _profile?: AnalysisProfileCommitment,
  ): AnalysisClient {
    return this.#unboundClient(
      "Cutter client creation requires the provider-owned selected profile binding.",
    );
  }

  async #configuration(options?: AnalysisProviderInspectionOptions) {
    const scope = options?.scope;
    if (scope?.active === true) {
      const existing = this.#registrationByScope.get(scope);
      if (existing !== undefined) return existing;
    }
    const signal = options?.signal;
    const pending =
      this.config.cutterMcpConfigPath === undefined
        ? Promise.resolve(notConfigured())
        : readCutterConfiguration(this.config.cutterMcpConfigPath, {
            ...(signal === undefined ? {} : { signal }),
            resourceScope: options?.resourceScope ?? this.#inspectionOwner,
          });
    if (scope?.active === true) this.#registrationByScope.set(scope, pending);
    return pending;
  }

  #regexLimitation(): string {
    return launchRegexMatchingLimitation(
      this.config.regexMatchingDeadline,
      this.config.regexWorkerHeapRequest,
    );
  }

  #createBoundClient(
    config: CutterConfiguration,
    target: BinaryTarget,
    profile: AnalysisProfileCommitment,
  ): AnalysisClient {
    return new CutterSessionClient(
      config,
      target,
      this.connectionFactory(config, this.environment),
      profile,
      this.config,
    );
  }

  #unboundClient(reason: string): AnalysisClient {
    const error = cutterConfigurationError(reason);
    return {
      execute: async () => err(error),
      close: async () => ok(null),
    };
  }
}
