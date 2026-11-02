import { isAbsolute, normalize } from "node:path";
import { z } from "zod";
import type { AppConfig } from "../config/types.js";
import { ABORTED, waitForAbortable } from "../process/AbortablePromise.js";
import {
  createAnalysisExecution,
  type AnalysisClient,
  type AnalysisOperation,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisProtocolError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import type { AnalysisProfileCommitment } from "../domain/analysisProfile.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { createEvidence } from "../domain/evidence.js";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { err, ok, type Result } from "../domain/result.js";
import { analysisClientFailureForOperation } from "../providers/AnalysisClientFailure.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";
import type { CutterConfiguration } from "./CutterConfiguration.js";
import { parseCutterInput } from "./CutterInput.js";
import type { CutterMcpConnection } from "./CutterMcpConnection.js";
import { CutterOperationRunner } from "./CutterOperationRunner.js";
import {
  CUTTER_LIMITATIONS,
  type CutterOperation,
} from "./CutterProviderCapabilities.js";
import {
  CUTTER_ANALYSIS_OPERATIONS,
  CUTTER_ANALYSIS_PROVIDER_IDENTITY,
  CUTTER_READ_TOOLS,
} from "./CutterProviderMetadata.js";
import {
  CutterIdentityRefusal,
  observeCutterTarget,
  type CutterTargetBinding,
} from "./CutterTargetIdentity.js";

const operationSet: ReadonlySet<string> = new Set(CUTTER_ANALYSIS_OPERATIONS);
const isCutterOperation = (operation: string): operation is CutterOperation =>
  operationSet.has(operation);
const wasCancelled = (options: ExecutionOptions | undefined): boolean =>
  options?.signal?.aborted === true;

/** Compare host-local spellings without collapsing POSIX symlink/.. traversal. */
const sameHostPath = (left: string, right: string): boolean =>
  process.platform === "win32"
    ? normalize(left).toLowerCase() === normalize(right).toLowerCase()
    : isAbsolute(left) === isAbsolute(right) &&
      absoluteCallerPath(left) === absoluteCallerPath(right);

const CONNECTION_RESOURCE = "Cutter MCP connection";

/** A failed cleanup retains the upstream connection and reports it for retry. */
class CutterCleanupError extends ProviderAdapterError {
  constructor(cause: unknown) {
    super("cutter", "close", {
      cause,
      cleanup: {
        reason: "Cutter MCP connection cleanup remains unverified.",
        resources: [CONNECTION_RESOURCE],
      },
      capturedOutput:
        cause instanceof AnalysisError ? cause.capturedOutput : undefined,
      diagnostics: {
        ...(cause instanceof AnalysisError ? cause.diagnostics : undefined),
        reason:
          "Cutter cleanup could not be verified; the remaining upstream connection is retained for retry.",
        failure_reason:
          cause instanceof AnalysisError
            ? (cause.diagnostics?.reason ?? cause.message)
            : cause instanceof Error
              ? cause.message
              : String(cause),
      },
    });
  }
}

interface CutterOperationFailureContext {
  runner: CutterOperationRunner | undefined;
  metadataBefore: JsonValue | undefined;
  metadataAfter: JsonValue | undefined;
  postOperationIdentityCheck: "not_attempted" | "started" | "verified";
  parameters: Readonly<Record<string, JsonValue>>;
}

/** Serial read-only session whose lifecycle authority excludes the Cutter GUI. */
export class CutterSessionClient implements AnalysisClient {
  #tail: Promise<void> = Promise.resolve();
  #startup: Promise<void> | undefined;
  #closed = false;
  #closing = false;
  #closePromise: Promise<Result<null, AnalysisError>> | undefined;
  #closeFailures: WeakRef<CutterCleanupError>[] = [];
  #ready = false;
  #binding: CutterTargetBinding | undefined;
  #metadata: JsonValue = null;

  constructor(
    private readonly config: CutterConfiguration,
    private readonly target: BinaryTarget,
    private readonly connection: CutterMcpConnection,
    private readonly profile?: AnalysisProfileCommitment,
    private readonly regexSettings?: Pick<
      AppConfig,
      "regexMatchingDeadline" | "regexWorkerHeapRequest"
    >,
  ) {}

  execute(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    options?: ExecutionOptions,
  ) {
    const call = this.#tail.then(() =>
      this.#execute(operation, parameters, options),
    );
    this.#tail = call.then(
      () => undefined,
      () => undefined,
    );
    return call;
  }

  async executeIfReady(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    options?: ExecutionOptions,
  ) {
    if (!this.#ready || this.#closed || this.#closing)
      return Promise.resolve(undefined);
    const call = this.#tail.then(() => {
      if (!this.#ready || this.#closed || this.#closing) return undefined;
      if (wasCancelled(options))
        return err(
          new AnalysisCancelledError(operation, {
            cause: options?.signal?.reason,
          }),
        );
      return this.#execute(operation, parameters, options, true);
    });
    this.#tail = call.then(
      () => undefined,
      () => undefined,
    );
    const result = await waitForAbortable(call, options?.signal);
    return result === ABORTED
      ? err(
          new AnalysisCancelledError(operation, {
            cause: options?.signal?.reason,
          }),
        )
      : result;
  }

  async #execute(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    options?: ExecutionOptions,
    readyOnly = false,
  ) {
    if (this.#closed || this.#closing)
      return err(
        new AnalysisProtocolError(
          "Cutter session is closing or closed; reopen the target.",
        ),
      );
    if (wasCancelled(options))
      return err(
        new AnalysisCancelledError(operation, {
          cause: options?.signal?.reason,
        }),
      );
    if (operation !== "health" && !isCutterOperation(operation))
      return err(
        new AnalysisCapabilityUnavailableError(
          "cutter",
          operation,
          "This integration admits read-only analysis operations only.",
        ),
      );
    if (operation !== "health") {
      const parsed = parseCutterInput(operation, parameters);
      if (!parsed.ok) return parsed;
      parameters = parsed.value;
    }
    const document = parameters.document;
    if (
      document !== undefined &&
      (typeof document !== "string" ||
        (!sameHostPath(document, this.target.path) &&
          (this.target.sourcePath === undefined ||
            !sameHostPath(document, this.target.sourcePath))))
    )
      return err(
        new AnalysisInputError(operation, undefined, [
          {
            path: ["document"],
            reason: "invalid_value",
            expected: this.target.path,
            message:
              "Cutter document must be the REA-bound target; omit document or use its admitted path.",
          },
        ]),
      );
    const failureContext: CutterOperationFailureContext = {
      runner: undefined,
      metadataBefore: undefined,
      metadataAfter: undefined,
      postOperationIdentityCheck: "not_attempted",
      parameters,
    };
    try {
      if (!readyOnly) await this.#start(operation);
      const before = await this.#observe(options);
      failureContext.metadataBefore = before;
      if (wasCancelled(options))
        throw new AnalysisCancelledError(operation, {
          cause: options?.signal?.reason,
        });
      if (operation === "health") return this.#health(before);
      if (!isCutterOperation(operation))
        throw new AnalysisProtocolError(
          "Cutter operation changed after validation.",
        );
      const runner = this.#runner(options);
      failureContext.runner = runner;
      const result = await runner.run(operation, parameters);
      if (wasCancelled(options))
        throw new AnalysisCancelledError(operation, {
          cause: options?.signal?.reason,
        });
      failureContext.postOperationIdentityCheck = "started";
      const after = await this.#observe(
        options,
        (observed) => (failureContext.metadataAfter = observed),
      );
      failureContext.postOperationIdentityCheck = "verified";
      if (wasCancelled(options))
        throw new AnalysisCancelledError(operation, {
          cause: options?.signal?.reason,
        });
      return ok(
        createAnalysisExecution(result, CUTTER_ANALYSIS_PROVIDER_IDENTITY, {
          rawResult: {
            upstream: this.connection.serverInfo(),
            metadata_before: before,
            metadata_after: after,
            observations: jsonValueSchema.parse(runner.raw),
          },
          limitations: [...CUTTER_LIMITATIONS, ...runner.limitations],
          ...(runner.relationshipCoverage === undefined
            ? {}
            : { relationshipCoverage: runner.relationshipCoverage }),
          locations: [
            { kind: "artifact-path", path: this.target.path },
            ...runner.locations,
          ],
          ...(this.profile === undefined
            ? {}
            : { analysisProfile: this.profile }),
        }),
      );
    } catch (cause: unknown) {
      return this.#failure(operation, cause, options, failureContext);
    }
  }

  #runner(options: ExecutionOptions | undefined): CutterOperationRunner {
    return new CutterOperationRunner(this.connection, {
      regexMatchingDeadline: this.regexSettings?.regexMatchingDeadline,
      regexWorkerHeapRequest: this.regexSettings?.regexWorkerHeapRequest,
      signal: options?.signal,
      selectorOrigin: options?.selectorOrigin,
      admittedDocument: this.target.path,
    });
  }

  #health(metadata: JsonValue) {
    return ok(
      createAnalysisExecution(
        {
          ready: true,
          mode: "attached",
          upstream: this.connection.serverInfo(),
          metadata,
        },
        CUTTER_ANALYSIS_PROVIDER_IDENTITY,
        {
          limitations: CUTTER_LIMITATIONS,
          ...(this.profile === undefined
            ? {}
            : { analysisProfile: this.profile }),
        },
      ),
    );
  }

  #failure(
    operation: string,
    cause: unknown,
    options: ExecutionOptions | undefined,
    context: CutterOperationFailureContext,
  ) {
    let failure: AnalysisError;
    if (cause instanceof CutterIdentityRefusal) {
      failure = new AnalysisOutputError(operation, cause.reason, {
        cause,
        userMessage: cause.reason,
        remediationAction: cause.recovery,
        diagnostics: cause.diagnostics,
      });
    } else if (cause instanceof AnalysisCancelledError) {
      failure = new AnalysisCancelledError(operation, {
        cause:
          cause.cause === undefined ? options?.signal?.reason : cause.cause,
        capturedOutput: cause.capturedOutput,
        diagnostics: cause.diagnostics,
        partialObservation: cause.partialObservation,
        cleanup:
          cause.cleanup ??
          (cause.cleanupIncomplete
            ? { reason: cause.message, resources: cause.cleanupResources }
            : undefined),
      })
        .bindCleanupDependencies([cause])
        .bindCleanupResourceOwner(cause);
    } else if (
      (cause instanceof AnalysisTimeoutError ||
        cause instanceof AnalysisResourceConstraintError) &&
      cause.operation === operation &&
      cause.diagnostics?.startup_operation !== undefined
    ) {
      // #start has already attributed this failure; wrapping it again would
      // replace the original producer cause with an intermediate.
      failure = cause;
    } else if (
      cause instanceof AnalysisTimeoutError ||
      cause instanceof AnalysisResourceConstraintError
    ) {
      failure = analysisClientFailureForOperation(
        cause,
        "cutter",
        operation,
      ).bindCleanupResourceOwner(cause);
    } else if (
      cause instanceof ProviderAdapterError &&
      cause.operation === "transport"
    )
      failure = analysisClientFailureForOperation(cause, "cutter", operation, {
        recovery:
          "Check the configured upstream MCP registration and that Cutter's MCP plugin server is running; see docs/cutter-provider.md.",
      }).bindCleanupResourceOwner(cause);
    else if (cause instanceof AnalysisError) failure = cause;
    else if (cause instanceof z.ZodError)
      failure = new AnalysisOutputError(
        operation,
        `Cutter MCP returned malformed or unsupported producer data: ${cause.issues.map((issue) => `${issue.path.join(".") || "$"}: ${issue.message}`).join("; ")}`,
        { cause },
      );
    else if (wasCancelled(options))
      failure = new AnalysisCancelledError(operation, {
        cause: options?.signal?.reason,
      });
    else
      failure = new ProviderAdapterError("cutter", operation, {
        cause,
        diagnostics: {
          reason:
            cause instanceof Error ? cause.message : "Unknown upstream failure",
          recovery:
            "Check the configured upstream MCP registration and selected target; see docs/cutter-provider.md.",
        },
      });
    // Only calls made after target identity validation can become partial Evidence.
    const { runner, metadataBefore, metadataAfter } = context;
    if (
      runner !== undefined &&
      runner.raw.length > 0 &&
      metadataBefore !== undefined
    ) {
      const observations = jsonValueSchema.parse(runner.raw);
      const binding =
        context.postOperationIdentityCheck !== "verified"
          ? {
              status: "not_verified",
              reason:
                cause instanceof Error
                  ? cause.message
                  : "Post-operation target identity was not observed.",
            }
          : { status: "verified" };
      failure.retainPartialObservation(
        createEvidence(this.target, CUTTER_ANALYSIS_PROVIDER_IDENTITY, {
          predicateType: "analysis-observation",
          operation,
          parameters: context.parameters,
          result: {
            status: "partial",
            failed_operation: operation,
            observations,
            metadata_before: metadataBefore,
            target_binding: binding,
            ...(metadataAfter === undefined
              ? {}
              : { metadata_after: metadataAfter }),
          },
          rawResult: {
            upstream: this.connection.serverInfo(),
            observations,
            metadata_before: metadataBefore,
            ...(metadataAfter === undefined
              ? {}
              : { metadata_after: metadataAfter }),
            post_operation_identity_check: context.postOperationIdentityCheck,
          },
          confidence: "observed",
          authority: "external-service",
          limitations: [
            ...CUTTER_LIMITATIONS,
            ...runner.limitations,
            "The requested Cutter operation failed after these completed upstream replies; the partial Evidence does not establish a complete result.",
            "Replies are bound to the selected target only by the pre-operation identity check unless post_operation_identity_check is verified.",
          ],
          locations: [
            { kind: "artifact-path", path: this.target.path },
            ...runner.locations,
          ],
          ...(this.profile === undefined
            ? {}
            : { analysisProfile: this.profile }),
        }),
      );
    }
    return err(failure);
  }

  async #start(operation: string): Promise<void> {
    this.#startup ??= this.#initialize();
    try {
      await this.#startup;
    } catch (cause: unknown) {
      if (
        !(cause instanceof AnalysisTimeoutError) &&
        !(cause instanceof AnalysisResourceConstraintError) &&
        !(cause instanceof ProviderAdapterError)
      )
        throw cause;
      // Transport adapters already receive caller attribution in #failure.
      if (
        cause instanceof ProviderAdapterError &&
        cause.operation === "transport"
      )
        throw cause;
      // Startup is shared, but each accepted operation owns its attribution.
      throw analysisClientFailureForOperation(cause, "cutter", operation, {
        startup_operation: cause.operation,
      }).bindCleanupResourceOwner(cause);
    }
  }

  async #initialize(): Promise<void> {
    const tools = new Set(await this.connection.connect());
    const missing = CUTTER_READ_TOOLS.filter((name) => !tools.has(name));
    if (missing.length > 0) {
      const summary = `CutterMCP+ compatibility profile is missing tools: ${missing.join(", ")}. The Cutter profile requires the CutterMCP+ 0.4 read tool catalog; see docs/cutter-provider.md.`;
      // The caller cannot act on a profile mismatch it never sees, so the
      // missing names travel as adapter diagnostics rather than a bare message.
      throw new ProviderAdapterError("cutter", "initialize", {
        userMessage: summary,
        diagnostics: {
          reason: summary,
          mode: "attached",
          expected_profile: "cuttermcp-plus-0.4",
          missing_tools: [...missing],
          recovery:
            "Install a CutterMCP+ build that serves the read tool catalog; see docs/cutter-provider.md.",
        },
      });
    }
    this.#ready = true;
  }

  async #observe(
    options?: ExecutionOptions,
    onObserved?: (metadata: JsonValue) => void,
  ): Promise<JsonValue> {
    const observation = await observeCutterTarget({
      call: (tool, args) =>
        this.connection.call(tool, args, { signal: options?.signal }),
      target: this.target,
      previous: this.#binding,
      signal: options?.signal,
    });
    this.#binding = observation.binding;
    this.#metadata = observation.raw;
    onObserved?.(observation.raw);
    return this.#metadata;
  }

  async close(): Promise<Result<null, AnalysisError>> {
    if (this.#closePromise !== undefined) return this.#closePromise;
    const closing = this.#closeOnce();
    const shared = closing.finally(() => {
      if (this.#closePromise === shared) this.#closePromise = undefined;
    });
    this.#closePromise = shared;
    return shared;
  }

  async #closeOnce(): Promise<Result<null, AnalysisError>> {
    this.#closing = true;
    await this.#tail;
    if (this.#closed) return ok(null);
    try {
      await this.connection.close();
      this.#closed = true;
      for (const failure of this.#closeFailures)
        failure.deref()?.resolveCleanup();
      this.#closeFailures = [];
      return ok(null);
    } catch (cause: unknown) {
      this.connection.detach();
      const failure = new CutterCleanupError(cause);
      const client = this;
      failure.bindCleanupResourceOwner({
        get cleanupResources() {
          return client.#closed ? [] : [CONNECTION_RESOURCE];
        },
      });
      this.#closeFailures = [
        ...this.#closeFailures.filter(
          (reference) => reference.deref() !== undefined,
        ),
        new WeakRef(failure),
      ];
      return err(failure);
    }
  }
}
