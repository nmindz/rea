import { z } from "zod";
import { AnalysisCleanupLease } from "../artifacts/AnalysisCleanupLease.js";
import type { RetainedResourceScope } from "../application/AnalysisProvider.js";
import { ConfigurationError } from "../domain/configurationErrors.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import type { AnalysisInputIssue } from "../domain/analysisErrorCore.js";
import { projectInputIssues } from "../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  withOwnedRegularFile,
  regularFileCancellation,
  RegularFileCleanupFailure,
} from "../filesystem/OwnedRegularFile.js";
import {
  RegularFileOperationCancelled,
  NonRegularFileReadError,
} from "../filesystem/RegularFile.js";
import { readBoundedFileBytes } from "../process/BoundedFileBytes.js";

const MAXIMUM_REGISTRATION_BYTES = 65_536;

/** Facts one adapter owns about its upstream registration file. */
export interface McpRegistrationOwner<Registration> {
  /** Environment setting that selects the file, named in every refusal. */
  readonly setting: string;
  /** Human noun for diagnostics, for example `IDA MCP registration`. */
  readonly subject: string;
  /** Cancellation operation name, for example `ida:registration`. */
  readonly operation: string;
  /** Repository path of the adapter guide named in refusals. */
  readonly guide: string;
  /** Sentence naming the accepted registration shapes. */
  readonly acceptedShapes: string;
  /** Key of the optional `mcpServers` envelope entry holding the registration. */
  readonly envelopeKey: string;
  readonly schema: z.ZodType<Registration>;
  /** Schema-authored correction text for one issue; never a rejected value. */
  readonly constraint: (issue: AnalysisInputIssue) => string | undefined;
}

/** A refusal that names the setting it concerns. */
export const mcpRegistrationConfigurationError = (
  setting: string,
  constraint: string,
  cause?: unknown,
): ConfigurationError =>
  new ConfigurationError(constraint, {
    ...(cause === undefined ? {} : { cause }),
    settings: [{ setting, constraint }],
  });

const registrationTooLarge = (setting: string): ConfigurationError =>
  mcpRegistrationConfigurationError(
    setting,
    `${setting} exceeds the 64 KiB registration size.`,
  );

/**
 * Read at most the registration limit from one regular file without starting
 * or installing a provider. A FIFO, socket or device cannot stall the read
 * while it waits for a producer.
 */
export const readMcpRegistrationFile = <Registration>(
  owner: McpRegistrationOwner<Registration>,
  path: string,
  options: {
    readonly signal?: AbortSignal;
    readonly resourceScope: RetainedResourceScope;
  },
): Promise<Result<Registration, ConfigurationError>> =>
  options.resourceScope.run(async () => {
    const { setting, subject, guide } = owner;
    let closeLease: AnalysisCleanupLease | undefined;
    try {
      const text = await withOwnedRegularFile<string>(
        path,
        {
          ...(options.signal === undefined ? {} : { signal: options.signal }),
          retainFailedClose: (closeOwner) => {
            closeLease = AnalysisCleanupLease.forCloseOwner(closeOwner, path);
            options.resourceScope.retain(
              {
                close: () => closeLease!.release(),
                get cleanupResources() {
                  return closeLease!.cleanupResources;
                },
              },
              path,
            );
          },
        },
        async ({ handle, initial: metadata }) => {
          if (metadata.size > MAXIMUM_REGISTRATION_BYTES)
            throw registrationTooLarge(setting);
          const bytes = await readBoundedFileBytes(
            handle,
            MAXIMUM_REGISTRATION_BYTES,
            {
              signal: options.signal,
              cancellationFailure: (reason) =>
                new RegularFileOperationCancelled(reason),
            },
          );
          if (bytes === undefined) throw registrationTooLarge(setting);
          return bytes.toString("utf8");
        },
      );
      const input: unknown = JSON.parse(text);
      const envelope = z
        .object({ mcpServers: z.object({ [owner.envelopeKey]: z.unknown() }) })
        .safeParse(input);
      const registration = envelope.success
        ? envelope.data.mcpServers[owner.envelopeKey]
        : input;
      const parsed = owner.schema.safeParse(registration);
      if (parsed.success) return ok(parsed.data);
      // Only schema-authored correction text is admitted; Zod's aggregate
      // message can contain registration values, including credentials.
      const constraints = projectInputIssues(
        parsed.error.issues,
        registration,
      ).flatMap((issue) => {
        const constraint = owner.constraint(issue);
        return constraint === undefined ? [] : [constraint];
      });
      if (constraints.length === 0)
        return err(
          mcpRegistrationConfigurationError(
            setting,
            `${setting} must contain ${owner.acceptedShapes}; see ${guide}.`,
            parsed.error,
          ),
        );
      return err(
        new ConfigurationError(
          `${setting}: ${constraints.join("; ")}. See ${guide}.`,
          {
            cause: parsed.error,
            settings: constraints.map((constraint) => ({
              setting,
              constraint,
            })),
          },
        ),
      );
    } catch (cause: unknown) {
      if (cause instanceof ConfigurationError) return err(cause);
      if (cause instanceof NonRegularFileReadError)
        return err(
          mcpRegistrationConfigurationError(
            setting,
            `${setting} must select a regular JSON file: ${path}`,
            cause,
          ),
        );
      if (cause instanceof AnalysisCancelledError) throw cause;
      const cancellation = regularFileCancellation(cause);
      if (cancellation !== undefined) {
        if (cause instanceof RegularFileCleanupFailure) {
          const error = new AnalysisCancelledError(owner.operation, {
            cause: cancellation.reason,
            cleanup: {
              reason:
                cause.cleanupCause instanceof Error
                  ? cause.cleanupCause.message
                  : String(cause.cleanupCause),
              resources: [path],
            },
          });
          closeLease?.bindCleanupError(error);
          throw error;
        }
        throw new AnalysisCancelledError(owner.operation, {
          cause: cancellation.reason,
        });
      }
      if (cause instanceof RegularFileCleanupFailure) {
        const primary =
          cause.outcome.kind === "failed"
            ? cause.outcome.cause
            : cause.cleanupCause;
        const primaryMessage =
          cause.outcome.kind === "failed"
            ? primary instanceof ConfigurationError
              ? primary.message
              : primary instanceof NonRegularFileReadError
                ? `${setting} must select a regular JSON file: ${path}`
                : `Cannot read ${subject} ${path}: ${primary instanceof Error ? primary.message : String(primary)}`
            : `Cannot close ${subject} ${path}; provide a readable JSON configuration.`;
        const error = new ConfigurationError(primaryMessage, {
          cause,
          cleanup: {
            reason:
              cause.cleanupCause instanceof Error
                ? cause.cleanupCause.message
                : String(cause.cleanupCause),
            resources: [path],
          },
          settings: [
            {
              setting,
              constraint: `Close remains incomplete for ${path}`,
            },
          ],
        });
        closeLease?.bindCleanupError(error);
        return err(error);
      }
      return err(
        mcpRegistrationConfigurationError(
          setting,
          `Cannot read ${subject} ${path}; provide a readable JSON configuration.`,
          cause,
        ),
      );
    }
  });
