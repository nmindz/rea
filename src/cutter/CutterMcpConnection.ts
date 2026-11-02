import { ChildProcess } from "node:child_process";
import { Socket } from "node:net";
import {
  ProtocolError,
  SdkError,
  SdkErrorCode,
  SdkHttpError,
} from "@modelcontextprotocol/client";
import {
  DEFAULT_INHERITED_ENV_VARS,
  StdioClientTransport,
} from "@modelcontextprotocol/client/stdio";
import {
  AnalysisCancelledError,
  AnalysisProtocolError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import {
  jsonObjectSchema,
  jsonValueSchema,
  type JsonValue,
} from "../domain/jsonValue.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import {
  mcpTextBlocks,
  mcpToolResultSchema,
  parseMcpJsonOrText,
} from "../providers/McpToolResult.js";
import { StructuredContentMcpClient } from "../providers/StructuredContentMcpClient.js";
import {
  cutterExplicitSensitiveValues,
  cutterRegistrationTimeoutGuidance,
  type CutterConfiguration,
} from "./CutterConfiguration.js";
import { CUTTER_READ_TOOLS } from "./CutterProviderMetadata.js";

/** Injectable MCP boundary used by the provider and transport tests. */
export interface CutterMcpConnection {
  connect(): Promise<readonly string[]>;
  call(
    name: string,
    args: Readonly<Record<string, JsonValue>>,
    options?: {
      readonly timeoutMs?: number | undefined;
      readonly signal?: AbortSignal | undefined;
    },
  ): Promise<JsonValue>;
  serverInfo(): JsonValue;
  close(): Promise<void>;
  /**
   * Keep a connection retained after failed cleanup from holding the host
   * process open. A long-lived MCP server can still retry through it; a
   * one-shot CLI exits, and the upstream wrapper observes end of input.
   */
  detach(): void;
}

const CUTTER_STDIO_MAX_MESSAGE_BYTES = 16 * 1024 * 1024;
const DIAGNOSTIC_SOURCE_BYTES = 64 * 1024;
const STDERR_TAIL_BYTES = 16_384;
const REDACTION_MARKER = "[redacted sensitive value]";
const OMITTED_DIAGNOSTIC = "[Cutter diagnostic omitted: exceeds 65536 bytes]";

const readTools: ReadonlySet<string> = new Set(CUTTER_READ_TOOLS);

/** Redact exactly the values the registration marks sensitive, plus their JSON-escaped spelling. */
export const createCutterDiagnosticRedactor = (
  config?: CutterConfiguration,
): ((text: string) => string) => {
  const secrets = [
    ...new Set(
      cutterExplicitSensitiveValues(config).flatMap((value) => [
        value,
        JSON.stringify(value).slice(1, -1),
      ]),
    ),
  ]
    .filter((value) => value.length > 0)
    .sort((left, right) => right.length - left.length);
  return (text) => {
    if (Buffer.byteLength(text, "utf8") > DIAGNOSTIC_SOURCE_BYTES)
      return OMITTED_DIAGNOSTIC;
    return secrets.reduce(
      (redacted, secret) => redacted.split(secret).join(REDACTION_MARKER),
      text,
    );
  };
};

/** Decode FastMCP's `{result: ...}` wrapper without dropping structured dictionaries. */
export const decodeCutterToolResult = (
  input: unknown,
  redact: (text: string) => string = createCutterDiagnosticRedactor(),
): JsonValue => {
  const result = mcpToolResultSchema.parse(input);
  const blocks = mcpTextBlocks(result.content);
  if (result.isError === true) {
    const reason = redact(blocks.join("\n"));
    throw new AnalysisProtocolError(`Cutter MCP tool failed: ${reason}`, {
      diagnostics: { reason },
    });
  }
  if (result.structuredContent !== undefined) {
    const value = jsonObjectSchema.parse(result.structuredContent);
    return Object.keys(value).length === 1 && Object.hasOwn(value, "result")
      ? value.result!
      : value;
  }
  // Without structured content, FastMCP emits one block per list element, so
  // only a single block is a complete observation.
  const text = blocks.length === 1 ? blocks[0] : undefined;
  if (text === undefined)
    throw new AnalysisProtocolError(
      "Cutter MCP omitted a single structured or text result; unsupported content cannot establish an empty observation.",
    );
  return parseMcpJsonOrText(text);
};

const retainedTransportCause = (cause: unknown, message: string): Error => {
  // Do not clone arbitrary upstream fields, stacks, data or nested causes.
  if (cause instanceof SdkHttpError)
    return new SdkHttpError(cause.code, message, {
      status: cause.data.status,
      statusText: "",
    });
  if (cause instanceof ProtocolError)
    return new ProtocolError(cause.code, message);
  return new Error(message);
};

/** Create a standard SDK connection to an existing upstream stdio registration. */
export const createCutterMcpConnection = (
  config: CutterConfiguration,
  environment: Readonly<NodeJS.ProcessEnv>,
): CutterMcpConnection => {
  const client = new StructuredContentMcpClient({
    name: "rea-cutter-provider",
    version: "1",
  });
  const redact = createCutterDiagnosticRedactor(config);
  let stderr = Buffer.alloc(0);
  let stderrBytes = 0;
  const capturedTransportOutput = () => {
    let start = 0;
    if (stderrBytes > stderr.length)
      while (start < stderr.length && (stderr[start]! & 0xc0) === 0x80) start++;
    return {
      stdout: "",
      stderr: redact(stderr.subarray(start).toString("utf8")),
      truncated: stderrBytes > stderr.length - start,
      stdout_bytes: 0,
      stderr_bytes: stderrBytes,
    };
  };
  // SDK 2.3.1 returns an SdkError abort reason by identity. A fresh private
  // reason distinguishes this caller abort from an already established failure.
  const requestWithCallerSignal = async <Value>(
    operation: string,
    signal: AbortSignal | undefined,
    request: (requestSignal: AbortSignal | undefined) => Promise<Value>,
  ): Promise<Value> => {
    if (signal === undefined) return request(undefined);
    const controller = new AbortController();
    const cancellation = new SdkError(
      SdkErrorCode.RequestTimeout,
      "REA caller cancelled this Cutter MCP request",
    );
    const abort = () => controller.abort(cancellation);
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
    try {
      return await request(controller.signal);
    } catch (cause: unknown) {
      if (cause === cancellation)
        throw new AnalysisCancelledError(operation, {
          cause: signal.reason,
          capturedOutput: capturedTransportOutput(),
        });
      throw cause;
    } finally {
      signal.removeEventListener("abort", abort);
    }
  };
  const transportFailure = (
    cause: unknown,
    operation = "cutter_mcp_response",
    requestTimeoutMs = config.timeoutMs,
  ): never => {
    const bufferLimit =
      cause instanceof Error
        ? /ReadBuffer exceeded maximum size of (\d+) bytes/u.exec(cause.message)
        : null;
    const message = redact(
      cause instanceof Error
        ? cause.message
        : "Unknown Cutter MCP transport failure",
    );
    const failure = new Error(message, {
      cause: retainedTransportCause(cause, message),
    });
    const capturedOutput = capturedTransportOutput();
    if (cause instanceof SdkError && cause.code === SdkErrorCode.RequestTimeout)
      throw new AnalysisTimeoutError(operation, requestTimeoutMs, {
        cause: failure,
        capturedOutput,
        ...cutterRegistrationTimeoutGuidance(
          requestTimeoutMs,
          config.timeoutMs,
        ),
      });
    if (bufferLimit !== null)
      throw new AnalysisResourceConstraintError(
        operation,
        "transport",
        `Upstream Cutter MCP reply exceeded the ${bufferLimit[1]}-byte transport limit; no partial Evidence was returned.`,
        { max_response_bytes: Number(bufferLimit[1]) },
        { cause, capturedOutput },
      );
    if (stderrBytes === 0) throw failure;
    throw new ProviderAdapterError("cutter", "transport", {
      cause: failure,
      diagnostics: { reason: failure.message },
      capturedOutput,
    });
  };
  const transport = new StdioClientTransport({
    command: config.command,
    args: config.args,
    env: {
      // The SDK always merges ambient defaults. Its string-only environment
      // API requires empty values to suppress omitted caller-selected keys.
      ...Object.fromEntries(DEFAULT_INHERITED_ENV_VARS.map((key) => [key, ""])),
      ...Object.fromEntries(
        Object.entries(snapshotEnvironment(environment)).filter(
          (entry): entry is [string, string] => entry[1] !== undefined,
        ),
      ),
      ...snapshotEnvironment(config.env),
    },
    stderr: "pipe",
    maxBufferSize: CUTTER_STDIO_MAX_MESSAGE_BYTES,
  });
  // Keep a bounded diagnostic tail for genuine failures; never persist ambient variables.
  transport.stderr?.on("data", (chunk: Buffer) => {
    stderrBytes += chunk.length;
    const combined = Buffer.concat([stderr, chunk]);
    stderr = Buffer.from(
      combined.subarray(Math.max(0, combined.length - STDERR_TAIL_BYTES)),
    );
  });
  return {
    async connect() {
      await client
        .connect(transport, { timeout: config.timeoutMs })
        .catch((cause: unknown) =>
          transportFailure(cause, "cutter_mcp_connect"),
        );
      const catalog = await client
        .listTools(undefined, { timeout: config.timeoutMs })
        .catch((cause: unknown) =>
          transportFailure(cause, "cutter_mcp_catalog"),
        );
      return catalog.tools.map(({ name }) => name);
    },
    async call(name, args, options) {
      // Defense in depth: no mutating upstream tool can be reached from REA.
      if (!readTools.has(name))
        throw new AnalysisProtocolError(
          `REA does not call the Cutter MCP tool ${name}; the adapter is read-only.`,
        );
      const requestTimeoutMs = Math.min(
        config.timeoutMs,
        options?.timeoutMs ?? config.timeoutMs,
      );
      return decodeCutterToolResult(
        await requestWithCallerSignal(name, options?.signal, (signal) =>
          client.callTool(
            { name, arguments: args },
            {
              timeout: requestTimeoutMs,
              ...(signal === undefined ? {} : { signal }),
            },
          ),
        ).catch((cause: unknown) => {
          if (cause instanceof AnalysisCancelledError) throw cause;
          return transportFailure(cause, name, requestTimeoutMs);
        }),
        redact,
      );
    },
    serverInfo: () => jsonValueSchema.parse(client.getServerVersion() ?? null),
    close: () => client.close().catch(transportFailure),
    detach() {
      // The SDK exposes only the child's pid, not the handles it holds.
      const child: unknown = Reflect.get(transport, "_process");
      if (!(child instanceof ChildProcess)) return;
      child.unref();
      for (const stream of [child.stdin, child.stdout, child.stderr])
        if (stream instanceof Socket) stream.unref();
    },
  };
};
