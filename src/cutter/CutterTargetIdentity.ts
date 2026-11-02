import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { AnalysisProtocolError } from "../domain/analysisErrorCore.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { cutterPermissionFlags } from "./CutterSections.js";
import {
  cutterAddressValue,
  cutterBytesSchema,
  cutterEntryPointsSchema,
  cutterRequestAddress,
  cutterSegmentsPageSchema,
} from "./CutterProtocol.js";

/** Largest probe and the smallest one that still discriminates a target. */
const PROBE_BYTES = 64;
const MIN_PROBE_BYTES = 16;
const MAX_PROBES = 4;
const SECTION_PAGE = 1000;
const FILE_CHUNK_BYTES = 1024 * 1024;

/** Format-owner facts for a refused target binding, before any analysis reply is used. */
export class CutterIdentityRefusal extends AnalysisProtocolError {
  constructor(
    readonly reason: string,
    readonly recovery: string,
    check: string,
  ) {
    super(reason, { diagnostics: { identity_check: check, reason, recovery } });
  }
}

interface Probe {
  readonly vaddr: string;
  readonly expected: Buffer;
}

/** A verified binding between the Cutter session and the REA-admitted file. */
export interface CutterTargetBinding {
  readonly layout: string;
  readonly probes: readonly Probe[];
}

export interface CutterIdentityObservation {
  readonly binding: CutterTargetBinding;
  readonly raw: JsonValue;
}

type Call = (
  tool: string,
  args: Readonly<Record<string, JsonValue>>,
) => Promise<JsonValue>;

const OPEN_AGAIN =
  "Open the selected original input in Cutter, wait for analysis, then reopen it in REA.";

interface CutterProbeRange {
  readonly vaddr: string;
  readonly paddr: bigint;
}

type SectionRows = ReturnType<typeof cutterSegmentsPageSchema.parse>;
type EntryRows = ReturnType<typeof cutterEntryPointsSchema.parse>;

/** First page of sections as the layout fingerprint; completeness is not claimed. */
const readLayout = async (
  call: Call,
): Promise<{ raw: JsonValue; rows: SectionRows; layout: string }> => {
  const raw = await call("list_segments", { offset: 0, limit: SECTION_PAGE });
  const rows = cutterSegmentsPageSchema.parse(raw);
  return {
    raw,
    rows,
    layout: JSON.stringify(
      rows.map(({ name, vaddr, paddr, size, perm }) => [
        name,
        vaddr,
        paddr,
        size,
        perm,
      ]),
    ),
  };
};

/** Entry points first, then executable sections: both are file-backed code. */
const probeCandidates = (
  rows: SectionRows,
  entries: EntryRows,
): CutterProbeRange[] => {
  const seen = new Set<string>();
  const candidates: CutterProbeRange[] = [];
  const add = (vaddr: string, paddr: string) => {
    if (seen.has(vaddr) || candidates.length >= MAX_PROBES) return;
    seen.add(vaddr);
    candidates.push({ vaddr, paddr: cutterAddressValue(paddr) });
  };
  for (const entry of entries) add(entry.vaddr, entry.paddr);
  const executable = rows
    .filter(
      ({ perm, size }) =>
        size > 0 && cutterPermissionFlags(perm)?.executable === true,
    )
    .sort((left, right) =>
      cutterAddressValue(left.vaddr) < cutterAddressValue(right.vaddr) ? -1 : 1,
    );
  for (const section of executable) add(section.vaddr, section.paddr);
  return candidates;
};

/**
 * Hash the whole file and copy each probe range from the same bytes, so the
 * expected probe content is bound to the digest REA admitted.
 */
const readLocalProbes = async (
  path: string,
  ranges: readonly CutterProbeRange[],
  signal: AbortSignal | undefined,
): Promise<{ sha256: string; slices: Buffer[] }> => {
  const hash = createHash("sha256");
  const slices = ranges.map(() => Buffer.alloc(0));
  let position = 0n;
  const stream = createReadStream(path, {
    highWaterMark: FILE_CHUNK_BYTES,
    ...(signal === undefined ? {} : { signal }),
  });
  for await (const chunk of stream as AsyncIterable<Buffer>) {
    hash.update(chunk);
    const chunkEnd = position + BigInt(chunk.length);
    ranges.forEach(({ paddr }, index) => {
      const start = paddr > position ? paddr : position;
      const probeEnd = paddr + BigInt(PROBE_BYTES);
      const end = probeEnd < chunkEnd ? probeEnd : chunkEnd;
      if (start < end)
        slices[index] = Buffer.concat([
          slices[index]!,
          chunk.subarray(Number(start - position), Number(end - position)),
        ]);
    });
    position = chunkEnd;
  }
  return { sha256: hash.digest("hex"), slices };
};

const readUpstream = async (
  call: Call,
  probe: Probe,
): Promise<Buffer | undefined> => {
  const value = cutterBytesSchema.parse(
    await call("read_bytes", {
      addr: cutterRequestAddress(probe.vaddr),
      size: probe.expected.length,
    }),
  );
  return value.bytes.length === probe.expected.length
    ? Buffer.from(value.bytes)
    : undefined;
};

/**
 * Observe the live session. The first observation proves the local file
 * digest, selects the probes and verifies every one against Cutter; later
 * observations compare the section layout and re-read the first probe.
 */
export const observeCutterTarget = async (input: {
  readonly call: Call;
  readonly target: { readonly path: string; readonly sha256: string };
  readonly previous: CutterTargetBinding | undefined;
  readonly signal: AbortSignal | undefined;
}): Promise<CutterIdentityObservation> => {
  const { call, previous, target } = input;
  const layout = await readLayout(call);
  if (previous !== undefined) {
    if (layout.layout !== previous.layout)
      throw new CutterIdentityRefusal(
        "The Cutter section layout changed during the REA session; the open file may have been replaced.",
        "Close the REA analysis session and reopen it after confirming the intended input in Cutter.",
        "session_layout",
      );
    const first = previous.probes[0]!;
    const observed = await readUpstream(call, first);
    if (observed === undefined || !observed.equals(first.expected))
      throw new CutterIdentityRefusal(
        "The bytes Cutter maps at the probed address no longer match the selected target.",
        "Close the REA analysis session and reopen it after confirming the intended input, and that no patch changed its code, in Cutter.",
        "session_probe",
      );
    return { binding: previous, raw: layout.raw };
  }
  const entries = cutterEntryPointsSchema.parse(
    await call("list_entry_points", {}),
  );
  const candidates = probeCandidates(layout.rows, entries);
  const local = await readLocalProbes(target.path, candidates, input.signal);
  if (local.sha256 !== target.sha256.toLowerCase())
    throw new CutterIdentityRefusal(
      `The selected target ${target.path} changed after REA admitted it.`,
      "Reopen the target in REA so it is admitted again, and open the same file in Cutter.",
      "local_sha256",
    );
  const probes: Probe[] = [];
  for (const [index, candidate] of candidates.entries()) {
    const expected = local.slices[index]!;
    if (expected.length < MIN_PROBE_BYTES) continue;
    const probe = { vaddr: candidate.vaddr, expected };
    const observed = await readUpstream(call, probe);
    if (observed === undefined || !observed.equals(expected))
      throw new CutterIdentityRefusal(
        `The bytes Cutter maps at ${candidate.vaddr} do not match the selected target ${target.path}.`,
        OPEN_AGAIN,
        "target_probe",
      );
    probes.push(probe);
  }
  if (probes.length === 0)
    throw new CutterIdentityRefusal(
      "Cutter exposes no file-backed entry point or executable section that REA can compare with the selected target, so the open file cannot be identified. CutterMCP+ reports neither the input path nor its digest.",
      "Open an executable with a recognized entry point or executable section in Cutter, or select a provider that reports the input digest.",
      "no_probe",
    );
  return { binding: { layout: layout.layout, probes }, raw: layout.raw };
};
