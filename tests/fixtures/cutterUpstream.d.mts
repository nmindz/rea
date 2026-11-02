/** Size of the simulated original input. */
export const FILE_SIZE: number;
export const CUTTER_READ_TOOL_NAMES: string[];
export const CUTTER_MUTATING_TOOL_NAMES: string[];

/** A minimal x86_64 ELF header followed by deterministic bytes. */
export function cutterFixtureBytes(): Buffer;

/** Mutable simulated CutterMCP+ session; not a real Cutter. */
export class CutterWorld {
  fileBytes: Buffer;
  sections: {
    name: string;
    vaddr: number;
    paddr: number;
    size: number;
    perm: string;
  }[];
  entries: { vaddr: number; paddr: number }[];
  seek: number;
  pageClamp: number;
  decompiler: boolean;
  calls: string[];
  /** Flip every bit of one mapped file byte. */
  corrupt(index: number): void;
  /** Return the value FastMCP would place under `result`. */
  call(tool: string, args?: Record<string, unknown>): unknown;
}
