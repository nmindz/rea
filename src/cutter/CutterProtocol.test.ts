import { describe, expect, it } from "vitest";
import { decodeCutterToolResult } from "./CutterMcpConnection.js";
import {
  cutterAddressSchema,
  cutterDisassemblySchema,
  cutterDisassemblyUnavailable,
  cutterFunctionsPageSchema,
  cutterSegmentsPageSchema,
} from "./CutterProtocol.js";
import { cutterPermissionFlags } from "./CutterSections.js";

describe("Cutter protocol values", () => {
  it("normalizes decimal and hexadecimal coordinates without rounding", () => {
    expect(cutterAddressSchema.parse(4198400)).toBe("0x401000");
    expect(cutterAddressSchema.parse("0X401000")).toBe("0x401000");
    // Rizin prints 64-bit coordinates as decimal integers; one JSON.parse
    // cannot represent exactly is refused instead of silently rounded.
    expect(cutterAddressSchema.safeParse(2 ** 53).success).toBe(false);
    expect(cutterAddressSchema.safeParse(-1).success).toBe(false);
    expect(cutterAddressSchema.safeParse("401000").success).toBe(false);
    expect(cutterAddressSchema.safeParse("0x401000; wx").success).toBe(false);
  });

  it("requires the function page envelope the plugin reports", () => {
    expect(
      cutterFunctionsPageSchema.safeParse({
        items: [{ addr: "0x1", name: "f" }],
        total: 1,
        offset: 0,
        limit: 50,
      }).success,
    ).toBe(true);
    expect(cutterFunctionsPageSchema.safeParse([{ addr: "0x1" }]).success).toBe(
      false,
    );
  });

  it("keeps an unnamed section as an empty name rather than inventing one", () => {
    expect(
      cutterSegmentsPageSchema.parse([
        { name: null, vaddr: "0x1000", paddr: "0x0", size: 16, perm: null },
      ]),
    ).toMatchObject([{ name: "", perm: null }]);
  });

  it("recognizes the wrapper's empty and null-json disassembly answers as unavailable", () => {
    expect(cutterDisassemblyUnavailable({})).toBe(true);
    expect(cutterDisassemblyUnavailable({ addr: "0x1", json: null })).toBe(
      true,
    );
    expect(cutterDisassemblyUnavailable({ name: "f", addr: 1, ops: [] })).toBe(
      false,
    );
    expect(
      cutterDisassemblySchema.safeParse({
        name: "f",
        addr: 1,
        ops: [{ offset: 1 }],
      }).success,
    ).toBe(false);
  });

  it("decodes permissions without turning absence into no access", () => {
    expect(cutterPermissionFlags("-r-x")).toEqual({
      readable: true,
      writable: false,
      executable: true,
    });
    expect(cutterPermissionFlags(6)).toEqual({
      readable: true,
      writable: true,
      executable: false,
    });
    expect(cutterPermissionFlags(null)).toBeUndefined();
  });
});

describe("Cutter tool results", () => {
  it("unwraps FastMCP's result key but preserves other dictionaries", () => {
    const block = { type: "text", text: "ignored" };
    expect(
      decodeCutterToolResult({
        content: [block],
        structuredContent: { result: ["a"] },
      }),
    ).toEqual(["a"]);
    expect(
      decodeCutterToolResult({
        content: [block],
        structuredContent: { result: 1, other: 2 },
      }),
    ).toEqual({ result: 1, other: 2 });
  });

  it("refuses split list content that lacks structured data", () => {
    expect(() =>
      decodeCutterToolResult({
        content: [
          { type: "text", text: "{}" },
          { type: "text", text: "{}" },
        ],
      }),
    ).toThrow(/single structured or text result/u);
  });

  it("reports an upstream tool error with its text", () => {
    expect(() =>
      decodeCutterToolResult({
        isError: true,
        content: [{ type: "text", text: "plugin unreachable" }],
      }),
    ).toThrow(/plugin unreachable/u);
  });
});
