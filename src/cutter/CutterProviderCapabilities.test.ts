import { describe, expect, it } from "vitest";
import { cutterCapabilities } from "./CutterProviderCapabilities.js";
import {
  CUTTER_ANALYSIS_OPERATIONS,
  CUTTER_READ_TOOLS,
} from "./CutterProviderMetadata.js";

describe("Cutter capability advertisement", () => {
  it("declares only read-only live operations and attributes limitations to them", () => {
    const capabilities = cutterCapabilities();
    expect(capabilities.map(({ operation }) => operation)).toEqual([
      ...CUTTER_ANALYSIS_OPERATIONS,
    ]);
    for (const capability of capabilities) {
      expect(capability.available).toBe(true);
      expect(capability.cachePolicy).toBe("live");
      expect(capability.effects).toMatchObject({
        mutatesArtifact: false,
        launchesProcess: true,
        mayShowUi: false,
        requiresRoot: false,
      });
    }
    const limitations = (operation: string) =>
      capabilities.find((capability) => capability.operation === operation)
        ?.limitations ?? [];
    expect(limitations("analyze_function").join(" ")).toContain("pdg");
    expect(limitations("list_documents").join(" ")).not.toContain("pdg");
    expect(limitations("search_strings").join(" ")).toContain("matching");
  });

  it("admits no mutating upstream tool in the required profile", () => {
    for (const tool of CUTTER_READ_TOOLS)
      expect(tool).not.toMatch(/^(rename|set)_/u);
  });
});
