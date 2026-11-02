import { digestCanonicalValue } from "../domain/canonicalDigest.js";
import type { CutterConfiguration } from "./CutterConfiguration.js";

/** Marked-sensitive values select a live connection but do not identify analysis semantics. */
export const cutterRegistrationDigest = (config: CutterConfiguration): string =>
  digestCanonicalValue(
    {
      ...config,
      env: Object.fromEntries(
        Object.entries(config.env).map(([name, value]) => [
          name,
          config.sensitive?.env.includes(name) ? null : value,
        ]),
      ),
    },
    "Cutter registration analysis identity",
  );
