/** Read/write/execute facts decoded from an upstream permission value. */
export interface CutterPermissionFlags {
  readonly readable: boolean;
  readonly writable: boolean;
  readonly executable: boolean;
}

const READ = 4;
const WRITE = 2;
const EXECUTE = 1;

/**
 * Decode Rizin's permission string (`-r-x`) or a numeric r=4, w=2, x=1 mask.
 * Absence stays absent: no value is not "no permissions".
 */
export const cutterPermissionFlags = (
  perm: string | number | null,
): CutterPermissionFlags | undefined => {
  if (perm === null) return undefined;
  if (typeof perm === "number")
    return {
      readable: (perm & READ) !== 0,
      writable: (perm & WRITE) !== 0,
      executable: (perm & EXECUTE) !== 0,
    };
  return {
    readable: perm.includes("r"),
    writable: perm.includes("w"),
    executable: perm.includes("x"),
  };
};
