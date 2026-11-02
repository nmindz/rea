# Cutter provider

REA adapts an existing [CutterMCP+](https://github.com/restkhz/CutterMCP-plus) server into its native analysis tools, using the open Cutter GUI session as the analysis engine. Install and configure Cutter, its Ghidra decompiler plugin if you want pseudocode, and CutterMCP+ using their instructions. REA does not install, upgrade, or license them, and does not bundle another Cutter server. CutterMCP+ is GPLv3 software separate from REA; REA only starts the stdio server you registered.

This is the `cutter` **provider**. It is distinct from the [Cutter bridge](reverse-engineering-tools.md#cutter-bridge) (`cutter_command`, `list_cutter_sessions`), which sends raw Rizin commands through REA's own Python plugin and does not answer `analyze_function`, `list_procedures`, `procedure_pseudo_code`, xrefs, strings, or segments. The two use different Cutter plugins and different authority:

| Question                                                         | Bridge                       | Provider                       |
| ---------------------------------------------------------------- | ---------------------------- | ------------------------------ |
| Native analysis tools (`analyze_function`, `list_procedures`, …) | Not answered                 | Answered from CutterMCP+       |
| Selected with                                                    | `cutter_command` tool        | `cutter` provider ID           |
| Upstream plugin                                                  | REA's `cutter_bridge` plugin | CutterMCP+ `mcp_plugin.py`     |
| Authority                                                        | Unrestricted Rizin commands  | Fixed read-only tool allowlist |

You can run both against the same Cutter instance. Nothing in the provider calls the bridge, and nothing in the bridge calls CutterMCP+.

Set `REA_CUTTER_MCP_CONFIG` to an upstream MCP JSON registration, then select `cutter` once through `REA_ANALYSIS_PROVIDER`, the CLI's `--provider cutter`, or MCP's `open_binary.provider_id`. No provider startup occurs during discovery or `rea doctor`.

## Supported upstream

The provider supports one profile, `cuttermcp-plus-0.4`: the tool catalog served by CutterMCP+ 0.4.0 (`mcp_server.py` wrapping `mcp_plugin.py`, plugin HTTP API at `127.0.0.1:8000/api/v1`). REA checks the live `tools/list` catalog before any analysis and fails closed, listing the missing tool names in the error diagnostics (`missing_tools`, `expected_profile`, `startup_operation: "initialize"`). A version string is never treated as a compatibility guarantee.

REA calls these upstream tools and no others:

`list_functions`, `function_detail`, `list_globals`, `list_strings`, `list_segments`, `list_entry_points`, `decompile`, `disasm_by_func_json`, `xrefs_to`, `read_bytes`, `current_address`, `current_function`.

The upstream also advertises mutating tools (`rename_function`, `rename_local_variable`, `set_comment`, `set_local_variable_type`). REA never calls them: its connection refuses any tool outside the list above before the request leaves the process. REA never saves or closes the Cutter project, and its close operation releases only its MCP connection.

## Analyze an already-open Cutter target

1. In Cutter, install the CutterMCP+ plugin (`mcp_plugin.py` in Cutter's plugin Python directory), open the **original input binary**, wait for analysis, and start the plugin's server (Cutter MCP Server dock, default `http://127.0.0.1:8000`). Keep the plugin on loopback.
2. Install the wrapper's dependencies with the upstream's own instructions. Use a virtual environment you manage; REA installs nothing.
3. Copy the upstream registration's `command`, `args`, and optional `env` into a JSON file. An existing `mcpServers` object with a `cuttermcp-plus` entry is also accepted:

```json
{
  "command": "/absolute/path/to/CutterMCP-plus/.venv/bin/python",
  "args": ["/absolute/path/to/CutterMCP-plus/mcp_server.py"]
}
```

Only stdio registrations are accepted: the wrapper's `--http` mode and HTTP URLs are refused with the setting named, because REA launches and owns its upstream process. `command` and `args` are used exactly as written; REA does not resolve a Python for you.

```bash
export REA_CUTTER_MCP_CONFIG=/absolute/path/to/cutter-mcp.json
export REA_ANALYSIS_PROVIDER=cutter
rea function /absolute/path/to/program main --json
rea decompile /absolute/path/to/program main --json
```

`REA_CUTTER_MCP_CONFIG` must be an absolute path. If the registration cannot be read or validated, provider diagnostics retain its selected `registration_path` and the configuration owner's setting and constraint facts; the availability `remediation` carries the repair. `configured` means a path was selected, not that it is valid or that a Cutter connection exists. Correct `REA_CUTTER_MCP_CONFIG` in the next CLI invocation's environment or the MCP server's launch environment, and restart that server after changing its environment.

The registration also accepts `timeoutMs` (integer from 1 to 2147483647, default 300000) for each upstream request, and `"sensitive": { "env": ["NAME"] }` to mark environment values REA must redact from diagnostics and keep out of the analysis identity. Unmarked values stay part of that identity; REA does not guess secrecy from names. The wrapper itself enforces a separate 10-second HTTP deadline to the Cutter plugin, so a slow decompile can fail inside the upstream before REA's own deadline.

## Target identity

CutterMCP+ reports neither the input path nor its digest, so REA cannot compare a recorded SHA-256 the way [IDA's attached mode](ida-provider.md#analyze-an-already-open-gui-target) does. It instead:

1. Re-reads the admitted target and computes its SHA-256 while copying file ranges that Cutter maps: the entry points and executable sections reported by `list_entry_points` and `list_segments`.
2. Reads the same virtual addresses back through `read_bytes` and requires an exact match for every probe. A target with no file-backed entry point or executable section cannot be identified and fails with `identity_check: no_probe`.
3. Records the section layout and one probe, and compares both before and after every request. A different layout (`session_layout`) or changed bytes (`session_probe`) fails with recovery guidance. A request that already collected replies when the post-check fails retains them as partial Evidence marked `not_verified`.

This is weaker than a digest. Matching probe bytes show that Cutter mapped the selected file at those addresses, not that every byte is unpatched, that analysis is complete, or which slice of a multi-image file is loaded. Universal Mach-O inputs are therefore refused at admission: open a thin file extracted with `lipo -thin` in both Cutter and REA, or use another provider. The original input must remain readable by REA and must not change after admission (`local_sha256`).

External edits in the GUI remain visible because results are live and never replayed from snapshots. These checks do not lock the GUI.

## Coverage and evidence

REA admits x86, x86_64, arm and arm64 executables through Cutter. Every other CPU family is refused until REA admits it explicitly. Raw-binary, GameCube DOL, and analysis-database inputs are refused; open them with Ghidra. Admission is not verification: nothing here has been run against a real Cutter (see [Verification](#verification)).

| REA operation                                       | Upstream source                                       |
| --------------------------------------------------- | ----------------------------------------------------- |
| `list_documents`                                    | The admitted target (identity verified first)         |
| `list_procedures`, `search_procedures`              | `list_functions`, paged to its reported total         |
| `procedure_address`, `resolve_containing_procedure` | Exact name from the inventory, or `function_detail`   |
| `procedure_pseudo_code`                             | `decompile` (Cutter's `pdg`)                          |
| `procedure_assembly`, `read_function_instructions`  | `disasm_by_func_json`                                 |
| `procedure_callers`, `procedure_callees`            | CALL-type references from `function_detail`           |
| `xrefs`                                             | `xrefs_to` for exactly the requested address          |
| `list_strings`, `search_strings`                    | `list_strings`, paged until an empty page             |
| `list_names`                                        | `list_globals` (Cutter's `isj` symbol table)          |
| `list_segments`                                     | `list_segments` (Cutter's `iSj` sections)             |
| `read_bytes`                                        | `read_bytes`, at most 65536 bytes per request         |
| `current_address`, `current_procedure`              | Cutter's seek position at read time                   |
| `analyze_function`                                  | Assembly, pseudocode, callers, callees, and signature |

Addresses sent upstream are always canonical `0x…` hexadecimal strings validated by REA, because the plugin interpolates them into Rizin commands. A selector that is not an exact function name or a hex address is refused as caller input, never forwarded. A function name that matches no function, matches more than one, or an address inside no function is invalid input, not a producer failure.

**Unknown stays unknown.** Complete function body ranges, typed reference edges, function-referenced strings and names, comments, local variables, basic blocks, and database revision are not reported. A dossier marks those facets unavailable with a reason; empty lists mean _unknown_, not observed absence. Relationship coverage is always `partial`: callers and callees come from CALL references Cutter recorded, calls whose source or target is outside a recognized function are counted in the limitations, and indirect calls are not resolved. Pseudocode that comes back empty (no Ghidra decompiler plugin, or an undecompilable function) is reported as unavailable, not as empty source. Strings carry no encoding or termination facts. `xrefs` reports no truncation marker, so a long result is not proof of completeness.

`provider.version` identifies the REA adapter; the profile records `version_scope: "rea-cutter-adapter"`. The MCP handshake's `serverInfo` is separate and does not establish Cutter, Rizin, or CutterMCP+ versions. Raw observations preserve the upstream tool names, arguments, and results.

## Connect an agent once

Add the registration path to the **REA** MCP entry's environment, keeping the upstream registration in its separate JSON file:

```json
{
  "mcpServers": {
    "rea": {
      "command": "npx",
      "args": ["-y", "rea-agents@<version-with-cutter>", "mcp"],
      "env": {
        "REA_ANALYSIS_PROVIDER": "cutter",
        "REA_CUTTER_MCP_CONFIG": "/absolute/path/to/cutter-mcp.json"
      }
    }
  }
}
```

Use a package version that actually includes this adapter; repository main can be ahead of the npm release. After reconnecting:

```json
{"name":"open_binary","arguments":{"path":"/absolute/path/to/program","provider_id":"cutter"}}
{"name":"analyze_function","arguments":{"procedure":"main","detail":"complete"}}
{"name":"search_strings","arguments":{"pattern":"license"}}
{"name":"close_binary","arguments":{}}
```

Opening an MCP target binds the provider without contacting Cutter; the stdio server starts on the first analysis request. For guided registration, set `REA_CUTTER_MCP_CONFIG` before `rea setup --client <client>`: setup includes the file reference in its reviewed plan and does not copy upstream environment values into the agent configuration. `rea doctor --provider cutter --json` validates the registration without starting Cutter and leaves catalog compatibility and target binding for analysis. For `cutter` or `auto` selection, Codex/Kimi setup and doctor use the registration's parsed `timeoutMs` when recommending the agent's per-tool deadline.

Caller cancellation drains the in-flight MCP request and retains the caller's original reason. A connection whose release cannot be verified is retained and reported as incomplete cleanup, and a later `close_binary` retries it. Closing never saves or closes the Cutter project.

## Verification

The tests in this repository run against a **simulated** CutterMCP+ upstream: a stdio MCP server whose tool names, arguments and result shapes follow the 0.4.0 wrapper, plus an in-process fixture at the connection seam. They cover provider selection, profile mismatch, identity mismatch, the main native workflows over the production CLI and MCP servers, read-only enforcement, cancellation and cleanup. They establish REA's adapter behavior only.

Not yet verified against a real Cutter: the result shapes of Rizin's JSON for real binaries (including how it reports permissions, symbol names, and call references), CutterMCP+ behavior under load or with its decompiler plugin absent, behavior on macOS, Windows or Linux Cutter builds, arm64 targets, and CutterMCP+ releases other than 0.4.0. Run a real workflow with a controlled binary and independently known function, string and reference facts before claiming support for a target.
