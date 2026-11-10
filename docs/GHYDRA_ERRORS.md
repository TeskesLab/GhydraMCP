# Error codes

Every error code the plugin and the clients answer with, where it is raised
and what it means. **Generated** from the source by
`scripts/gen_errors_doc.py`; a test fails when it drifts.

**119 codes** in 18 families. A code is a contract: a
client branches on it, a test asserts it, and
[GHYDRA_TROUBLESHOOTING.md](GHYDRA_TROUBLESHOOTING.md) explains the ones a
user meets.

| Column | Meaning |
| --- | --- |
| Code | the machine-readable value |
| Side | where it is produced (`Java` = the server, `Python` = CLI/bridge) |
| Status | the HTTP status the server answers with, when it sets one |
| Says | the message the server sends with it, when it is a literal |
| Raised at | the file and line that produces it |

## ANALYSIS

`1` code(s): `ANALYSIS_RUNNING`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `ANALYSIS_RUNNING` | Java | 409 | Analysis is already running | `src/main/java/eu/starsong/ghidra/resource/AnalysisResource.java:66` |

## ASSERTION

`3` code(s): `ASSERTION_BAD_FILE`, `ASSERTION_BAD_SPEC`, `ASSERTION_UNKNOWN_KIND`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `ASSERTION_BAD_FILE` | Python | — | — | `ghydra/assertions.py:35` |
| `ASSERTION_BAD_SPEC` | Python | — | — | `ghydra/assertions.py:36` |
| `ASSERTION_UNKNOWN_KIND` | Python | — | — | `ghydra/assertions.py:37` |

## BSIM

`18` code(s): `BSIM_BELOW_THRESHOLD`, `BSIM_CREATE_FAILED`, `BSIM_DISABLED`, `BSIM_INCOMPLETE_INGEST`, `BSIM_INGEST_FAILED`, `BSIM_INIT_FAILED`, `BSIM_INSERT_FAILED`, `BSIM_NO_BODY`, `BSIM_NO_DATABASE`, `BSIM_NO_FUNCTION`, `BSIM_NO_MATCH`, `BSIM_NO_NAME`, `BSIM_NO_PROGRAM`, `BSIM_NO_TARGET`, `BSIM_QUERY_FAILED`, `BSIM_RENAME_FAILED`, `BSIM_RENAME_REFUSED`, `BSIM_SCAN_FAILED`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `BSIM_BELOW_THRESHOLD` | Java | 400 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:213` |
| `BSIM_CREATE_FAILED` | Java | 409 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:225` |
| `BSIM_DISABLED` | Java | 503 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:165` |
| `BSIM_INCOMPLETE_INGEST` | Java | 409 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:272` |
| `BSIM_INGEST_FAILED` | Java | 500 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:261` |
| `BSIM_INIT_FAILED` | Java | 409 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:231` |
| `BSIM_INSERT_FAILED` | Java | 500 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:237` |
| `BSIM_NO_BODY` | Java | 400 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:189` |
| `BSIM_NO_DATABASE` | Java | 400 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:171` |
| `BSIM_NO_FUNCTION` | Java | 400 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:183` |
| `BSIM_NO_MATCH` | Java | 400 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:201` |
| `BSIM_NO_NAME` | Java | 400 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:207` |
| `BSIM_NO_PROGRAM` | Java | 400 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:177` |
| `BSIM_NO_TARGET` | Java | 400 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:195` |
| `BSIM_QUERY_FAILED` | Java | 500 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:249` |
| `BSIM_RENAME_FAILED` | Java | 500 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:255` |
| `BSIM_RENAME_REFUSED` | Java | 400 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:219` |
| `BSIM_SCAN_FAILED` | Java | 500 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:243` |

## DIFF

`1` code(s): `DIFF_READ_FAILED`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `DIFF_READ_FAILED` | Python | — | — | `ghydra/diff.py:38` |

## EVIDENCE

`5` code(s): `EVIDENCE_BAD_ID`, `EVIDENCE_BAD_KIND`, `EVIDENCE_IO`, `EVIDENCE_NO_FILE`, `EVIDENCE_NO_LEDGER`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `EVIDENCE_BAD_ID` | Python | — | — | `ghydra/evidence.py:357` |
| `EVIDENCE_BAD_KIND` | Python | — | — | `bridge_mcp_hydra.py:11487` |
| `EVIDENCE_IO` | Python | — | — | `bridge_mcp_hydra.py:11592` |
| `EVIDENCE_NO_FILE` | Python | — | — | `ghydra/evidence.py:253` |
| `EVIDENCE_NO_LEDGER` | Python | — | — | `ghydra/evidence.py:234` |

## FLEET

`3` code(s): `FLEET_BAD_PORTS`, `FLEET_MISSING_TARGET`, `FLEET_UNKNOWN_KIND`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `FLEET_BAD_PORTS` | Python | — | — | `bridge_mcp_hydra.py:13107` |
| `FLEET_MISSING_TARGET` | Python | — | — | `bridge_mcp_hydra.py:13114` |
| `FLEET_UNKNOWN_KIND` | Python | — | — | `bridge_mcp_hydra.py:13055` |

## FUNCTION

`1` code(s): `FUNCTION_NOT_FOUND`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `FUNCTION_NOT_FOUND` | Python | — | — | `bridge_mcp_hydra.py:5047` |

## HEADLESS

`14` code(s): `HEADLESS_ALREADY_RUNNING`, `HEADLESS_BAD_PORT`, `HEADLESS_BAD_PROJECT_DIR`, `HEADLESS_DIED`, `HEADLESS_LAUNCH`, `HEADLESS_LIMITATION`, `HEADLESS_NO_FILE`, `HEADLESS_NO_GHIDRA`, `HEADLESS_NO_JDK`, `HEADLESS_NO_LAUNCHER`, `HEADLESS_NO_PORT`, `HEADLESS_NO_RUN`, `HEADLESS_PORT_IN_USE`, `HEADLESS_TIMEOUT`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `HEADLESS_ALREADY_RUNNING` | Python | — | — | `ghydra/headless.py:816` |
| `HEADLESS_BAD_PORT` | Python | — | — | `ghydra/headless.py:636` |
| `HEADLESS_BAD_PROJECT_DIR` | Python | — | — | `bridge_mcp_hydra.py:11134` |
| `HEADLESS_DIED` | Python | — | — | `bridge_mcp_hydra.py:11179` |
| `HEADLESS_LAUNCH` | Python | — | — | `bridge_mcp_hydra.py:11142` |
| `HEADLESS_LIMITATION` | Java | — | (computed) | `src/main/java/eu/starsong/ghidra/server/GhydraServer.java:183` |
| `HEADLESS_NO_FILE` | Python | — | — | `bridge_mcp_hydra.py:11107` |
| `HEADLESS_NO_GHIDRA` | Python | — | — | `bridge_mcp_hydra.py:11114` |
| `HEADLESS_NO_JDK` | Python | — | — | `bridge_mcp_hydra.py:11120` |
| `HEADLESS_NO_LAUNCHER` | Python | — | — | `ghydra/headless.py:194` |
| `HEADLESS_NO_PORT` | Python | — | — | `ghydra/headless.py:422` |
| `HEADLESS_NO_RUN` | Python | — | — | `bridge_mcp_hydra.py:11221` |
| `HEADLESS_PORT_IN_USE` | Python | — | — | `bridge_mcp_hydra.py:11124` |
| `HEADLESS_TIMEOUT` | Python | — | — | `bridge_mcp_hydra.py:11192` |

## KUNA

`13` code(s): `KUNA_BAD_ARTIFACT`, `KUNA_DISABLED`, `KUNA_FAILED`, `KUNA_IO`, `KUNA_LAUNCH`, `KUNA_MISSING`, `KUNA_NO_DIR`, `KUNA_NO_FILE`, `KUNA_NO_FUNCTION`, `KUNA_NO_INDEX`, `KUNA_NO_JSON`, `KUNA_TIMEOUT`, `KUNA_TOO_LARGE`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `KUNA_BAD_ARTIFACT` | Python | — | — | `bridge_mcp_hydra.py:8023` |
| `KUNA_DISABLED` | Python | — | — | `bridge_mcp_hydra.py:360` |
| `KUNA_FAILED` | Python | — | — | `bridge_mcp_hydra.py:452` |
| `KUNA_IO` | Python | — | — | `bridge_mcp_hydra.py:7794` |
| `KUNA_LAUNCH` | Python | — | — | `bridge_mcp_hydra.py:7852` |
| `KUNA_MISSING` | Python | — | — | `ghydra/kuna.py:131` |
| `KUNA_NO_DIR` | Python | — | — | `bridge_mcp_hydra.py:7956` |
| `KUNA_NO_FILE` | Python | — | — | `bridge_mcp_hydra.py:371` |
| `KUNA_NO_FUNCTION` | Python | — | — | `bridge_mcp_hydra.py:8048` |
| `KUNA_NO_INDEX` | Python | — | — | `bridge_mcp_hydra.py:7999` |
| `KUNA_NO_JSON` | Python | — | — | `bridge_mcp_hydra.py:442` |
| `KUNA_TIMEOUT` | Python | — | — | `ghydra/kuna.py:166` |
| `KUNA_TOO_LARGE` | Python | — | — | `bridge_mcp_hydra.py:448` |

## MISSION

`1` code(s): `MISSION_IO`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `MISSION_IO` | Python | — | — | `bridge_mcp_hydra.py:12694` |

## REPORT

`3` code(s): `REPORT_NO_FILE`, `REPORT_NO_INSTANCE`, `REPORT_WRONG_BINARY`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `REPORT_NO_FILE` | Python | — | — | `ghydra/report.py:534` |
| `REPORT_NO_INSTANCE` | Python | — | — | `ghydra/report.py:581` |
| `REPORT_WRONG_BINARY` | Python | — | — | `ghydra/report.py:548` |

## RUNBOOK

`4` code(s): `RUNBOOK_BAD_ENTRY`, `RUNBOOK_BAD_FILE`, `RUNBOOK_BAD_STEPS`, `RUNBOOK_IO`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `RUNBOOK_BAD_ENTRY` | Python | — | — | `ghydra/runbook.py:34` |
| `RUNBOOK_BAD_FILE` | Python | — | — | `bridge_mcp_hydra.py:12160` |
| `RUNBOOK_BAD_STEPS` | Python | — | — | `bridge_mcp_hydra.py:12126` |
| `RUNBOOK_IO` | Python | — | — | `bridge_mcp_hydra.py:12133` |

## SCRIPTS

`1` code(s): `SCRIPTS_DISABLED`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `SCRIPTS_DISABLED` | Java | 403 | Script execution is disabled. Start Ghidra with -Dghydra.dev.allowScripts=true | `src/main/java/eu/starsong/ghidra/resource/ScriptResource.java:82` |

## SESSION

`4` code(s): `SESSION_ALREADY`, `SESSION_BAD_NAME`, `SESSION_NOT_RUNNING`, `SESSION_NO_SUCH`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `SESSION_ALREADY` | Python | — | — | `bridge_mcp_hydra.py:11711` |
| `SESSION_BAD_NAME` | Python | — | — | `ghydra/sessions.py:155` |
| `SESSION_NOT_RUNNING` | Python | — | — | `bridge_mcp_hydra.py:11772` |
| `SESSION_NO_SUCH` | Python | — | — | `bridge_mcp_hydra.py:11784` |

## TASK

`1` code(s): `TASK_NOT_FOUND`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `TASK_NOT_FOUND` | Python | — | — | `bridge_mcp_hydra.py:11823` |

## TOOL

`3` code(s): `TOOL_GROUP_CORE`, `TOOL_GROUP_UNAVAILABLE`, `TOOL_GROUP_UNKNOWN`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `TOOL_GROUP_CORE` | Python | — | — | `bridge_mcp_hydra.py:13535` |
| `TOOL_GROUP_UNAVAILABLE` | Python | — | — | `bridge_mcp_hydra.py:13395` |
| `TOOL_GROUP_UNKNOWN` | Python | — | — | `bridge_mcp_hydra.py:13387` |

## X64DBG

`9` code(s): `X64DBG_BAD_ARGS`, `X64DBG_DISABLED`, `X64DBG_ERROR`, `X64DBG_MISSING`, `X64DBG_NO_FILE`, `X64DBG_NO_MATCH`, `X64DBG_TIMEOUT`, `X64DBG_UNAUTHORIZED`, `X64DBG_UNCERTAIN`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `X64DBG_BAD_ARGS` | Python | — | — | `bridge_mcp_hydra.py:9175` |
| `X64DBG_DISABLED` | Python | — | — | `ghydra/gateway.py:98` |
| `X64DBG_ERROR` | Python | — | — | `bridge_mcp_hydra.py:9215` |
| `X64DBG_MISSING` | Python | — | — | `ghydra/x64dbg.py:369` |
| `X64DBG_NO_FILE` | Python | — | — | `ghydra/x64dbg.py:852` |
| `X64DBG_NO_MATCH` | Python | — | — | `ghydra/x64dbg.py:899` |
| `X64DBG_TIMEOUT` | Python | — | — | `ghydra/x64dbg.py:379` |
| `X64DBG_UNAUTHORIZED` | Python | — | — | `ghydra/x64dbg.py:419` |
| `X64DBG_UNCERTAIN` | Python | — | — | `ghydra/x64dbg.py:380` |

## Generic — the shape every client branches on

`34` code(s): `BAD_REQUEST`, `CONNECTION_ERROR`, `INCOMPATIBLE_GHIDRA_BUILD`, `INTERNAL_ERROR`, `INVALID_BASE64`, `INVALID_DIMENSIONS`, `INVALID_HEX`, `INVALID_JSON`, `INVALID_RESPONSE`, `INVALID_TARGETS`, `LAUNCHER_NO_GHIDRA`, `LAUNCHER_NO_JDK`, `LAUNCHER_NO_UTILITY`, `MISSING_PARAMETER`, `NON_JSON_RESPONSE`, `NO_PROGRAM_LOADED`, `NO_PROJECT_OPEN`, `ORIGIN_NOT_ALLOWED`, `READ_ONLY_MODE`, `REQUEST_TIMEOUT`, `SAVE_FAILED`, `SHUTDOWN_DISABLED`, `TAINT_READ_FAILED`, `TARGET_BAD_ADDRESS`, `TARGET_NOT_FOUND`, `TARGET_NOT_LOADED`, `TARGET_NOT_SAME_BINARY`, `TARGET_NO_CODE`, `TARGET_NO_PROGRAM`, `TRANSACTION_FAILED`, `TRIAGE_ERROR`, `TRIAGE_NO_FILE`, `UNEXPECTED_ERROR`, `UNSAVED_CHANGES`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `BAD_REQUEST` | Java | — | (computed) | `src/main/java/eu/starsong/ghidra/server/GhydraServer.java:203` |
| `CONNECTION_ERROR` | Python | — | — | `bridge_mcp_hydra.py:1069` |
| `INCOMPATIBLE_GHIDRA_BUILD` | Java | — | (computed) | `src/main/java/eu/starsong/ghidra/server/GhydraServer.java:220` |
| `INTERNAL_ERROR` | Java | — | Internal server error: | `src/main/java/eu/starsong/ghidra/middleware/ErrorHandler.java:27` |
| `INVALID_BASE64` | Python | — | — | `bridge_mcp_hydra.py:6402` |
| `INVALID_DIMENSIONS` | Python | — | — | `bridge_mcp_hydra.py:10399` |
| `INVALID_HEX` | Python | — | — | `bridge_mcp_hydra.py:6412` |
| `INVALID_JSON` | Java | — | Malformed JSON body: | `src/main/java/eu/starsong/ghidra/server/GhydraServer.java:209` |
| `INVALID_RESPONSE` | Python | — | — | `bridge_mcp_hydra.py:4890` |
| `INVALID_TARGETS` | Python | — | — | `bridge_mcp_hydra.py:5897` |
| `LAUNCHER_NO_GHIDRA` | Python | — | — | `ghydra/launcher.py:125` |
| `LAUNCHER_NO_JDK` | Python | — | — | `ghydra/launcher.py:362` |
| `LAUNCHER_NO_UTILITY` | Python | — | — | `ghydra/launcher.py:448` |
| `MISSING_PARAMETER` | Python | — | — | `bridge_mcp_hydra.py:5028` |
| `NON_JSON_RESPONSE` | Python | — | — | `bridge_mcp_hydra.py:1028` |
| `NO_PROGRAM_LOADED` | Java | — | (computed) | `src/main/java/eu/starsong/ghidra/server/GhydraServer.java:166` |
| `NO_PROJECT_OPEN` | Java | — | (computed) | `src/main/java/eu/starsong/ghidra/server/GhydraServer.java:171` |
| `ORIGIN_NOT_ALLOWED` | Python | — | — | `bridge_mcp_hydra.py:971` |
| `READ_ONLY_MODE` | Java | — | this instance runs in read-only mode, so | `src/main/java/eu/starsong/ghidra/middleware/ReadOnlyGuard.java:83` |
| `REQUEST_TIMEOUT` | Python | — | — | `bridge_mcp_hydra.py:1059` |
| `SAVE_FAILED` | Java | 500 | Save before shutdown failed (not shutting down): | `src/main/java/eu/starsong/ghidra/resource/DevResource.java:78` |
| `SHUTDOWN_DISABLED` | Java | 403 | Dev shutdown is disabled. Start Ghidra with -Dghydra.dev.allowShutdown=true | `src/main/java/eu/starsong/ghidra/resource/DevResource.java:61` |
| `TAINT_READ_FAILED` | Python | — | — | `ghydra/taint.py:46` |
| `TARGET_BAD_ADDRESS` | Python | — | — | `ghydra/target.py:217` |
| `TARGET_NOT_FOUND` | Python | — | — | `ghydra/target.py:215` |
| `TARGET_NOT_LOADED` | Python | — | — | `ghydra/target.py:214` |
| `TARGET_NOT_SAME_BINARY` | Python | — | — | `ghydra/target.py:216` |
| `TARGET_NO_CODE` | Python | — | — | `ghydra/target.py:218` |
| `TARGET_NO_PROGRAM` | Python | — | — | `ghydra/target.py:213` |
| `TRANSACTION_FAILED` | Java | — | (computed) | `src/main/java/eu/starsong/ghidra/server/GhydraServer.java:196` |
| `TRIAGE_ERROR` | Python | — | — | `bridge_mcp_hydra.py:10700` |
| `TRIAGE_NO_FILE` | Python | — | — | `bridge_mcp_hydra.py:10694` |
| `UNEXPECTED_ERROR` | Python | — | — | `bridge_mcp_hydra.py:1079` |
| `UNSAVED_CHANGES` | Java | 409 | Refusing to shut down: | `src/main/java/eu/starsong/ghidra/resource/DevResource.java:86` |

## Regenerating

```bash
python scripts/gen_errors_doc.py           # rewrite this document
python scripts/gen_errors_doc.py --check   # fail when it is stale
```
