# Error codes

Every error code the plugin and the clients answer with, where it is raised
and what it means. **Generated** from the source by
`scripts/gen_errors_doc.py`; a test fails when it drifts.

**159 codes** in 20 families. A code is a contract: a
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
| `ANALYSIS_RUNNING` | Java | 409 | Analysis is already running | `src/main/java/eu/starsong/ghidra/resource/AnalysisResource.java:69` |

## ASSERTION

`3` code(s): `ASSERTION_BAD_FILE`, `ASSERTION_BAD_SPEC`, `ASSERTION_UNKNOWN_KIND`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `ASSERTION_BAD_FILE` | Python | — | — | `ghydra/assertions.py:35` |
| `ASSERTION_BAD_SPEC` | Python | — | — | `ghydra/assertions.py:36` |
| `ASSERTION_UNKNOWN_KIND` | Python | — | — | `ghydra/assertions.py:37` |

## BSIM

`37` code(s): `BSIM_APPLY_BUSY`, `BSIM_APPLY_INVALID`, `BSIM_APPLY_TOKEN`, `BSIM_BATCH_INVALID`, `BSIM_BELOW_THRESHOLD`, `BSIM_COMPARISON_INVALID`, `BSIM_CREATE_FAILED`, `BSIM_DISABLED`, `BSIM_FILTER_INVALID`, `BSIM_FILTER_UNSUPPORTED`, `BSIM_INCOMPLETE_INGEST`, `BSIM_INGEST_FAILED`, `BSIM_INIT_FAILED`, `BSIM_INSERT_FAILED`, `BSIM_MATCH_PROFILE`, `BSIM_MATCH_STALE`, `BSIM_MATCH_UNKNOWN`, `BSIM_NO_BODY`, `BSIM_NO_DATABASE`, `BSIM_NO_FUNCTION`, `BSIM_NO_MATCH`, `BSIM_NO_NAME`, `BSIM_NO_PROGRAM`, `BSIM_NO_TARGET`, `BSIM_QUERY_FAILED`, `BSIM_REFERENCE_ADDRESS_AMBIGUOUS`, `BSIM_REFERENCE_FUNCTION_NOT_FOUND`, `BSIM_REFERENCE_IDENTITY_MISMATCH`, `BSIM_REFERENCE_SCOPE_MISMATCH`, `BSIM_REFERENCE_UNAVAILABLE`, `BSIM_RENAME_FAILED`, `BSIM_RENAME_REFUSED`, `BSIM_SCAN_FAILED`, `BSIM_SIGNATURE_ABI`, `BSIM_SIGNATURE_ARCHIVE`, `BSIM_SIGNATURE_TOO_LARGE`, `BSIM_SIGNATURE_TYPE_CONFLICT`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `BSIM_APPLY_BUSY` | Java | 409 | Finish the active native transaction and prepare again | `src/main/java/eu/starsong/ghidra/service/BSimMatchApplyService.java:149` |
| `BSIM_APPLY_INVALID` | Python | — | — | `bridge_mcp_hydra.py:14285` |
| `BSIM_APPLY_TOKEN` | Java | 409 | Unknown, expired, consumed or mismatched apply token; query and prepare a fresh preview | `src/main/java/eu/starsong/ghidra/service/BSimMatchApplyService.java:389` |
| `BSIM_BATCH_INVALID` | Java | 400 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:319` |
| `BSIM_BELOW_THRESHOLD` | Java | 400 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:389` |
| `BSIM_COMPARISON_INVALID` | Python | — | — | `bridge_mcp_hydra.py:14219` |
| `BSIM_CREATE_FAILED` | Java | 409 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:401` |
| `BSIM_DISABLED` | Java | 503 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:341` |
| `BSIM_FILTER_INVALID` | Java | 400 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:329` |
| `BSIM_FILTER_UNSUPPORTED` | Java | 400 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:335` |
| `BSIM_INCOMPLETE_INGEST` | Java | 409 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:448` |
| `BSIM_INGEST_FAILED` | Java | 500 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:437` |
| `BSIM_INIT_FAILED` | Java | 409 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:407` |
| `BSIM_INSERT_FAILED` | Java | 500 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:413` |
| `BSIM_MATCH_PROFILE` | Java | 409 | Use the BSim profile that produced this match. | `src/main/java/eu/starsong/ghidra/service/BSimMatchService.java:133` |
| `BSIM_MATCH_STALE` | Java | 409 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:324` |
| `BSIM_MATCH_UNKNOWN` | Java | 404 | The selected match is unknown or was evicted. Query again and select a returned match ID. | `src/main/java/eu/starsong/ghidra/service/BSimMatchService.java:131` |
| `BSIM_NO_BODY` | Java | 400 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:365` |
| `BSIM_NO_DATABASE` | Java | 400 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:347` |
| `BSIM_NO_FUNCTION` | Java | 400 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:359` |
| `BSIM_NO_MATCH` | Java | 400 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:377` |
| `BSIM_NO_NAME` | Java | 400 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:383` |
| `BSIM_NO_PROGRAM` | Java | 400 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:353` |
| `BSIM_NO_TARGET` | Java | 400 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:371` |
| `BSIM_QUERY_FAILED` | Java | 500 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:425` |
| `BSIM_REFERENCE_ADDRESS_AMBIGUOUS` | Java | 409 | Selected reference function address is ambiguous | `src/main/java/eu/starsong/ghidra/service/RepositoryService.java:389` |
| `BSIM_REFERENCE_FUNCTION_NOT_FOUND` | Java | 404 | Selected reference function was not found at its exact address | `src/main/java/eu/starsong/ghidra/service/RepositoryService.java:367` |
| `BSIM_REFERENCE_IDENTITY_MISMATCH` | Java | 409 | Reference executable MD5 does not match the selected match | `src/main/java/eu/starsong/ghidra/service/RepositoryService.java:270` |
| `BSIM_REFERENCE_SCOPE_MISMATCH` | Java | 403 | Selected repository URL is outside the approved profile | `src/main/java/eu/starsong/ghidra/service/RepositoryService.java:345` |
| `BSIM_REFERENCE_UNAVAILABLE` | Python | — | — | `bridge_mcp_hydra.py:14235` |
| `BSIM_RENAME_FAILED` | Java | 500 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:431` |
| `BSIM_RENAME_REFUSED` | Java | 400 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:395` |
| `BSIM_SCAN_FAILED` | Java | 500 | (computed) | `src/main/java/eu/starsong/ghidra/resource/BSimResource.java:419` |
| `BSIM_SIGNATURE_ABI` | Java | 409 | Source and target language, compiler and pointer size must match exactly | `src/main/java/eu/starsong/ghidra/service/BSimMatchApplyService.java:92` |
| `BSIM_SIGNATURE_ARCHIVE` | Java | 422 | Native signature archive could not be exported: | `src/main/java/eu/starsong/ghidra/service/BSimSignatureTransfer.java:94` |
| `BSIM_SIGNATURE_TOO_LARGE` | Java | 413 | Complete signature transport exceeds its bounds (524288 archive bytes, 900000 JSON bytes or 4096 dependency types); truncation is never accepted | `src/main/java/eu/starsong/ghidra/service/BSimSignatureTransfer.java:171` |
| `BSIM_SIGNATURE_TYPE_CONFLICT` | Java | 409 | Incompatible existing native datatype: | `src/main/java/eu/starsong/ghidra/service/BSimMatchApplyService.java:387` |

## CONNECTION

`11` code(s): `CONNECTION_AUTH_FAILED`, `CONNECTION_AUTH_REQUIRED`, `CONNECTION_ERROR`, `CONNECTION_FAILED`, `CONNECTION_PERMISSION_DENIED`, `CONNECTION_PROFILE_INVALID`, `CONNECTION_PROFILE_NOT_FOUND`, `CONNECTION_PROFILE_REQUIRED`, `CONNECTION_STORE_UNSAFE`, `CONNECTION_TLS_FAILED`, `CONNECTION_WORKER_RESTRICTED`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `CONNECTION_AUTH_FAILED` | Java | 401 | The native authenticated identity does not match the selected profile. | `src/main/java/eu/starsong/ghidra/connection/WorkerAuthentication.java:95` |
| `CONNECTION_AUTH_REQUIRED` | Java | 409 | The connection profile changed; start the operation again. | `src/main/java/eu/starsong/ghidra/connection/ConnectionProfiles.java:195` |
| `CONNECTION_ERROR` | Python | — | — | `bridge_mcp_hydra.py:1072` |
| `CONNECTION_FAILED` | Java | 503 | This Ghidra installation cannot construct the configured BSim client. | `src/main/java/eu/starsong/ghidra/connection/WorkerAuthentication.java:81` |
| `CONNECTION_PERMISSION_DENIED` | Java | 403 | The selected profile does not permit this operation. | `src/main/java/eu/starsong/ghidra/connection/ConnectionProfiles.java:129` |
| `CONNECTION_PROFILE_INVALID` | Java | 400 | The worker connection configuration is invalid; ask its operator to repair it. | `src/main/java/eu/starsong/ghidra/connection/ConnectionProfiles.java:333` |
| `CONNECTION_PROFILE_NOT_FOUND` | Java | 404 | The selected worker connection profile does not exist. | `src/main/java/eu/starsong/ghidra/connection/ConnectionProfiles.java:119` |
| `CONNECTION_PROFILE_REQUIRED` | Java | 400 | Select a worker connection profile. | `src/main/java/eu/starsong/ghidra/connection/ConnectionProfiles.java:78` |
| `CONNECTION_STORE_UNSAFE` | Java | 503 | Connection storage requires worker-owned private POSIX files without symlinks. | `src/main/java/eu/starsong/ghidra/connection/ConnectionProfiles.java:337` |
| `CONNECTION_TLS_FAILED` | Java | 503 | The worker could not initialize verified TLS. Check its certificate configuration. | `src/main/java/eu/starsong/ghidra/connection/WorkerTLS.java:50` |
| `CONNECTION_WORKER_RESTRICTED` | Java | 403 | Script endpoints are unavailable on credential-owning workers. | `src/main/java/eu/starsong/ghidra/resource/ScriptResource.java:87` |

## DIFF

`1` code(s): `DIFF_READ_FAILED`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `DIFF_READ_FAILED` | Python | — | — | `ghydra/diff.py:38` |

## EVIDENCE

`5` code(s): `EVIDENCE_BAD_ID`, `EVIDENCE_BAD_KIND`, `EVIDENCE_IO`, `EVIDENCE_NO_FILE`, `EVIDENCE_NO_LEDGER`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `EVIDENCE_BAD_ID` | Python | — | — | `ghydra/evidence.py:351` |
| `EVIDENCE_BAD_KIND` | Python | — | — | `bridge_mcp_hydra.py:12243` |
| `EVIDENCE_IO` | Python | — | — | `bridge_mcp_hydra.py:12348` |
| `EVIDENCE_NO_FILE` | Python | — | — | `ghydra/evidence.py:247` |
| `EVIDENCE_NO_LEDGER` | Python | — | — | `ghydra/evidence.py:228` |

## FLEET

`3` code(s): `FLEET_BAD_PORTS`, `FLEET_MISSING_TARGET`, `FLEET_UNKNOWN_KIND`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `FLEET_BAD_PORTS` | Python | — | — | `bridge_mcp_hydra.py:13872` |
| `FLEET_MISSING_TARGET` | Python | — | — | `bridge_mcp_hydra.py:13879` |
| `FLEET_UNKNOWN_KIND` | Python | — | — | `bridge_mcp_hydra.py:13820` |

## FUNCTION

`1` code(s): `FUNCTION_NOT_FOUND`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `FUNCTION_NOT_FOUND` | Python | — | — | `bridge_mcp_hydra.py:5657` |

## HEADLESS

`15` code(s): `HEADLESS_ALREADY_RUNNING`, `HEADLESS_BAD_PORT`, `HEADLESS_BAD_PROJECT_DIR`, `HEADLESS_DIED`, `HEADLESS_LAUNCH`, `HEADLESS_LIMITATION`, `HEADLESS_NO_FILE`, `HEADLESS_NO_GHIDRA`, `HEADLESS_NO_JDK`, `HEADLESS_NO_LAUNCHER`, `HEADLESS_NO_PORT`, `HEADLESS_NO_RUN`, `HEADLESS_PORT_IN_USE`, `HEADLESS_STOP_REFUSED`, `HEADLESS_TIMEOUT`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `HEADLESS_ALREADY_RUNNING` | Python | — | — | `ghydra/headless.py:1012` |
| `HEADLESS_BAD_PORT` | Python | — | — | `ghydra/headless.py:672` |
| `HEADLESS_BAD_PROJECT_DIR` | Python | — | — | `bridge_mcp_hydra.py:11775` |
| `HEADLESS_DIED` | Python | — | — | `bridge_mcp_hydra.py:11820` |
| `HEADLESS_LAUNCH` | Python | — | — | `bridge_mcp_hydra.py:11783` |
| `HEADLESS_LIMITATION` | Java | — | (computed) | `src/main/java/eu/starsong/ghidra/server/GhydraServer.java:256` |
| `HEADLESS_NO_FILE` | Python | — | — | `bridge_mcp_hydra.py:11748` |
| `HEADLESS_NO_GHIDRA` | Python | — | — | `bridge_mcp_hydra.py:11755` |
| `HEADLESS_NO_JDK` | Python | — | — | `bridge_mcp_hydra.py:11761` |
| `HEADLESS_NO_LAUNCHER` | Python | — | — | `ghydra/headless.py:192` |
| `HEADLESS_NO_PORT` | Python | — | — | `ghydra/headless.py:421` |
| `HEADLESS_NO_RUN` | Python | — | — | `bridge_mcp_hydra.py:11944` |
| `HEADLESS_PORT_IN_USE` | Python | — | — | `bridge_mcp_hydra.py:11765` |
| `HEADLESS_STOP_REFUSED` | Python | — | — | `bridge_mcp_hydra.py:11954` |
| `HEADLESS_TIMEOUT` | Python | — | — | `bridge_mcp_hydra.py:11833` |

## KUNA

`13` code(s): `KUNA_BAD_ARTIFACT`, `KUNA_DISABLED`, `KUNA_FAILED`, `KUNA_IO`, `KUNA_LAUNCH`, `KUNA_MISSING`, `KUNA_NO_DIR`, `KUNA_NO_FILE`, `KUNA_NO_FUNCTION`, `KUNA_NO_INDEX`, `KUNA_NO_JSON`, `KUNA_TIMEOUT`, `KUNA_TOO_LARGE`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `KUNA_BAD_ARTIFACT` | Python | — | — | `bridge_mcp_hydra.py:8662` |
| `KUNA_DISABLED` | Python | — | — | `bridge_mcp_hydra.py:363` |
| `KUNA_FAILED` | Python | — | — | `bridge_mcp_hydra.py:455` |
| `KUNA_IO` | Python | — | — | `bridge_mcp_hydra.py:8433` |
| `KUNA_LAUNCH` | Python | — | — | `bridge_mcp_hydra.py:8491` |
| `KUNA_MISSING` | Python | — | — | `ghydra/kuna.py:131` |
| `KUNA_NO_DIR` | Python | — | — | `bridge_mcp_hydra.py:8595` |
| `KUNA_NO_FILE` | Python | — | — | `bridge_mcp_hydra.py:374` |
| `KUNA_NO_FUNCTION` | Python | — | — | `bridge_mcp_hydra.py:8687` |
| `KUNA_NO_INDEX` | Python | — | — | `bridge_mcp_hydra.py:8638` |
| `KUNA_NO_JSON` | Python | — | — | `bridge_mcp_hydra.py:445` |
| `KUNA_TIMEOUT` | Python | — | — | `ghydra/kuna.py:166` |
| `KUNA_TOO_LARGE` | Python | — | — | `bridge_mcp_hydra.py:451` |

## MISSION

`1` code(s): `MISSION_IO`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `MISSION_IO` | Python | — | — | `bridge_mcp_hydra.py:13459` |

## REPORT

`3` code(s): `REPORT_NO_FILE`, `REPORT_NO_INSTANCE`, `REPORT_WRONG_BINARY`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `REPORT_NO_FILE` | Python | — | — | `ghydra/report.py:536` |
| `REPORT_NO_INSTANCE` | Python | — | — | `ghydra/report.py:583` |
| `REPORT_WRONG_BINARY` | Python | — | — | `ghydra/report.py:550` |

## REPOSITORY

`5` code(s): `REPOSITORY_CLOSED`, `REPOSITORY_CONFLICT`, `REPOSITORY_NOT_FOUND`, `REPOSITORY_READ_ONLY`, `REPOSITORY_UNSUPPORTED`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `REPOSITORY_CLOSED` | Java | 409 | Repository service is closed | `src/main/java/eu/starsong/ghidra/service/RepositoryService.java:532` |
| `REPOSITORY_CONFLICT` | Java | 409 | Save the active program before opening another repository program. | `src/main/java/eu/starsong/ghidra/server/ActiveProgram.java:33` |
| `REPOSITORY_NOT_FOUND` | Java | 404 | Repository file or folder was not found | `src/main/java/eu/starsong/ghidra/service/RepositoryService.java:786` |
| `REPOSITORY_READ_ONLY` | Java | 403 | Repository program is read-only | `src/main/java/eu/starsong/ghidra/server/ManagedProgramGuard.java:78` |
| `REPOSITORY_UNSUPPORTED` | Java | 501 | Required native Ghidra repository APIs are unavailable | `src/main/java/eu/starsong/ghidra/service/RepositoryService.java:539` |

## RUNBOOK

`4` code(s): `RUNBOOK_BAD_ENTRY`, `RUNBOOK_BAD_FILE`, `RUNBOOK_BAD_STEPS`, `RUNBOOK_IO`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `RUNBOOK_BAD_ENTRY` | Python | — | — | `ghydra/runbook.py:34` |
| `RUNBOOK_BAD_FILE` | Python | — | — | `bridge_mcp_hydra.py:12925` |
| `RUNBOOK_BAD_STEPS` | Python | — | — | `bridge_mcp_hydra.py:12891` |
| `RUNBOOK_IO` | Python | — | — | `bridge_mcp_hydra.py:12898` |

## SCRIPTS

`1` code(s): `SCRIPTS_DISABLED`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `SCRIPTS_DISABLED` | Java | 403 | Script execution is disabled. Start Ghidra with -D | `src/main/java/eu/starsong/ghidra/resource/ScriptResource.java:95` |

## SESSION

`4` code(s): `SESSION_ALREADY`, `SESSION_BAD_NAME`, `SESSION_NOT_RUNNING`, `SESSION_NO_SUCH`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `SESSION_ALREADY` | Python | — | — | `bridge_mcp_hydra.py:12467` |
| `SESSION_BAD_NAME` | Python | — | — | `ghydra/sessions.py:153` |
| `SESSION_NOT_RUNNING` | Python | — | — | `bridge_mcp_hydra.py:11940` |
| `SESSION_NO_SUCH` | Python | — | — | `bridge_mcp_hydra.py:12549` |

## TASK

`1` code(s): `TASK_NOT_FOUND`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `TASK_NOT_FOUND` | Python | — | — | `bridge_mcp_hydra.py:12588` |

## TOOL

`3` code(s): `TOOL_GROUP_CORE`, `TOOL_GROUP_UNAVAILABLE`, `TOOL_GROUP_UNKNOWN`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `TOOL_GROUP_CORE` | Python | — | — | `bridge_mcp_hydra.py:14788` |
| `TOOL_GROUP_UNAVAILABLE` | Python | — | — | `bridge_mcp_hydra.py:14648` |
| `TOOL_GROUP_UNKNOWN` | Python | — | — | `bridge_mcp_hydra.py:14640` |

## X64DBG

`9` code(s): `X64DBG_BAD_ARGS`, `X64DBG_DISABLED`, `X64DBG_ERROR`, `X64DBG_MISSING`, `X64DBG_NO_FILE`, `X64DBG_NO_MATCH`, `X64DBG_TIMEOUT`, `X64DBG_UNAUTHORIZED`, `X64DBG_UNCERTAIN`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `X64DBG_BAD_ARGS` | Python | — | — | `bridge_mcp_hydra.py:9814` |
| `X64DBG_DISABLED` | Python | — | — | `ghydra/gateway.py:98` |
| `X64DBG_ERROR` | Python | — | — | `bridge_mcp_hydra.py:9854` |
| `X64DBG_MISSING` | Python | — | — | `ghydra/x64dbg.py:369` |
| `X64DBG_NO_FILE` | Python | — | — | `ghydra/x64dbg.py:852` |
| `X64DBG_NO_MATCH` | Python | — | — | `ghydra/x64dbg.py:899` |
| `X64DBG_TIMEOUT` | Python | — | — | `ghydra/x64dbg.py:379` |
| `X64DBG_UNAUTHORIZED` | Python | — | — | `ghydra/x64dbg.py:419` |
| `X64DBG_UNCERTAIN` | Python | — | — | `ghydra/x64dbg.py:380` |

## Generic — the shape every client branches on

`38` code(s): `BAD_REQUEST`, `CONNECTIONS_DISABLED`, `INCOMPATIBLE_GHIDRA_BUILD`, `INSTANCE_NOT_FOUND`, `INTERNAL_ERROR`, `INVALID_BASE64`, `INVALID_DIMENSIONS`, `INVALID_HEX`, `INVALID_JSON`, `INVALID_RESPONSE`, `INVALID_TARGETS`, `LAUNCHER_INVALID_ARGUMENT`, `LAUNCHER_NO_GHIDRA`, `LAUNCHER_NO_JDK`, `LAUNCHER_NO_UTILITY`, `MISSING_PARAMETER`, `NON_JSON_RESPONSE`, `NO_PROGRAM_LOADED`, `NO_PROJECT_OPEN`, `ORIGIN_NOT_ALLOWED`, `READ_ONLY_MODE`, `REQUEST_TIMEOUT`, `SAVE_FAILED`, `SHUTDOWN_DISABLED`, `TAINT_READ_FAILED`, `TARGET_BAD_ADDRESS`, `TARGET_NOT_FOUND`, `TARGET_NOT_IN_IMAGE`, `TARGET_NOT_LOADED`, `TARGET_NOT_SAME_BINARY`, `TARGET_NO_CODE`, `TARGET_NO_PROGRAM`, `TRANSACTION_FAILED`, `TRIAGE_ERROR`, `TRIAGE_NO_FILE`, `UNEXPECTED_ERROR`, `UNSAVED_CHANGES`, `WORKER_STOPPING`

| Code | Side | Status | Says | Raised at |
| --- | --- | --- | --- | --- |
| `BAD_REQUEST` | Java | — | (computed) | `src/main/java/eu/starsong/ghidra/server/GhydraServer.java:276` |
| `CONNECTIONS_DISABLED` | Java | 503 | This instance has no worker connection profiles configured. | `src/main/java/eu/starsong/ghidra/connection/ConnectionProfiles.java:76` |
| `INCOMPATIBLE_GHIDRA_BUILD` | Java | — | (computed) | `src/main/java/eu/starsong/ghidra/server/GhydraServer.java:297` |
| `INSTANCE_NOT_FOUND` | Python | — | — | `bridge_mcp_hydra.py:6173` |
| `INTERNAL_ERROR` | Java | — | The credential worker could not complete this request. | `src/main/java/eu/starsong/ghidra/middleware/ErrorHandler.java:27` |
| `INVALID_BASE64` | Python | — | — | `bridge_mcp_hydra.py:7041` |
| `INVALID_DIMENSIONS` | Python | — | — | `bridge_mcp_hydra.py:11038` |
| `INVALID_HEX` | Python | — | — | `bridge_mcp_hydra.py:7051` |
| `INVALID_JSON` | Java | — | (computed) | `src/main/java/eu/starsong/ghidra/server/GhydraServer.java:284` |
| `INVALID_RESPONSE` | Python | — | — | `bridge_mcp_hydra.py:5500` |
| `INVALID_TARGETS` | Python | — | — | `bridge_mcp_hydra.py:6536` |
| `LAUNCHER_INVALID_ARGUMENT` | Python | — | — | `ghydra/launcher.py:462` |
| `LAUNCHER_NO_GHIDRA` | Python | — | — | `ghydra/launcher.py:125` |
| `LAUNCHER_NO_JDK` | Python | — | — | `ghydra/launcher.py:339` |
| `LAUNCHER_NO_UTILITY` | Python | — | — | `ghydra/launcher.py:471` |
| `MISSING_PARAMETER` | Python | — | — | `bridge_mcp_hydra.py:5638` |
| `NON_JSON_RESPONSE` | Python | — | — | `bridge_mcp_hydra.py:1031` |
| `NO_PROGRAM_LOADED` | Java | — | (computed) | `src/main/java/eu/starsong/ghidra/server/GhydraServer.java:239` |
| `NO_PROJECT_OPEN` | Java | — | (computed) | `src/main/java/eu/starsong/ghidra/server/GhydraServer.java:244` |
| `ORIGIN_NOT_ALLOWED` | Python | — | — | `bridge_mcp_hydra.py:974` |
| `READ_ONLY_MODE` | Java | — | this instance runs in read-only mode, so | `src/main/java/eu/starsong/ghidra/middleware/ReadOnlyGuard.java:83` |
| `REQUEST_TIMEOUT` | Python | — | — | `bridge_mcp_hydra.py:1062` |
| `SAVE_FAILED` | Java | 500 | Save before shutdown failed (not shutting down): | `src/main/java/eu/starsong/ghidra/resource/DevResource.java:84` |
| `SHUTDOWN_DISABLED` | Java | 403 | Dev shutdown is disabled. Start Ghidra with -D | `src/main/java/eu/starsong/ghidra/resource/DevResource.java:67` |
| `TAINT_READ_FAILED` | Python | — | — | `ghydra/taint.py:45` |
| `TARGET_BAD_ADDRESS` | Python | — | — | `ghydra/target.py:217` |
| `TARGET_NOT_FOUND` | Python | — | — | `ghydra/target.py:215` |
| `TARGET_NOT_IN_IMAGE` | Python | — | — | `ghydra/target.py:221` |
| `TARGET_NOT_LOADED` | Python | — | — | `ghydra/target.py:214` |
| `TARGET_NOT_SAME_BINARY` | Python | — | — | `ghydra/target.py:216` |
| `TARGET_NO_CODE` | Python | — | — | `ghydra/target.py:222` |
| `TARGET_NO_PROGRAM` | Python | — | — | `ghydra/target.py:213` |
| `TRANSACTION_FAILED` | Java | — | (computed) | `src/main/java/eu/starsong/ghidra/server/GhydraServer.java:269` |
| `TRIAGE_ERROR` | Python | — | — | `bridge_mcp_hydra.py:11339` |
| `TRIAGE_NO_FILE` | Python | — | — | `bridge_mcp_hydra.py:11333` |
| `UNEXPECTED_ERROR` | Python | — | — | `bridge_mcp_hydra.py:1082` |
| `UNSAVED_CHANGES` | Java | 409 | Refusing to shut down: | `src/main/java/eu/starsong/ghidra/resource/DevResource.java:92` |
| `WORKER_STOPPING` | Java | 503 | The worker is checking shutdown safety. | `src/main/java/eu/starsong/ghidra/server/GhydraServer.java:209` |

## Regenerating

```bash
python scripts/gen_errors_doc.py           # rewrite this document
python scripts/gen_errors_doc.py --check   # fail when it is stale
```
