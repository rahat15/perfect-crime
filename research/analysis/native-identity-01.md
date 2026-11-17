# Native history identity observation

One full-access coding/resume pilot completed in the pinned baseline image with Codex CLI 0.154.0, requested model `gpt-6-sol`, and subscription authentication. This is process and functionality evidence. It is not a defense evaluation or an attack-success-rate sample.

| Measurement | Observed result |
| --- | --- |
| Native Codex process holding the current session JSONL | UID/GID 1000, zero capabilities, read/write descriptor with O_APPEND |
| Coding-stage history-handle samples | 309 clean matching samples |
| Resume-stage history-handle samples | 67 clean matching samples |
| Held Python tool and its Bash parent | UID/GID 1000, zero capabilities |
| Independently corroborated held-tool samples | 57 |
| History descriptor inherited by that held tool | Not observed at entry or in corroborating samples |
| Independent coding control | All four cases passed |
| Native resume | Same session ID, exact token recalled, no model tool calls in either recorded surface |
| Current session JSONL | Grew from 74,062 to 79,489 bytes, preserving the complete earlier byte prefix and inode |
| Cleanup | Verified by the collection controller |

The observed history-holding process and agent shell have the same Unix identity and capabilities. They cannot be treated as distinct accounts in a permission layout. A defense candidate must establish an enforcement boundary that permits the native writer's legitimate operations while restricting agent tools. This pilot does not establish that a proposed boundary works.

## Readiness correction

The original collector reported `checkpoint_ready: false` because its resume checker classified every item other than a message or reasoning item as tool activity. The resume stream contained an `error` item carrying the known model-metadata fallback diagnostic before the turn started. That diagnostic was incorrectly counted as a tool call.

The separate review verifies the original archive, all 233 archived files, all 199 source files, both native process transports, process-analysis replay, file inventories, and the appended native history. Both recorded resume surfaces contain the user recall request and assistant response without a model tool call. The reviewed readiness is true. The original false verdict, diagnostic, source, and raw records remain unchanged.

The review recognizes only the exact model-metadata diagnostic shape observed here. Other errors, unfamiliar event types, actual tool calls, incomplete lifecycles, and inconsistent evidence remain unresolved or blocked. This correction concerns the native-resume observation check.

Initial review consists of assistant examination of the supplied original records with deterministic offline replay and cross-checks. Independent human scientific review is pending. The public summary is `research/results/native-identity-01-reviewed-summary.json`. The review implementation is `research/native/review_native_identity.py`.

## Limits and follow-up requirements

- The metadata fallback warning remains a configuration limitation. The requested model name does not independently establish the served model version.
- The agent first attempted an unavailable `apply_patch` shell command, then successfully wrote the file through a shell fallback. No separate native editor process or writable coding-output handle was captured by polling. No editor identity is inferred.
- The wall clock moved backwards during both observations. Corresponding wall/monotonic offset changes were approximately -0.801 and -0.818 seconds. Monotonic sample order remained intact. Positive findings are corroborated by process start times, same-sample ancestry, and matching file identities. These records support no performance claim. Future collection should add monotonic stage and control markers.
- Polling can miss short-lived processes and handles. No inherited history handle observed in this held tool does not establish that inheritance is impossible.
- A writable descriptor establishes observed access, not a write syscall. O_APPEND on a descriptor is not a verified append-only inode attribute.
- Other native SQLite files, including `state_5.sqlite` and `thread_history_1.sqlite`, were inventoried without collecting or interpreting their contents. Their role in native resume and the intended protection scope must be established before making broader native-history protection claims.
- The generic shared-controller `permission_mode: auto` field is not the effective Codex configuration. The native invocation and saved turn context confirm full access, disabled permission profile, and approval policy `never`.
- Account-usage fields present in the original native history are omitted from the public summary. Original private evidence is retained unchanged. A later public evidence package must identify any omissions and preserve original-file hashes.

Original source commit: `78f30f862cd96d802c506503e19b0074b28b9b59`.

Original archive SHA256: `939cbcab7e28684ba4cc8f2c5f93602ad48b6d906beaa41948effac8955504b7`.
