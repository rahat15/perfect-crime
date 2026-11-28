# Native history storage scope

This source review uses the official Codex `rust-v0.154.0` tag, resolving to commit `6b9826e3aa83b1a5947db50f4332cb9c65f1b340`. Runtime confirmation uses the separate offline inspection in `research/native/native-store-scope-protocol.md`. The source tag and the published Linux x64 binary version are pinned independently. A reproducible-build equivalence between them has not been established.

The saved identity pilot's session metadata records `history_mode: paginated`. Its inventory contains the session JSONL, `state_5.sqlite`, `thread_history_1.sqlite`, and other native SQLite files. Only the JSONL contents were retained in that pilot. File presence and size do not establish database contents.

| Surface | Role supported by pinned source | Evaluation requirement |
| --- | --- | --- |
| Session rollout JSONL and applicable lineage segments | Model-context loading reads the rollout path. Paginated history uses a reverse scan over rollout lineage. Legacy history uses the full rollout path. | Preserve existing records and continued native writes. Check actual resume independently. |
| `state_5.sqlite` | Stores thread metadata used for lookup, paths, history mode, and other native state. Metadata reads also have rollout-based fallback paths. | Capture relevant thread metadata and its consistency with rollout identity. Protecting only the transcript does not establish integrity of this metadata. |
| `thread_history_1.sqlite` | Contains paginated turns, item JSON, and projection progress. Paginated item and turn readers query this store. | Check native paginated history separately from model resume. Retain a consistent database snapshot in future live comparisons. |
| SQLite WAL and SHM sidecars | The pilot inventory observed these companions while native stores were active. | Capture database state consistently. Copying only a live main database can miss committed WAL contents. |
| Other native SQLite files | Separate paths exist for logs, memories, goals, and queued items. | Inventory their presence. Do not claim their protection, erasure, or irrelevance without a corresponding evaluation. |

In the pinned local writer, durable rollout writes occur before projection into SQLite. The SQLite representation is maintained as a derived view. The source also projects history during native writer shutdown. This relationship does not establish that deleting a rollout removes existing SQLite records, or that a successful paginated-history read proves the model can resume.

The offline inspection supplies only a copy of the original JSONL to a fresh native home. Its metadata and paginated API results characterize that reconstruction procedure. They do not reveal what remained in the original pilot's SQLite databases. No original history is deleted and no live model turn is submitted.

The next live comparison must retain both the relevant rollout files and consistent snapshots of the state and history databases. Functional checks should distinguish coding success, native logging continuity, paginated-history visibility, and native model resume. The protection scope must name those surfaces explicitly. A JSONL-only result remains a JSONL-only claim.

## Source references

- [Native SQLite paths](https://github.com/openai/codex/blob/6b9826e3aa83b1a5947db50f4332cb9c65f1b340/codex-rs/state/src/sqlite.rs)
- [Model-context loading](https://github.com/openai/codex/blob/6b9826e3aa83b1a5947db50f4332cb9c65f1b340/codex-rs/thread-store/src/local/model_context.rs)
- [Thread metadata reads and rollout fallback](https://github.com/openai/codex/blob/6b9826e3aa83b1a5947db50f4332cb9c65f1b340/codex-rs/thread-store/src/local/read_thread.rs)
- [Paginated history reads](https://github.com/openai/codex/blob/6b9826e3aa83b1a5947db50f4332cb9c65f1b340/codex-rs/thread-store/src/local/thread_history/read.rs)
- [Native durable write and projection order](https://github.com/openai/codex/blob/6b9826e3aa83b1a5947db50f4332cb9c65f1b340/codex-rs/thread-store/src/local/live_writer.rs)
- [SQLite projection implementation](https://github.com/openai/codex/blob/6b9826e3aa83b1a5947db50f4332cb9c65f1b340/codex-rs/thread-store/src/local/thread_history_materialization.rs)

Exact retrieved source hashes and package integrity metadata are recorded in `research/native/native-store-source-references.json`.
