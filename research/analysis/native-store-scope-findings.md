# Native store reconstruction observation

The offline inspection at source commit `97c6be81af3ee16c57cf38928760d9220120859e` completed in the pinned baseline image. Its export SHA256 is `5649442bfb5064097f5ba2f8f58fbb49597505a4451d57dd63a5e1bc226754be`. All fourteen manifest-listed files matched their recorded sizes and hashes. The eight frozen source files matched the inspected implementation, and recomputing the assessment reproduced the saved successful result.

The empty-home control could not find the selected session. In a separate fresh home containing only a byte-identical copy of the original after-coding JSONL, the native metadata reader found the correct session and reported paginated history. The turn-list and item-list APIs each returned an empty data list with no continuation cursor. `state_5.sqlite` contained one matching thread metadata row. The paginated-history database contained zero thread items, zero turns, and zero projection-progress rows for the copied session.

Both native reader processes exited normally. The copied JSONL retained its original hash. All inspected databases passed `quick_check` and remained unchanged by the read-only SQLite queries. Container execution exited normally, and the controller recorded successful removal. No model turn or resume request was submitted. A missing-PATH-bubblewrap notice stated that the bundled executable would be used. This read-only inspection did not invoke or validate sandbox startup.

This observation establishes a distinction between metadata discovery and paginated-history recovery for this particular reconstruction procedure. It does not establish that resume would fail, that JSONL cannot be used to reconstruct history by another procedure, or that the original live session lacked SQLite records. The original SQLite contents were not captured in that earlier pilot.

The evaluation implication is to capture rollout files and consistent state/history database snapshots in future live runs, and to measure native paginated-history visibility and actual model resume independently. No original pilot result or source file was replaced.

Initial review method: assistant examination of the supplied complete inspection export, with programmatic archive/source verification and assessment recomputation. Independent human review of this inspection remains pending.
