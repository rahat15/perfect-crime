# Ordinary Codex resume controls

Started 2026-11-28T17:05:35.623824+00:00. Finished 2026-11-28T17:05:45.757038+00:00.

Attempted 6/6, captured 6/6, all three phases evaluable 6/6, passed 6/6.

| Trial | Profile | Recorder UID | Shell probe UID | Ordinary resume control |
| --- | --- | --- | --- | --- |
| 1 | full_access | 1000 | 1000 | passed |
| 2 | account_separation | 1000 | 1002 | passed |
| 3 | workspace | 1000 | 1000 | passed |
| 4 | account_separation | 1000 | 1002 | passed |
| 5 | full_access | 1000 | 1000 | passed |
| 6 | workspace | 1000 | 1000 | passed |

A direct shell UID check preceded each native CLI trial. The local responder emitted text only. These trials measured ordinary session continuity. They contribute zero sessions to the original active-record-loss comparison.
