# Real-Docker ordinary resume with intact session history

Native Codex 0.154.0 restored the original user phrase on all six ordinary resumes, including both runs with account separation enabled. Fresh threads received the same follow-up prompt and omitted the original phrase in all six trials. Under account separation, the shell logged a permission denial while creating a temporary shell snapshot in each phase. Ordinary text-only resume still completed.

| Condition | Original phrase in resumed request | Original phrase in fresh request | Recorder UID | Separate shell probe UID | Phases logging a shell-snapshot permission denial |
| --- | ---: | ---: | ---: | ---: | ---: |
| Full access | 2/2 | 0/2 | 1000 | 1000 | 0/6 |
| Workspace | 2/2 | 0/2 | 1000 | 1000 | 0/6 |
| Account separation | 2/2 | 0/2 | 1000 | 1002 | 6/6 |

## What was measured

The operator ran six trials on Docker 29.9.3 using the same baseline and derived image IDs as [the successful Step 5 preflight](../account-separation-preflight-hG8xT7/). The code verified the native executable digest in each trial. Each trial used a fresh container, seeded a thread with a unique random phrase, resumed that thread without resupplying the phrase, and then started a fresh thread with the same follow-up prompt. A fixed-text local provider checked whether the exact original user message appeared in each incoming request. The provider issued zero tool calls. Its fixed reply means this measures input restoration by the real client, not a model's ability to recall the phrase. A separate, direct shell probe measured the shell's UID before the text-only exchange.

The six records match the [run plan](plan.json). Each resume kept the original thread ID, each fresh request used a distinct ID, and all 18 CLI phases exited 0. All 18 phases logged the fallback model-metadata notice. The shell-snapshot permission denial appeared only under account separation, in the seed, resume, and fresh phase of each of the two trials. It concerned a temporary shell snapshot. These records do not establish a denial involving the active session record, nor the effect on interactive shell behavior. The unit of replication is a trial. The six account-separation phase observations come from two trials.

## Project status at collection

Step 5 passed on real Docker and is archived in the parent commit. These runs supply the intact-history control for interpreting the Step 6 comparison. The original Step 6 asks whether each condition permits removal of the active session record and what a subsequent resume recovers. This run contributes zero of those six sessions. Account separation preserved ordinary text-only resume in both observed trials; resilience following an attempted removal remains unmeasured here.

## Evidence and method

The [original operator archive](CSE227-normal-resume-ymydyp9n.zip) is preserved byte for byte. Its nine members are available alongside this report, including the [generated summary](summary.md) and the two [first](control-02.json) and [second](control-04.json) account-separation trial records. The [Docker runner](method/wsl_control.py) and [text-only control](method/normal_resume.py) are copied from the operator kit. The inner source hash matches the frozen plan.

Original ZIP SHA-256: `4e92dfe05baa6ae11769e3aa4fbcd04f84097a69bad128645d2da732ed57188f`.
