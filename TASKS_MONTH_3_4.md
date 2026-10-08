# mcp-gate: TASKS_MONTH_3_4.md

> Atomic, test-first task list for Month 3 (Boundary Observation) and Month 4 (Policy Evaluation, Reporting, Reference Suites).
> Source of truth: [SPEC.md](SPEC.md) v0.2.

| Field | Value |
|---|---|
| Covers | Month 3 (Weeks 9 to 13), Month 4 (Weeks 14 to 17) |
| Target milestone | Month 3 Gate, Month 4 Gate |

---

## Tracker

| ID | Title | Test IDs | Done |
|---|---|---|---|
| TASK-3.1 | Observer: openat with dirfd base resolution | P2-OBS-01 | [x] |
| TASK-3.2 | Observer: openat2 observation | P2-OBS-02 | [x] |
| TASK-3.3 | Observer: vfork and exec confirmation | P2-OBS-03 | [x] |
| TASK-3.4 | Observer: clone with CLONE_NEWUSER denial | P2-OBS-04 | [x] |
| TASK-3.5 | Observer: io_uring denial | P2-OBS-05 | [x] |
| TASK-3.6 | Observer: x32 ABI filter kill | P2-OBS-06 | [x] |
| TASK-3.7 | Observer: signal foreign targets denial | P2-OBS-07 | [x] |
| TASK-3.8 | Observer: multithreaded notification concurrency | P2-OBS-08 | [x] |
| TASK-3.9 | Observer: unsupported host exit 69 | P2-OBS-09 | [x] |
| TASK-3.10 | Landlock fallback observation reporting | P2-OBS-10 | [x] |
| TASK-3.11 | Required Landlock missing exit 69 | P2-OBS-11 | [x] |
| TASK-3.12 | Stream leak scanner (JSON, base64, hex/percent, random) | P1-LEAK-01..04 | [x] |
| TASK-4.1 | Domain event and finding models | - | [x] |
| TASK-4.2 | Policy evaluator: decision order and single rule dispatch | P1-EVAL-01 | [x] |
| TASK-4.3 | Policy evaluator: priority order (canary beats out-of-policy) | P1-EVAL-02 | [x] |
| TASK-4.4 | Policy evaluator: canary tiers (tier B warning) | P1-EVAL-03 | [x] |
| TASK-4.5 | Policy evaluator: declared_use global suppression | P1-EVAL-04 | [x] |
| TASK-4.6 | Policy evaluator: scenario allow_access scoping | P1-EVAL-04a, P1-EVAL-04b | [x] |
| TASK-4.7 | Policy evaluator: canary value leak never suppressed | P1-EVAL-04c | [x] |
| TASK-4.8 | Policy evaluator: deduplication and occurrence counting | P1-EVAL-05 | [x] |
| TASK-4.9 | Policy evaluator: stable fingerprints across run dirs | P1-EVAL-06 | [x] |
| TASK-4.10 | Policy evaluator: deterministic sorting and ordering | P1-EVAL-07 | [x] |
| TASK-4.11 | SARIF reporter: stable fingerprints across seeds | P1-SEED-05 | [x] |
| TASK-4.12 | SARIF reporter: schema validation and GitHub compatibility | P4-SARIF-01..09 | [x] |
| TASK-4.13 | JUnit reporter: schema validation, counts, escaping | P4-JUNIT-01..03 | [x] |
| TASK-4.14 | Integration: vulnerable server defect suite | P2-VULN-01..20 | [x] |
| TASK-4.15 | Integration: benign server false-positive suite | P3-BEN-01..12 | [x] |
| TASK-4.16 | Month 3 and 4 Milestone Gate check | All above | [x] |
