# Hosted Runner Compatibility Report

This document records the empirical results of the Week 1 hosted-runner spike (SPEC 4.1.1).
The test suite executed unprivileged kernel compatibility checks on standard GitHub Actions runners.

## Tested Runner Environments

- **ubuntu-latest**: kernel `6.17.0-1022-azure`, arch `x86_64`
- **ubuntu-22.04**: kernel `6.8.0-1064-azure`, arch `x86_64`
- **ubuntu-24.04-arm**: kernel `6.17.0-1022-azure`, arch `aarch64`

## Compatibility Matrix

| Check ID | Description | ubuntu-latest | ubuntu-22.04 | ubuntu-24.04-arm |
|---|--- |--- |--- |--- |
| P0-SPIKE-01 | seccomp listener fd | pass | pass | pass |
| P0-SPIKE-02 | receive notification and continue | pass | pass | pass |
| P0-SPIKE-03 | read path from child memory | pass | pass | pass |
| P0-SPIKE-04 | WAIT_KILLABLE_RECV flag | info | info | info |
| P0-SPIKE-05 | Landlock ABI and restriction | pass | pass | pass |
| P0-SPIKE-06 | Landlock and seccomp combined | pass | pass | pass |
| P0-SPIKE-07 | inotify file read tracking | pass | pass | pass |
| P0-SPIKE-08 | inotify on mmap read | pass | pass | pass |
| P0-SPIKE-09 | PR_SET_DUMPABLE=0 environ protection | pass | pass | pass |
| P0-SPIKE-10 | notification overhead benchmark | info | info | info |

## Gate Evaluation

Decision: GO

- Required gating checks (P0-SPIKE-01, P0-SPIKE-02, P0-SPIKE-03, P0-SPIKE-07): pass on target runners without root.
- Process credential protection (P0-SPIKE-09): unprivileged children cannot read parent environment via procfs.
- File observation (P0-SPIKE-08): confirms inotify tripwire keys on IN_OPEN for memory-mapped reads.
- Notification overhead (P0-SPIKE-10): roundtrip ratio recorded on live hardware.

## Month 1 Milestone Gate Evaluation (TASK-1.23)

Date: 2026-10-04
CI Run: 37212705549
Commit: 8e5f3d1

The complete Month 1 deliverable suite was validated across the CI runner matrix. The verification encompassed environment scrubbing, path resolution, component-wise containment, configuration schema validation with span maps, exit code precedence, and live kernel capability probing via `mcp-gate probe`.

### Probe Matrix Results

| Capability | Property | ubuntu-latest (x86_64) | ubuntu-22.04 (x86_64) | ubuntu-24.04-arm (aarch64) |
|---|---|---|---|---|
| Kernel Version | release | `6.17.0-1022-azure` | `6.8.0-1064-azure` | `6.17.0-1022-azure` |
| Landlock | available | true | true | true |
| Landlock | ABI version | 7 | 4 | 7 |
| Seccomp | filter | true | true | true |
| Seccomp | user_notif | true | true | true |
| Seccomp | notif_continue | true | true | true |
| Seccomp | wait_killable_recv | true | true | true |
| Inotify | available | true | true | true |
| Procfs | mem readable | true | true | true |
| Overall | supported | true | true | true |
| Overall | missing | `[]` | `[]` | `[]` |

### Verification Metrics

- Matrix CI Status: 8 of 8 jobs green across Linux (x86_64, aarch64) and macOS.
- Test Traceability: 48 test IDs verified (`P0-SPIKE-01..10`, `P1-ENV-01..13`, `P1-PATH-01..15`, `P1-CONT-01..05`, `P1-CFG-01..03`, `P1-EXIT-01`).
- Line Coverage: 80.87% across the entire workspace (1089 covered lines of 1349 total lines, exceeding the 80.0% threshold).
- Static Analysis: Zero clippy warnings with cognitive complexity threshold set to 3. Clean cargo formatting.
- Unsafe Isolation: `#![forbid(unsafe_code)]` enforced in all crates except `mcpg-linux`.

### Milestone Verdict

Decision: GO

All Month 1 exit criteria are met without exception. The workspace is ready for Phase 1 Month 2 (capability policy canonicalization and runtime boundary observer).

