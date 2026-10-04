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
