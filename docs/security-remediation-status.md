# Security remediation status

This patch is an initial remediation, not a declaration that the review is
resolved. No build, test, kernel integration test, or coverage measurement has
been executed as part of generating this patch.

## Implemented

- The production launch path applies Landlock before seccomp.
- Parent-death protection arms `PR_SET_PDEATHSIG` before checking the expected
  parent PID.
- A concurrent launch supervisor receives the listener and continues the root
  exec while `Command::spawn` waits for exec completion. This removes the
  circular dependency between spawn returning and the observer starting.
- Listener handover and the root-exec wait have a five-second deadline.
  Failures after PID handover kill the child; the spawning path reaps it.
- Launch handover descriptors use owned resources. The child-side SCM_RIGHTS
  sender uses aligned stack storage rather than allocating after fork.
- New Linux tests launch the actual syscall-probe fixture and interpret actual
  kernel notifications. The load test requires 8,000 successful OS opens and
  8,000 corresponding target-path event payloads.
- The leak scanner now supports mixed-case/mixed-literal percent encoding,
  JSON escape normalization, and a bounded, per-stream incremental API with
  absolute wire offsets. Base64 matching covers all three byte alignments
  without depending on the prefix or padding boundary bits.

Run the new tests on a supported, unprivileged Linux host:

```sh
cargo build -p syscall-probe
cargo test -p mcpg-linux --test launch_handshake
cargo test -p mcpg-domain --test leak_scanner --test leak_stream
```

Then run workspace formatting, linting, and the entire test suite.

## Still blocking production readiness

1. **Root-exec evidence:** the launch supervisor currently consumes the root
   exec notification to complete `Command::spawn`. It does not publish that
   event to the application event sink. A future Sandbox session must own the
   launch handshake and observer together and preserve this evidence.

2. **Application wiring:** the CLI still contains orchestration and raw
   resource management. Introduce an application RunPlanner and an opaque
   Sandbox session port. The Linux adapter must own and join observer,
   tripwire, and stream-reader workers through shutdown. Do not introduce
   dependencies from mcpg-app back to Linux or MCP adapters.

3. **Incremental scanner integration:** existing CLI readers still implement
   their own fixed 256-byte overlap. Replace that overlap with the new
   incremental scanner, separately for each ordered stream. The new API does
   not reconstruct secrets split between distinct JSON-RPC string values or
   unrelated sockets, nor does it detect arbitrary encryption or every
   possible nested encoding.

4. **TOCTOU:** `/proc/<pid>/mem`, cwd, descriptor targets, and filesystem
   resolution remain best-effort observations, not authoritative syscall
   arguments. Notification-ID validation establishes notification liveness,
   not memory immutability. The production observer still needs its
   post-inspection ID check and must not treat pointer-derived allowlist
   decisions as a security boundary. Landlock enforces filesystem access
   against the kernel's actual objects.

5. **Canary access:** only inode-backed tripwire evidence should establish
   successful canary access. Pointer-derived events may establish observed
   attempts, not successful reads. Tripwire initialization/watch failures,
   queue overflow, watch removal, and shutdown draining must be surfaced as
   coverage loss rather than silently producing PASS.

6. **Reporting:** retain structured findings and primary evidence instead of
   reducing findings to `(rule, message)` pairs. SARIF findings derived from
   pointer inspection must carry `precision: "medium"`. Preserve severity,
   phase, outcome, occurrence count, fingerprint, config span, and coverage.
   Redact all untrusted report content using the same encoding-aware scanner.

7. **Acceptance coverage:** existing mock tests carrying P2/P3/P4 acceptance
   IDs are not proof of kernel behavior, SARIF schema validity, performance,
   or GitHub ingestion. They must be renamed as unit tests or replaced.
   The new kernel load test supplements, rather than legitimizes, those tests.
   Schema compliance must use the checksum-pinned complete OASIS schema,
   not a locally invented structural subset.

8. **Filter completeness:** audit native-architecture syscall tables, legacy
   open and mutation calls, handover bypass lifetime, tamper reporting, and
   signal/process-group decisions. Notify file opens regardless of ancillary
   flags such as `O_LARGEFILE`; access classification must mask `O_ACCMODE`
   and separately account for creation, truncation, append, and `openat2`'s
   pointed-to `open_how`.

The repository must not claim complete specification coverage or
production-grade isolation until these items have executable acceptance
evidence.