# Validation receipt

5 October 2026, Australia/Sydney. Local fixture evidence only.

- Mandatory Ubuntu/WSL2 isolation was used, with user/mount/network/PID/IPC/UTS
  namespaces, read-only bundle/runtime, private tmpfs, no_new_privs, dropped
  capabilities and kernel seccomp. No weaker execution path is shipped.
- Final protocol/security suite: **52 passed**, 21.73 seconds. The command was
  `PYTHONPATH=<pytest site-packages>:.
  PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -q -p no:cacheprovider`
  from `$REPO`. No dependency was downloaded.
- Python and urllib network attempts become socket_attempt errors. Native libc
  and raw syscall socket attempts return EPERM even outside the Python hook.
  Filesystem, process, mount, timeout/OOM, one-emit, malformed verdict, private
  snapshot, tag suppression and refusal/error/log integrity tests pass.
- A counterexample test proves success/no_emit can carry a secret even with a
  constant v1c verdict. The paper explicitly excludes that outcome channel from
  the verdict-only proof and the noise kernel's likelihood-ratio bound.
- Experiment: 256 binary trials per condition, all 256 byte values per payload
  condition, plus separate release-kernel repeated-noise simulations. Both unsafe
  controls recover all inputs. Unsafe output is never persisted or publicly filed.
- Public records: nine safe condition logs plus stability and completeness logs.
  All hashes/chains/schemas verify, and all entries match the recorded runner
  version. The exact aggregate counts are in results.json and RESULTS.md.
- Honest verdict is stable across two processes and opposite planted phrases.
  Method-card hash matches both public and bundled copies. Twenty submissions
  yield ten accepted and ten refused lines.
- Scientific plot was inspected visually. The seven-page PDF review copy was
  rendered with Poppler and every page inspected; table and plot counts also
  match extracted PDF text. No clipping, overlapping content or missing appendix
  was observed. The PDF was generated from the measured Markdown with ReportLab.
- Standalone draft.tex is preserved and opened in the native editor. Two native
  compilation attempts failed before document diagnostics with
  `Unable to find standard directories for platform`. Compilation is unverified;
  no TeX installation or plugin was added. The PDF review copy is a separate
  typesetting route and does not imply native LaTeX compilation succeeded.

Only fixture behavior and these software controls were measured. No real-model,
learned-judge, hardware-attestation, hostile-root secrecy or global privacy claim
is supported. No paper was submitted or published and no lab was contacted.
