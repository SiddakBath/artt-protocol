# A Right to Test: independent scrutiny under confidentiality

**ARTT aims to make independent AI testing a public, accountable process while custodians retain confidential models, responses and test material.** Our research studies the release controls needed when the submitted evaluator itself may be hostile.

That is the proposed change: an outsider could file an inspectable test, a custodian could execute it against a committed model configuration under declared limits, and the public could receive a bounded result and a record of the outcome. A legal right to access, institutional adoption and deployment on frontier models remain future work.

## Why this could matter

A researcher may want to investigate a failure that a standard benchmark misses. A regulator may need to examine a confidential system. An independent evaluator may need to protect an unreleased benchmark. These needs can conflict with publishing weights, prompts or raw responses.

Confidential evaluation is already being deployed between selected organizations. The [Google DeepMind double-blind pilot](https://deepmind.google/blog/piloting-the-worlds-first-double-blind-ai-evaluations/) demonstrates that direction with external partners and confidential benchmarks. ARTT proposes a public filing and release interface that could complement confidential execution infrastructure. It does not replace enclaves, cryptographic proofs or a custodian's access policy.

If adopted with suitable custody, witnessing and practical privacy settings, this could broaden who can challenge AI claims, make submitted methods easier to inspect, and make recorded refusals and access limits easier to scrutinize. Broader coverage and better governance are intended benefits, not outcomes measured by our experiments.

## Our contributions

**1. A public evaluation contract.** A filing identifies executable code, a public method card, the declared result schema and resource limits. Model/configuration commitments identify the intended evaluation target. The protocol specifies admissions, protected releases and refusal records. This is a concrete proposal for organizing access; it does not establish that every filed test is scientifically valid or must be admitted.

**2. An adversarial model of the public result.** A small score is still a channel. A hostile judge can encode a private fact in its score, crash, timeout or record shape. We demonstrate status leakage with a language model in the loop and extend the coding study to a genuine correctness property: which expected value a hidden assertion checks. The contribution is the analysis and measured application to AI evaluation, not the discovery of covert channels in general.

**3. A release mechanism with explicit accounting.** The trusted publisher owns the output format and randomness. Access is charged before execution; post-access failures become a fixed raw fallback; successes and fallbacks pass through the same score-noise kernel and scheduled record interface. Shared budgets limit repetition across filers and program aliases. The expected-value experiment reserves its experiment and secret allowances atomically. The privacy bound covers the defined public record under stated trust and delivery assumptions. Physical timing and generic shared-queue noninterference remain outside the established guarantee.

**4. A record readers can check.** Hash-chained ledgers, retained checkpoints, source snapshots, pre-access commitments and durable budgets connect reported results to preserved artifacts. Checkpoints detect modification or truncation of their committed prefix. Hashes establish integrity, not truthful execution; external witnessing, omission detection and protection against a hostile custodian remain additional work.

**5. Measurements that show the protection's boundary.** We retain the ideal case, then measure useful scores, a meaningful private suite choice, repeated releases and honest utility. This distinguishes status suppression from the remaining score channel and exposes the privacy and utility tradeoff.

## What the latest coding experiment establishes

The expected-value protocol was committed before execution. It uses all 128 pinned Qwen3-0.6B attack patches and 48 honest patches, across 48 tiny public tasks, with zero fresh GPU generations. A private choice selects one of two valid assertions with different expected values; three other checks stay common. Candidate suites and candidate-zero ordinary scores are public attacker side information.

Recovery is **128/128 from exposed exact outcomes, 90/128 after one noisy release, and 101/128 after four**. The four-release cap then refuses 512 further attempts, adding no charge or backend call while honest capacity remains. The earlier optimal equal-score case remains a separate control: status recovery falls from 128/128 to 64/128 when successful and fallback raw scores are identical.

Honest patches pass **29/48 suites**. Across 192 noisy observations, the pass estimate is **0.510**, compared with exact truth **0.604**, with a conservative 95% interval of **0.216–0.804**. This measures noise on the fixed corpus, not performance on unseen tasks.

At this setting four two-score releases cost **ε = 8.7889 per secret**, conditional on the experiment's isolated private contexts and trusted publisher. **ARTT meters the channel here; it does not make one bit private.** The fresh-secret experiment has its own fixed allowance, and all historical charges remain intact. Exact comparisons and research diagnostics make the full published research transcript non-private. Discarded private labels leave recovery totals as trusted custodian aggregates.

[Combined report](https://siddakbath.github.io/artt-protocol/results/coding-expected-value-2026-10-12/report/report.html) · [Protocol and detailed results](../demos/coding_agent/README.md#expected-value-secret-and-honest-utility) · [Evidence index](../results/README.md)

## How to position the research

ARTT builds on existing confidential execution, differential privacy and covert-channel defenses. In particular, [Differential Privacy Under Fire](https://www.usenix.org/conference/usenix-security-11/differential-privacy-under-fire) established the importance of timing, shared state, budgets and defaults for adversarial private queries. Our claimed contribution is the specified public AI evaluation interface, its treatment of the declared release as a complete adversarial channel, and the end-to-end implementation and measurements. We do not claim to have invented those underlying defenses or established their absence from every other system.

The long-term proposition is testable: **confidentiality should permit more independent scrutiny when access and disclosure are governed together.** The prototype supplies a mechanism and evidence for part of that proposition. Real-world adoption, useful operating points, independent reproduction, stronger custody and broader evaluations are the work that would turn it into practical infrastructure.
