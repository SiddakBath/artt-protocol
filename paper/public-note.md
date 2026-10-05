# A Right to Test (ARTT): Public Evaluation Under Output Confidentiality

ARTT is a proposed way for people outside an AI lab to file an evaluation for a
custodian-held model. The evaluation runs in a sealed environment beside the
model. The custodian keeps the weights, prompts, raw responses, and private
execution details confidential. The filer and public receive only a small,
declared result record. That makes it possible to learn something from an
evaluation without publishing the model or its raw outputs.

## What is filed and what is released

An evaluation is the whole procedure: its code, prompts or task environment,
any allowed tool use, scoring rule, and resource budget. A verdict is the small
record released after that evaluation runs. A filing identifies its code and
optional local evaluator model with hashes, a public method card, a release
schema, and resource limits. The study does not demonstrate tool-use or
multi-step agent evaluations. The same release mechanism can apply when every
tool stays inside the seal and has no external side effect; otherwise the tool
is another exit that needs its own protection. This paper's implementation,
experiments and theorem cover judges that make one model call per admission.

ARTT does not prescribe which target models a custodian must offer or how large
they must be. It applies when the custodian commits to the model identity and
serving configuration while retaining the weights and raw outputs. It also does
not establish that a filed evaluation is scientifically valid. It protects the
release interface around an evaluation; evaluation design and validation remain
separate work.

The prototype writes results to a public hash-chained ledger. ARTT recommends
such a ledger because it can make filings and refusals visible, but it is not a
core requirement of the release mechanism or its privacy guarantee. A deployment
can use another declared public or authorized-observer interface instead.

## Why the release needs protection

A limited verdict is still a channel out of the sealed environment. A hostile
evaluator can choose a score, an error, a timeout, or a record shape based on a
private model response. A reader can then decode that choice. A smaller output
schema does not solve the problem if the evaluator still controls even one bit.

ARTT charges the privacy budget before model access. Every post-access failure,
including a timeout, maps to the same fallback value as the protected success
path. The publisher applies the same fresh noise to both values and releases one
record of the same shape on a fixed schedule. This means that run status and
other execution details cannot become a second, unprotected exit.

## What this study shows

The target model in the main study was Qwen3-0.6B, a small open-weight stand-in.
The judges in that study were deterministic code, not another language model.
Across 256 admissions, the task instantiated four deterministic prompts; it was
a literal-format canary task, not a semantic alignment measurement. A separate
fixture study used an honest substring-rule judge across 32 public prompts.

The status attack is the central result. A malicious judge made a constant
proposal for one planted secret and failed for the other. With the status channel
open, a decoder recovered the secret in 256/256 trials even though the score did
not change. With the ARTT release protocol, status recovery fell to 128/256,
including deliberate timeouts. A score decoder obtained 124/256 across three
closed attacks and 202/256 when its score channel was deliberately opened. On
the same protected contexts, an honest evaluator retained an aggregate formatting
signal, including every fallback.

Earlier fixture experiments show the same lesson. Four or two free score axes
can carry a planted secret in all 256 trials. A runner-fixed verdict removes
that choice, but also removes useful evaluator discretion. Runner-owned noise
can make one release unreliable, yet repeated releases can average it away. The
whole release, not only the score, needs protection.

## Scope

The privacy proof depends on trusted isolation, accounting, the custodian and
publisher, and fixed-slot delivery. It does not cover hardware attacks, host
telemetry, physical timing, ledger rollback, or shared-queue effects without an
additional locality argument. The paper gives a bounded release protocol and an
end-to-end attack and repair for a defined task. It does not claim to solve
model-wide secrecy, hardware custody, or semantic alignment evaluation.

The goal is practical: let people file tests, make the evaluation method
inspectable, publish a useful protected result, and measure what that result can
leak. The research draft contains the implementation, theorem, evidence, and
full boundaries.
