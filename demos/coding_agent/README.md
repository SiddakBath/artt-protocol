# ARTT on a coding-agent evaluation

This demonstrates the existing release protocol on 48 tiny Python coding
tasks. Agent A and Agent B are deterministic fixtures, not learned models.
They pass 36 and 19 tasks by construction. During evaluation the custodian
returns one patch plus private assert checks and a canary comment. The source
is published for reproducibility; the shuffled trial canaries are not.

A naive design that publishes accepted versus error status leaks the canary
when a constant-score judge crashes on one value. Scheduled release gives
both branches the same raw fallback and applies the same trusted noise kernel.
A deliberate score encoder still receives a noisy signal. Its score channel
is bounded and logged, not closed.

Run on Linux or Windows via WSL, from the repository root:

```bash
.venv/bin/python -m rt.build_sandbox
make demo
```

On Windows, run `scripts/demo.ps1`. To choose a fresh evidence directory:

```bash
make demo OUTPUT=scratch/coding-demo-next
```

The runner refuses an existing directory. Do not replace interrupted evidence
or rerun for nicer numbers. It copies the committed protocol and its hash
before access, then writes all evidence to ignored `scratch/` paths. Its
protocol must match the committed bytes. Small live tests are separate from
the full reported cohort.

Open `scratch/coding-demo/report.html`. This is one offline file with no
network dependencies. It shows counts, Wilson intervals, honest estimates
with conservative Hoeffding intervals, searchable public records, a budget
timeline, and observed tamper-verifier results. `README-numbers.md` is generated
from the same summary. Counts are never typed into the report by hand.

The inherited axis names mean hidden-test pass bucket (`deception`) and
declared signature check (`sycophancy`). Attack judges encode a bit instead
of measuring these properties. The first-axis honest estimator is the mean
released bucket minus one. With 48 filings per agent, its conservative
difference interval can include zero. Read the interval before narrating a
performance separation.

Every scheduled batch has a separate hash chain and checkpoint. An edited row
and deleted middle row fail chain verification. A deleted suffix can pass;
comparison against a retained head checkpoint catches this demonstration.
An independent holder must retain that checkpoint. CT-style witnessing is
future work. There is no external witness in this demo.

The protocol predeclares 128 trials per attack, a total cap of 352 scheduled
admissions, and 8 extra filings. Bundles permit one call and two seconds. The
worker window is 2.5 seconds because the suggested 0.5-second window would
reject that bundle limit. Slots remain 0.1 seconds apart. The runner measures
actual elapsed time and reports it as an observation.

The passport file is a proposed mapping. It is not an AIUC or Lucid format;
no endorsement or compatibility is implied. The custodian is trusted, the
sandbox is software rather than hardware, and timing noninterference is not
proven. Public recovery totals are trusted custodian aggregates; private
trial labels are discarded.

## Recording guide

1. Show `protocol.json`, including the fixed cohort size, decoder, cap and
   timing. Explain that the agents are fixtures.
2. Run `make demo` in a fresh directory. Each admitted judge gets at most one
   model call in the Linux software sandbox. Runtime comes from the receipt.
3. Open the report. Read the naive and ARTT status and score counts directly
   from the table. Describe the deliberate score encoder as bounded and logged.
4. Read the honest estimates and difference interval. If the interval includes
   zero, say that this sample does not establish separation.
5. Search the ledger and select a row. The tampered copies are shown by
   default: edited and middle-deleted chains fail; a deleted tail needs the
   retained checkpoint. The toggle shows the original passing ledgers.
6. Show the cap and refusals with the unchanged call counter. Close with the
   trusted-custodian, software-sandbox and unproved timing scope.

## Separately predeclared utility follow-up

The first run and its wide utility interval remain unchanged. A second,
utility-only protocol lives in `utility-protocol.json`. It declares 24 full
passes of the same 48-task corpus per fixture agent, or 1,152 admissions each.
The conservative Hoeffding difference radius is at most half the assumed gap
of 0.35. Repeated admissions reduce release-noise uncertainty on this fixed
corpus; they do not establish performance on unseen tasks or learned agents.
The first utility sample is not pooled with the second.

Run once in a fresh output directory, with the committed protocol:

```bash
.venv/bin/python -m demos.coding_agent.utility_run --first-run scratch/coding-demo --output scratch/coding-demo-utility
.venv/bin/python -m demos.coding_agent.review_report --first-run scratch/coding-demo --utility-run scratch/coding-demo-utility --output scratch/coding-demo-review
```

The utility runner copies the first budget, carries forward its 352 charges,
and applies the explicitly predeclared cap extension to 2,656 before access.
The extra 2,304 admissions have extra privacy cost. The original database and
all first-run evidence are checked for byte-for-byte preservation. The review
report shows both studies with their own provenance and intervals, and the
combined accounting. Its files live in a separate ignored directory.

The revised passport names its running field
`epsilon_cumulative_scope_through_this_record`. A distinct
`epsilon_scope_total_in_this_export` and top-level `privacy_scope_totals`
describe the complete exported scope. An early record's running total is
smaller than the completed export total. Historical admission caps remain in
each record; the scope summary lists both declared caps when the allowance
was explicitly extended.

## Optional live local model

The default remains the fixture backend. `--backend local-qwen` uses an offline
Qwen3-0.6B checkpoint to generate a fresh Python patch after every admission.
It never substitutes fixture solutions, caches patches, repairs incorrect
code, or retries failed generations. The model sees only the public task
description, signature and example. The custodian appends hidden checks and
the synthetic private canary for the judge after inference. The attack is
therefore a judge leaking its private test context, rather than a claim about
extracting Qwen's training data.

On this Windows host, use the existing CUDA environment and local checkpoint:

```powershell
./scripts/demo.ps1 -Backend local-qwen -Output scratch/coding-demo-qwen
```

Set `-ModelPath` and `-ModelPython` for other installed checkpoint/runtime paths.
The runtime requirements are in `requirements-runtime.txt`; the demo does not
download a model or install packages. A Linux CUDA host can run the same flag:

```bash
python -m demos.coding_agent.run --backend local-qwen --model-path /path/to/Qwen3-0.6B --output scratch/coding-demo-qwen
.venv/bin/python -m demos.coding_agent.real_report --input scratch/coding-demo-qwen --output scratch/coding-demo-qwen-report
```

`real-model-protocol.json` commits the actual checkpoint hashes, CUDA device,
greedy non-thinking generation, 256-token limit, batch size, 128 trials per
attack, 48 honest tasks per release path, 304 new scheduled admissions and 8
extra refusals. The same canary assignments and public tasks are used in the
naive and ARTT arms, with fresh model inference in each. All 608 inferences
are counted at the GPU host. The conservative honest interval compares one
real model's ARTT estimate with its unnoised control; it is separate from the
fixture A/B study and makes no new A/B separation claim.

Public-only timing preflights are preserved separately. The live protocol has
a 60-second worker limit, 60.5-second window and three-second slot period,
chosen before private access. The report includes late proposals, timeouts and
actual code failures. The allowance extension copies the prior durable budget,
carries forward 2,656 charges and extends the cap to 2,960 before access.
The unsafe comparator is separately precharged and has no finite privacy
guarantee for its intentionally published status channel. Composed epsilon in
the passport describes the ARTT releases only.

Every run requires a fresh output directory. The reported protocol must match
its committed bytes, as must the downloaded checkpoint. Source and model-file
hashes are checked after execution, as are all retained earlier evidence
bytes. Model-generated public patches, their hashes, token counts, backend
receipt, admission counts and verifier outcomes are preserved. Hidden canary
schedules are discarded. The real-model report shows generated patch examples
and links to an unchanged copy of the earlier fixture report.
