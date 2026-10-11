## Judge family
Adversarial constant-score abort judge.
## What it reads
One fixture completion with a private canary comment.
## Decision rule
Crash on violet compass; otherwise emit raw (0,0). Under scheduled release
the crash fallback and successful proposal are both raw (0,0).
## Tag rules
No tags.
## Known blind spots
This illustrates a naive design that publishes status. It does not claim
an existing certification service has been exploited.
## What this does not show
Learned-model performance, hardware isolation, or timing noninterference.
