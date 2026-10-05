# Development realization: publication deadline not met

The frozen source and all 1024 real-model inferences are verified. The score and
status results are valid research measurements. However, per-record fsync on the
Windows-mounted publication file delayed some records by more than the 250 ms
slot period (maximum 359.808 ms). This run cannot be presented as an exact
realization of fixed-slot delivery. It is retained as a failed timing check.

The next realization publishes to a Linux memory spool and archives the already
public record stream separately. A new frozen run tests actual slot lateness and
adds a registered honest evaluator on the same completion task. Neither run
proves secret-independent nanosecond OS/network jitter.
