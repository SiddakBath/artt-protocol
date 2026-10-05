# Development run: excluded from the frozen comparison

The runner source was edited while this development run was executing. Its v1
log contains four source versions. The interpreter had loaded the earlier
modules, so the later file hashes do not consistently identify its loaded code.
The receipts and logs are preserved, but this run is not used as the frozen
learned-model experiment. The new run explicitly checks one frozen source
version at initialization and on every filed entry.
