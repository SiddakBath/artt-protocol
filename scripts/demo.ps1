param([string]$Output = 'scratch/coding-demo')
$ErrorActionPreference = 'Stop'
if ($Output -notmatch '^[A-Za-z0-9_./-]+$') {
    throw 'Output must be a simple relative Linux path.'
}
$repository = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$command = ".venv/bin/python -m demos.coding_agent.run --output $Output && .venv/bin/python -m demos.coding_agent.report --input $Output --html $Output/report.html"
wsl --cd $repository -- bash -lc $command
if ($LASTEXITCODE -ne 0) { throw "WSL demo failed with exit code $LASTEXITCODE. Its output is preserved." }
