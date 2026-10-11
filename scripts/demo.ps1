param(
    [string]$Output = 'scratch/coding-demo',
    [ValidateSet('fixture', 'local-qwen')][string]$Backend = 'fixture',
    [string]$ModelPath,
    [string]$ModelPython
)
$ErrorActionPreference = 'Stop'
if ($Output -notmatch '^[A-Za-z0-9_./-]+$') {
    throw 'Output must be a simple relative Linux path.'
}
$repository = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if ($Backend -eq 'local-qwen') {
    if (-not $ModelPath) { $ModelPath = Join-Path $repository '../research/adversarial-auditor-independence/models/Qwen3-0.6B' }
    if (-not $ModelPython) { $ModelPython = Join-Path $repository '../.venv/Scripts/python.exe' }
    if (-not (Test-Path -LiteralPath $ModelPython)) { throw 'Set -ModelPython to a Windows Python with the documented CUDA runtime.' }
    Push-Location -LiteralPath $repository
    try {
        & $ModelPython -u -m demos.coding_agent.run --backend local-qwen --model-path $ModelPath --output $Output
        if ($LASTEXITCODE -ne 0) { throw "Real-model run failed with exit code $LASTEXITCODE. Its evidence is preserved." }
    } finally { Pop-Location }
    $command = ".venv/bin/python -m demos.coding_agent.real_report --input $Output --output $Output-report"
    wsl --cd $repository -- bash -lc $command
    if ($LASTEXITCODE -ne 0) { throw "Real-model report failed with exit code $LASTEXITCODE." }
    return
}
$command = ".venv/bin/python -m demos.coding_agent.run --output $Output && .venv/bin/python -m demos.coding_agent.report --input $Output --html $Output/report.html"
wsl --cd $repository -- bash -lc $command
if ($LASTEXITCODE -ne 0) { throw "WSL demo failed with exit code $LASTEXITCODE. Its output is preserved." }
