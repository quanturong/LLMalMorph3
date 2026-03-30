param(
    [string]$Config = ".\configs\framework_production.json",
    [switch]$DryRun
)

$repoRoot = Split-Path -Parent $PSScriptRoot
$pythonExe = Join-Path $repoRoot ".venv\Scripts\python.exe"
$runner = Join-Path $repoRoot "run_production_framework.py"

if (-not (Test-Path $pythonExe)) {
    throw "Python virtual environment not found at $pythonExe"
}

$configPath = $Config
if (-not [System.IO.Path]::IsPathRooted($configPath)) {
    $configPath = Join-Path $repoRoot $configPath
}
$configPath = (Resolve-Path $configPath).Path

$argList = @($runner, "--config", $configPath)
if ($DryRun) {
    $argList += "--dry-run"
}

& $pythonExe @argList
exit $LASTEXITCODE
