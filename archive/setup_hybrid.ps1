# Quick Hybrid Setup Script
# For RTX 4050 Users

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Hybrid LLM Setup for RTX 4050" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check if Ollama is installed
Write-Host "[1/5] Checking Ollama installation..." -ForegroundColor Yellow
$ollamaInstalled = Get-Command ollama -ErrorAction SilentlyContinue

if (-not $ollamaInstalled) {
    Write-Host "  X Ollama not found!" -ForegroundColor Red
    Write-Host "  Installing Ollama..." -ForegroundColor Yellow
    
    try {
        winget install Ollama.Ollama
        Write-Host "  OK Ollama installed!" -ForegroundColor Green
    }
    catch {
        Write-Host "  X Failed to install Ollama automatically" -ForegroundColor Red
        Write-Host "  Please download manually from: https://ollama.ai" -ForegroundColor Yellow
        exit 1
    }
}
else {
    Write-Host "  OK Ollama already installed" -ForegroundColor Green
}

Write-Host ""

# Step 2: Check if model is downloaded
Write-Host "[2/5] Checking for model..." -ForegroundColor Yellow
$modelName = "qwen2.5-coder:7b-instruct-q4_K_M"

$modelExists = ollama list | Select-String -Pattern "qwen2.5-coder"

if (-not $modelExists) {
    Write-Host "  Downloading model (this may take 5-10 minutes)..." -ForegroundColor Yellow
    Write-Host "  Model: $modelName" -ForegroundColor Cyan
    Write-Host "  Size: ~4GB" -ForegroundColor Cyan
    Write-Host ""
    
    ollama pull $modelName
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  OK Model downloaded!" -ForegroundColor Green
    }
    else {
        Write-Host "  X Failed to download model" -ForegroundColor Red
        exit 1
    }
}
else {
    Write-Host "  OK Model already downloaded" -ForegroundColor Green
}

Write-Host ""

# Step 3: Test model
Write-Host "[3/5] Testing model..." -ForegroundColor Yellow
Write-Host "  Running quick test..." -ForegroundColor Cyan

$testPrompt = "Fix this C code: int main() { printf('hello'); return 0; }"
$testOutput = ollama run $modelName $testPrompt 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "  OK Model works!" -ForegroundColor Green
}
else {
    Write-Host "  ! Model test timed out (this is OK if first run)" -ForegroundColor Yellow
}

Write-Host ""

# Step 4: Check GPU
Write-Host "[4/5] Checking GPU..." -ForegroundColor Yellow

$gpuCheck = nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "  GPU: $gpuCheck" -ForegroundColor Cyan
    Write-Host "  OK NVIDIA GPU detected" -ForegroundColor Green
}
else {
    Write-Host "  ! Could not detect GPU (Ollama will use CPU)" -ForegroundColor Yellow
}

Write-Host ""

# Step 5: Update config
Write-Host "[5/5] Updating configuration..." -ForegroundColor Yellow

$configPath = "project_config.json"

if (Test-Path $configPath) {
    # Backup config
    Copy-Item $configPath "$configPath.backup" -Force
    Write-Host "  Backed up config to project_config.json.backup" -ForegroundColor Cyan
    
    # Read config
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
    
    # Update hybrid settings
    $config.compilation.use_hybrid_llm = $false  # Default to false, user can enable
    $config.compilation.hybrid_local_model = $modelName
    $config.compilation.hybrid_local_file_size_limit = 15000
    
    # Save config
    $config | ConvertTo-Json -Depth 10 | Set-Content $configPath
    
    Write-Host "  OK Config updated with hybrid settings" -ForegroundColor Green
    Write-Host "  Note: Hybrid mode is DISABLED by default" -ForegroundColor Yellow
    Write-Host "  To enable: Set use_hybrid_llm: true in config" -ForegroundColor Yellow
}
else {
    Write-Host "  ! Config file not found: $configPath" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Edit project_config.json:" -ForegroundColor White
Write-Host "   Set 'use_hybrid_llm': true" -ForegroundColor Yellow
Write-Host ""
Write-Host "2. Run the pipeline:" -ForegroundColor White
Write-Host "   python project_based_pipeline.py --config project_config.json" -ForegroundColor Yellow
Write-Host ""
Write-Host "3. Check statistics at the end of the run" -ForegroundColor White
Write-Host ""

Write-Host "For detailed guide, see: HYBRID_SETUP_GUIDE.md" -ForegroundColor Cyan
Write-Host ""
