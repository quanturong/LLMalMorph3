# 🎯 Run All 6 Mutation Strategies
# This script automatically runs the pipeline with each strategy

Write-Host "`n══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "    🚀 MULTI-STRATEGY PIPELINE RUNNER" -ForegroundColor Yellow
Write-Host "══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

# Configuration
$strategies = @("strat_1", "strat_2", "strat_3", "strat_4", "strat_5", "strat_6")
$configFile = "project_config.json"
$backupFile = "project_config.json.backup"
$resultsDir = "multi_strategy_results"

# Strategy descriptions
$strategyDesc = @{
    "strat_1" = "Code Obfuscation"
    "strat_2" = "Control Flow Obfuscation"
    "strat_3" = "Data Obfuscation"
    "strat_4" = "Code Restructuring"
    "strat_5" = "Anti-Analysis Techniques"
    "strat_6" = "Combined Strategies"
}

# Create results directory
if (!(Test-Path $resultsDir)) {
    New-Item -ItemType Directory -Path $resultsDir | Out-Null
    Write-Host "✓ Created results directory: $resultsDir" -ForegroundColor Green
}

# Backup original config
if (!(Test-Path $backupFile)) {
    Copy-Item $configFile $backupFile
    Write-Host "✓ Backed up config: $backupFile" -ForegroundColor Green
}

Write-Host "`nRunning $($strategies.Count) strategies..." -ForegroundColor Cyan
Write-Host "Estimated total time: ~2-2.5 hours`n" -ForegroundColor Yellow

# Set environment variables
$env:OLLAMA_MODELS = "E:\Ollama\models"
if ($env:MISTRAL_API_KEY) {
    Write-Host "✓ MISTRAL_API_KEY is set" -ForegroundColor Green
} else {
    Write-Host "⚠️  MISTRAL_API_KEY not set (will use local-only mode)" -ForegroundColor Yellow
}

# Results tracking
$results = @()
$startTime = Get-Date

foreach ($strat in $strategies) {
    $stratStartTime = Get-Date
    
    Write-Host "`n══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  📊 STRATEGY: $strat - $($strategyDesc[$strat])" -ForegroundColor Yellow
    Write-Host "══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan
    
    try {
        # Update config with new strategy
        $config = Get-Content $configFile -Raw | ConvertFrom-Json
        $config.mutation.strategy = $strat
        $config | ConvertTo-Json -Depth 10 | Set-Content $configFile
        
        Write-Host "✓ Updated config to use $strat" -ForegroundColor Green
        Write-Host "Running pipeline...`n" -ForegroundColor Cyan
        
        # Run pipeline
        python project_based_pipeline.py
        
        $stratDuration = (Get-Date) - $stratStartTime
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "`n✓ $strat completed successfully in $($stratDuration.ToString('mm\:ss'))" -ForegroundColor Green
            
            # Find the latest run folder
            $latestRun = Get-ChildItem "project_mutation_output" -Directory | 
                         Sort-Object CreationTime -Descending | 
                         Select-Object -First 1
            
            if ($latestRun) {
                # Copy to results directory
                $destDir = Join-Path $resultsDir $strat
                Copy-Item -Path $latestRun.FullName -Destination $destDir -Recurse -Force
                Write-Host "✓ Results copied to: $destDir" -ForegroundColor Green
                
                # Read final report
                $reportPath = Join-Path $latestRun.FullName "final_report.json"
                if (Test-Path $reportPath) {
                    $report = Get-Content $reportPath -Raw | ConvertFrom-Json
                    $successCount = $report.successful_compilations
                    $totalProjects = $report.projects_compiled
                    
                    $results += [PSCustomObject]@{
                        Strategy = $strat
                        Description = $strategyDesc[$strat]
                        Success = $successCount
                        Total = $totalProjects
                        SuccessRate = "$([math]::Round($successCount/$totalProjects*100, 1))%"
                        Duration = $stratDuration.ToString('mm\:ss')
                        Status = "✓ Success"
                    }
                    
                    Write-Host "  Projects compiled: $successCount/$totalProjects ($([math]::Round($successCount/$totalProjects*100, 1))%)" -ForegroundColor Cyan
                }
            }
        } else {
            Write-Host "`n✗ $strat failed (Exit code: $LASTEXITCODE)" -ForegroundColor Red
            
            $results += [PSCustomObject]@{
                Strategy = $strat
                Description = $strategyDesc[$strat]
                Success = 0
                Total = 0
                SuccessRate = "0%"
                Duration = $stratDuration.ToString('mm\:ss')
                Status = "✗ Failed"
            }
        }
    }
    catch {
        Write-Host "`n✗ Error running $strat : $_" -ForegroundColor Red
        
        $results += [PSCustomObject]@{
            Strategy = $strat
            Description = $strategyDesc[$strat]
            Success = 0
            Total = 0
            SuccessRate = "0%"
            Duration = "N/A"
            Status = "✗ Error"
        }
    }
}

# Restore original config
Copy-Item $backupFile $configFile -Force
Write-Host "`n✓ Restored original config" -ForegroundColor Green

# Calculate total time
$totalDuration = (Get-Date) - $startTime

# Display final summary
Write-Host "`n══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "    📊 FINAL SUMMARY" -ForegroundColor Yellow
Write-Host "══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

$results | Format-Table -AutoSize

Write-Host "`n📈 Statistics:" -ForegroundColor Cyan
$totalSuccess = ($results | Measure-Object -Property Success -Sum).Sum
$totalProjects = ($results | Measure-Object -Property Total -Sum).Sum
$avgSuccessRate = if ($totalProjects -gt 0) { [math]::Round($totalSuccess/$totalProjects*100, 1) } else { 0 }

Write-Host "  Total variants compiled: $totalSuccess/$totalProjects" -ForegroundColor White
Write-Host "  Average success rate: $avgSuccessRate%" -ForegroundColor White
Write-Host "  Total duration: $($totalDuration.ToString('hh\:mm\:ss'))" -ForegroundColor White
Write-Host "  Results saved in: $resultsDir" -ForegroundColor White

# Export results to CSV
$csvPath = Join-Path $resultsDir "summary.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "`n✓ Summary exported to: $csvPath" -ForegroundColor Green

# Export results to JSON
$jsonPath = Join-Path $resultsDir "summary.json"
$results | ConvertTo-Json | Set-Content $jsonPath
Write-Host "✓ Summary exported to: $jsonPath" -ForegroundColor Green

Write-Host "`n══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "    ✅ ALL STRATEGIES COMPLETED!" -ForegroundColor Green
Write-Host "══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan





