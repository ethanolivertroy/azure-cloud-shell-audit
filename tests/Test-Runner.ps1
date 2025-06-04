#!/usr/bin/env pwsh
#Requires -Version 7.0

<#
.SYNOPSIS
    Test runner for Azure Security Audit Tool
.DESCRIPTION
    Executes all unit tests and integration tests with comprehensive reporting
.PARAMETER TestType
    Type of tests to run (Unit, Integration, All)
.PARAMETER OutputFormat
    Output format for test results (Console, NUnitXml, JUnitXml)
.PARAMETER Coverage
    Enable code coverage analysis
.EXAMPLE
    ./Test-Runner.ps1 -TestType All -OutputFormat JUnitXml -Coverage
#>

param(
    [ValidateSet("Unit", "Integration", "All")]
    [string]$TestType = "All",
    
    [ValidateSet("Console", "NUnitXml", "JUnitXml")]
    [string]$OutputFormat = "Console",
    
    [switch]$Coverage,
    
    [string]$OutputPath = "./test-results"
)

# Ensure Pester is available
if (-not (Get-Module -ListAvailable -Name Pester)) {
    Write-Host "Installing Pester testing framework..." -ForegroundColor Yellow
    Install-Module -Name Pester -Force -SkipPublisherCheck
}

Import-Module Pester -Force

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

Write-Host "Azure Security Audit Tool - Test Runner" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host ""

# Define test configurations
$testConfigs = @()

if ($TestType -in @("Unit", "All")) {
    $testConfigs += @{
        Name = "Unit Tests"
        Path = "./tests/unit/*.ps1"
        Tags = @("Unit")
    }
}

if ($TestType -in @("Integration", "All")) {
    $testConfigs += @{
        Name = "Integration Tests" 
        Path = "./tests/integration/*.ps1"
        Tags = @("Integration")
    }
}

# Run tests
$allResults = @()

foreach ($config in $testConfigs) {
    Write-Host "Running $($config.Name)..." -ForegroundColor Yellow
    Write-Host ""
    
    $pesterConfig = New-PesterConfiguration
    $pesterConfig.Run.Path = $config.Path
    $pesterConfig.Filter.Tag = $config.Tags
    $pesterConfig.Output.Verbosity = "Detailed"
    
    # Configure output format
    switch ($OutputFormat) {
        "NUnitXml" {
            $outputFile = Join-Path $OutputPath "$($config.Name -replace ' ', '-')-results.xml"
            $pesterConfig.TestResult.Enabled = $true
            $pesterConfig.TestResult.OutputFormat = "NUnitXml"
            $pesterConfig.TestResult.OutputPath = $outputFile
        }
        "JUnitXml" {
            $outputFile = Join-Path $OutputPath "$($config.Name -replace ' ', '-')-results.xml"
            $pesterConfig.TestResult.Enabled = $true
            $pesterConfig.TestResult.OutputFormat = "JUnitXml"
            $pesterConfig.TestResult.OutputPath = $outputFile
        }
    }
    
    # Configure code coverage
    if ($Coverage) {
        $pesterConfig.CodeCoverage.Enabled = $true
        $pesterConfig.CodeCoverage.Path = @("./modules/**/*.ps1")
        $pesterConfig.CodeCoverage.OutputFormat = "JaCoCo"
        $pesterConfig.CodeCoverage.OutputPath = Join-Path $OutputPath "coverage.xml"
    }
    
    # Run the tests
    $result = Invoke-Pester -Configuration $pesterConfig
    $allResults += $result
    
    Write-Host ""
}

# Generate summary report
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "============" -ForegroundColor Cyan

$totalTests = ($allResults | ForEach-Object { $_.TotalCount }) | Measure-Object -Sum | Select-Object -ExpandProperty Sum
$passedTests = ($allResults | ForEach-Object { $_.PassedCount }) | Measure-Object -Sum | Select-Object -ExpandProperty Sum
$failedTests = ($allResults | ForEach-Object { $_.FailedCount }) | Measure-Object -Sum | Select-Object -ExpandProperty Sum
$skippedTests = ($allResults | ForEach-Object { $_.SkippedCount }) | Measure-Object -Sum | Select-Object -ExpandProperty Sum

Write-Host "Total Tests: $totalTests" -ForegroundColor White
Write-Host "Passed: $passedTests" -ForegroundColor Green
Write-Host "Failed: $failedTests" -ForegroundColor Red
Write-Host "Skipped: $skippedTests" -ForegroundColor Yellow

$successRate = if ($totalTests -gt 0) { [math]::Round(($passedTests / $totalTests) * 100, 2) } else { 0 }
Write-Host "Success Rate: $successRate%" -ForegroundColor $(if ($successRate -ge 95) { "Green" } elseif ($successRate -ge 80) { "Yellow" } else { "Red" })

# Code coverage summary
if ($Coverage -and (Test-Path (Join-Path $OutputPath "coverage.xml"))) {
    Write-Host ""
    Write-Host "Code Coverage Analysis" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    
    # Parse coverage XML (simplified)
    try {
        [xml]$coverageXml = Get-Content (Join-Path $OutputPath "coverage.xml")
        $coverage = $coverageXml.report.counter | Where-Object { $_.type -eq "LINE" }
        
        if ($coverage) {
            $coveredLines = [int]$coverage.covered
            $totalLines = [int]$coverage.covered + [int]$coverage.missed
            $coveragePercent = if ($totalLines -gt 0) { [math]::Round(($coveredLines / $totalLines) * 100, 2) } else { 0 }
            
            Write-Host "Line Coverage: $coveragePercent% ($coveredLines/$totalLines lines)" -ForegroundColor $(if ($coveragePercent -ge 80) { "Green" } elseif ($coveragePercent -ge 60) { "Yellow" } else { "Red" })
        }
    }
    catch {
        Write-Warning "Could not parse coverage report: $($_.Exception.Message)"
    }
}

Write-Host ""

# Exit with appropriate code
if ($failedTests -gt 0) {
    Write-Host "Some tests failed. Check the results above." -ForegroundColor Red
    exit 1
}
else {
    Write-Host "All tests passed successfully!" -ForegroundColor Green
    exit 0
}