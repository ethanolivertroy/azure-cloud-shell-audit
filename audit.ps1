#!/usr/bin/env pwsh
#Requires -Version 7.0

<#
.SYNOPSIS
    Azure Security Audit Script for FedRAMP and NIST 800-53 Compliance
.DESCRIPTION
    This script performs comprehensive security audits of Azure environments directly from Azure Cloud Shell.
    It checks for compliance with FedRAMP and NIST 800-53 standards while assessing CIA triad impacts.
.PARAMETER SubscriptionId
    The Azure subscription ID to audit
.PARAMETER Controls
    Comma-separated list of control families to audit (e.g., "AC-*,AU-*")
.PARAMETER OutputFormat
    Output format for the report (JSON, HTML, CSV, Markdown)
.PARAMETER AssessmentType
    Type of assessment to perform (Full, CIA, QuickScan)
.EXAMPLE
    ./audit.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012"
.EXAMPLE
    ./audit.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" -Controls "AC-*,AU-*" -OutputFormat HTML
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory=$false)]
    [string]$Controls = "*",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("JSON", "HTML", "CSV", "Markdown")]
    [string]$OutputFormat = "HTML",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Full", "CIA", "QuickScan")]
    [string]$AssessmentType = "Full",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "./reports",
    
    [Parameter(Mandatory=$false)]
    [switch]$EnablePolicyCompliance,
    
    [Parameter(Mandatory=$false)]
    [switch]$EnableContinuousCompliance,
    
    [Parameter(Mandatory=$false)]
    [string]$NotificationEmail
)

# Script configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Import required modules
$modulePath = Join-Path $PSScriptRoot "modules"
$modules = @(
    "core/auth.ps1",
    "core/logging.ps1", 
    "core/reporting.ps1",
    "core/progress.ps1",
    "core/policy.ps1",
    "controls/iam.ps1",
    "controls/network.ps1",
    "controls/data.ps1",
    "controls/logging.ps1",
    "controls/incident.ps1",
    "controls/configuration.ps1",
    "controls/system-integrity.ps1",
    "controls/risk-assessment.ps1"
)

foreach ($module in $modules) {
    $fullPath = Join-Path $modulePath $module
    if (Test-Path $fullPath) {
        . $fullPath
    }
    else {
        Write-Warning "Module not found: $fullPath"
    }
}

# Initialize logging
Write-Host "Azure Security Audit Script v1.0" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Validate Azure Cloud Shell environment
function Test-CloudShellEnvironment {
    if (-not $env:AZUREPS_HOST_ENVIRONMENT) {
        Write-Warning "This script is optimized for Azure Cloud Shell. Some features may not work correctly in other environments."
    }
    
    # Check for required Azure modules
    $requiredModules = @("Az.Accounts", "Az.Resources", "Az.Security")
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            throw "Required module '$module' is not installed. Please run this script in Azure Cloud Shell."
        }
    }
}

# Main audit workflow
function Start-AzureSecurityAudit {
    param(
        [string]$SubscriptionId,
        [string]$Controls,
        [string]$OutputFormat,
        [string]$AssessmentType
    )
    
    $auditResults = @{
        Metadata = @{
            AuditDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            SubscriptionId = $SubscriptionId
            AssessmentType = $AssessmentType
            AuditorIdentity = $env:USER ?? "Unknown"
        }
        Summary = @{
            TotalControls = 0
            PassedControls = 0
            FailedControls = 0
            NotApplicable = 0
            CriticalFindings = 0
        }
        CIAImpact = @{
            Confidentiality = @{
                High = 0
                Medium = 0
                Low = 0
            }
            Integrity = @{
                High = 0
                Medium = 0
                Low = 0
            }
            Availability = @{
                High = 0
                Medium = 0
                Low = 0
            }
        }
        ControlResults = @()
    }
    
    Write-Host "Starting security audit for subscription: $SubscriptionId" -ForegroundColor Yellow
    Write-Host "Assessment Type: $AssessmentType" -ForegroundColor Yellow
    Write-Host "Control Scope: $Controls" -ForegroundColor Yellow
    Write-Host ""
    
    # Set Azure context
    try {
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
        Write-Host "✓ Successfully connected to Azure subscription" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to set Azure context: $_"
        return
    }
    
    # Perform control checks based on selection
    Write-Host ""
    Write-Host "Performing security control assessments..." -ForegroundColor Cyan
    Write-Host ""
    
    # Parse control selection and initialize progress
    $controlFamilies = $Controls -split ',' | ForEach-Object { $_.Trim() }
    $allControls = @()
    
    # Calculate total steps for progress tracking
    $totalSteps = 0
    foreach ($family in $controlFamilies) {
        switch -Wildcard ($family) {
            "AC-*" { $totalSteps += 2 }
            "SC-*" { $totalSteps += 2 }
            "AU-*" { $totalSteps += 1 }
            "IR-*" { $totalSteps += 1 }
            "CM-*" { $totalSteps += 1 }
            "SI-*" { $totalSteps += 1 }
            "RA-*" { $totalSteps += 1 }
            "IA-*" { $totalSteps += 1 }
            "MP-*" { $totalSteps += 1 }
            "*" { $totalSteps = 10; break }
            default { $totalSteps += 1 }
        }
    }
    
    # Initialize progress tracking
    Initialize-AuditProgress -TotalSteps $totalSteps
    $currentStep = 0
    
    # Run control assessments
    foreach ($family in $controlFamilies) {
        switch -Wildcard ($family) {
            "AC-*" {
                Update-AuditProgress -Operation "Access Control (AC) - Identity & Access Management" -Step (++$currentStep)
                $allControls += Test-IAMControls -SubscriptionId $SubscriptionId
                
                Update-AuditProgress -Operation "Access Control (AC) - Information Flow Enforcement" -Step (++$currentStep)
                $allControls += Test-InformationFlowEnforcement -SubscriptionId $SubscriptionId
            }
            "SC-*" {
                Update-AuditProgress -Operation "System & Communications Protection (SC) - Network Security" -Step (++$currentStep)
                $allControls += Test-NetworkControls -SubscriptionId $SubscriptionId
                
                Update-AuditProgress -Operation "System & Communications Protection (SC) - Data Protection" -Step (++$currentStep)
                $allControls += Test-DataProtectionControls -SubscriptionId $SubscriptionId
            }
            "AU-*" {
                Update-AuditProgress -Operation "Audit and Accountability (AU) - Logging & Monitoring" -Step (++$currentStep)
                $allControls += Test-LoggingControls -SubscriptionId $SubscriptionId
            }
            "IR-*" {
                Update-AuditProgress -Operation "Incident Response (IR) - Response Capabilities" -Step (++$currentStep)
                $allControls += Test-IncidentResponseControls -SubscriptionId $SubscriptionId
            }
            "CM-*" {
                Update-AuditProgress -Operation "Configuration Management (CM) - Change Control" -Step (++$currentStep)
                $allControls += Test-ConfigurationManagementControls -SubscriptionId $SubscriptionId
            }
            "SI-*" {
                Update-AuditProgress -Operation "System & Information Integrity (SI) - Integrity Controls" -Step (++$currentStep)
                $allControls += Test-SystemIntegrityControls -SubscriptionId $SubscriptionId
            }
            "RA-*" {
                Update-AuditProgress -Operation "Risk Assessment (RA) - Risk Management" -Step (++$currentStep)
                $allControls += Test-RiskAssessmentControls -SubscriptionId $SubscriptionId
            }
            "IA-*" {
                Update-AuditProgress -Operation "Identification and Authentication (IA) - Multi-Factor Auth" -Step (++$currentStep)
                $allControls += Test-MultifactorAuthentication -SubscriptionId $SubscriptionId
            }
            "MP-*" {
                Update-AuditProgress -Operation "Media Protection (MP) - Secure Transport" -Step (++$currentStep)
                $allControls += Test-MediaProtection -SubscriptionId $SubscriptionId
            }
            "*" {
                Update-AuditProgress -Operation "Comprehensive Audit - All Control Families" -Step (++$currentStep)
                $allControls += Test-IAMControls -SubscriptionId $SubscriptionId
                
                Update-AuditProgress -Operation "Network Security Controls" -Step (++$currentStep)
                $allControls += Test-NetworkControls -SubscriptionId $SubscriptionId
                
                Update-AuditProgress -Operation "Data Protection Controls" -Step (++$currentStep)
                $allControls += Test-DataProtectionControls -SubscriptionId $SubscriptionId
                
                Update-AuditProgress -Operation "Logging and Monitoring Controls" -Step (++$currentStep)
                $allControls += Test-LoggingControls -SubscriptionId $SubscriptionId
                
                Update-AuditProgress -Operation "Incident Response Controls" -Step (++$currentStep)
                $allControls += Test-IncidentResponseControls -SubscriptionId $SubscriptionId
                
                Update-AuditProgress -Operation "Configuration Management Controls" -Step (++$currentStep)
                $allControls += Test-ConfigurationManagementControls -SubscriptionId $SubscriptionId
                
                Update-AuditProgress -Operation "System Integrity Controls" -Step (++$currentStep)
                $allControls += Test-SystemIntegrityControls -SubscriptionId $SubscriptionId
                
                Update-AuditProgress -Operation "Risk Assessment Controls" -Step (++$currentStep)
                $allControls += Test-RiskAssessmentControls -SubscriptionId $SubscriptionId
                break
            }
            default {
                Update-AuditProgress -Operation "Checking $family controls" -Step (++$currentStep)
                Write-Host "  Custom control family: $family (manual implementation required)" -ForegroundColor Yellow
            }
        }
    }
    
    # Complete progress tracking
    Complete-AuditProgress
    
    # Check Azure Policy compliance if requested
    if ($EnablePolicyCompliance) {
        Write-Host ""
        Write-Host "Checking Azure Policy compliance..." -ForegroundColor Cyan
        $policyCompliance = Test-PolicyCompliance -SubscriptionId $SubscriptionId
        $auditResults.PolicyCompliance = $policyCompliance
    }
    
    # Enable continuous compliance if requested
    if ($EnableContinuousCompliance -and $NotificationEmail) {
        Write-Host ""
        Write-Host "Enabling continuous compliance monitoring..." -ForegroundColor Cyan
        Enable-ContinuousCompliance -SubscriptionId $SubscriptionId -ContactEmail $NotificationEmail
    }
    elseif ($EnableContinuousCompliance -and -not $NotificationEmail) {
        Write-Warning "Continuous compliance requires notification email. Use -NotificationEmail parameter."
    }
    
    # Process results and update summary
    foreach ($control in $allControls) {
        $auditResults.ControlResults += $control
        $auditResults.Summary.TotalControls++
        
        switch ($control.Status) {
            "Pass" { $auditResults.Summary.PassedControls++ }
            "Fail" { 
                $auditResults.Summary.FailedControls++
                if ($control.CIAImpact.Confidentiality -eq "High" -or 
                    $control.CIAImpact.Integrity -eq "High") {
                    $auditResults.Summary.CriticalFindings++
                }
            }
            "Manual" { $auditResults.Summary.NotApplicable++ }
        }
        
        # Update CIA impact counts
        foreach ($aspect in @("Confidentiality", "Integrity", "Availability")) {
            $impact = $control.CIAImpact.$aspect
            if ($impact -and $control.Status -eq "Fail") {
                $auditResults.CIAImpact.$aspect.$impact++
            }
        }
    }
    
    # Generate report
    Write-Host ""
    Write-Host "Generating audit report..." -ForegroundColor Cyan
    
    # Create output directory if it doesn't exist
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath | Out-Null
    }
    
    # Generate filename
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $filename = "AzureSecurityAudit_${SubscriptionId}_${timestamp}.${OutputFormat.ToLower()}"
    $outputFile = Join-Path $OutputPath $filename
    
    # Use the reporting module to generate the report
    New-AuditReport -AuditResults $auditResults -Format $OutputFormat -OutputPath $outputFile
    
    Write-Host "✓ Report generated: $outputFile" -ForegroundColor Green
    Write-Host ""
    Write-Host "Audit Summary:" -ForegroundColor Cyan
    Write-Host "  Total Controls Assessed: $($auditResults.Summary.TotalControls)" -ForegroundColor White
    Write-Host "  Passed Controls: $($auditResults.Summary.PassedControls)" -ForegroundColor Green
    Write-Host "  Failed Controls: $($auditResults.Summary.FailedControls)" -ForegroundColor Red
    Write-Host ""
    
    return $auditResults
}

# Main execution
try {
    Test-CloudShellEnvironment
    $results = Start-AzureSecurityAudit -SubscriptionId $SubscriptionId -Controls $Controls -OutputFormat $OutputFormat -AssessmentType $AssessmentType
}
catch {
    Write-Error "Audit failed: $_"
    exit 1
}