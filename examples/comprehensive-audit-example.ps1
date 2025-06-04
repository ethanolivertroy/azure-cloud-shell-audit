#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Comprehensive Azure Security Audit Example
.DESCRIPTION
    This example demonstrates all features of the Azure Cloud Shell Security Audit Tool
    including FedRAMP/NIST compliance checking, CIA impact analysis, and continuous monitoring
.NOTES
    Run this script in Azure Cloud Shell for best results
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory=$false)]
    [string]$NotificationEmail = "security@yourcompany.com"
)

Write-Host "Azure Security Audit - Comprehensive Example" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Example 1: Quick Security Assessment
Write-Host "Example 1: Quick Security Assessment (High-Risk Controls)" -ForegroundColor Yellow
Write-Host ""

./audit.ps1 -SubscriptionId $SubscriptionId `
           -Controls "AC-*,SC-*,SI-*" `
           -AssessmentType QuickScan `
           -OutputFormat HTML

Write-Host ""
Write-Host "Quick assessment completed. Check ./reports/ for HTML report." -ForegroundColor Green
Write-Host ""

# Example 2: Comprehensive FedRAMP Audit
Write-Host "Example 2: Comprehensive FedRAMP High Baseline Audit" -ForegroundColor Yellow
Write-Host ""

./audit.ps1 -SubscriptionId $SubscriptionId `
           -Controls "*" `
           -AssessmentType Full `
           -OutputFormat JSON `
           -EnablePolicyCompliance

Write-Host ""
Write-Host "Comprehensive audit completed with policy compliance check." -ForegroundColor Green
Write-Host ""

# Example 3: CIA Triad Focused Assessment
Write-Host "Example 3: CIA Triad Impact Assessment" -ForegroundColor Yellow
Write-Host ""

./audit.ps1 -SubscriptionId $SubscriptionId `
           -Controls "AC-*,AU-*,SC-*" `
           -AssessmentType CIA `
           -OutputFormat Markdown

Write-Host ""
Write-Host "CIA impact assessment completed. Review findings by impact level." -ForegroundColor Green
Write-Host ""

# Example 4: Enable Continuous Compliance (if email provided)
if ($NotificationEmail -ne "security@yourcompany.com") {
    Write-Host "Example 4: Enable Continuous Compliance Monitoring" -ForegroundColor Yellow
    Write-Host ""
    
    ./audit.ps1 -SubscriptionId $SubscriptionId `
               -Controls "AC-*,SC-*" `
               -EnableContinuousCompliance `
               -NotificationEmail $NotificationEmail `
               -OutputFormat HTML
    
    Write-Host ""
    Write-Host "Continuous compliance monitoring enabled!" -ForegroundColor Green
    Write-Host "You will receive notifications at: $NotificationEmail" -ForegroundColor Green
}
else {
    Write-Host "Example 4: Skipped (Update NotificationEmail parameter to enable)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "All examples completed! Check the following:" -ForegroundColor Cyan
Write-Host "- HTML reports in ./reports/ directory" -ForegroundColor White
Write-Host "- JSON output for automation integration" -ForegroundColor White
Write-Host "- Markdown reports for documentation" -ForegroundColor White
Write-Host "- Azure Policy assignments (if continuous compliance enabled)" -ForegroundColor White
Write-Host ""

# Display control coverage summary
Write-Host "Control Coverage Summary:" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
Write-Host "✓ Access Control (AC) - 6 controls" -ForegroundColor Green
Write-Host "✓ Audit and Accountability (AU) - 4 controls" -ForegroundColor Green  
Write-Host "✓ System and Communications Protection (SC) - 8 controls" -ForegroundColor Green
Write-Host "✓ System and Information Integrity (SI) - 5 controls" -ForegroundColor Green
Write-Host "✓ Incident Response (IR) - 4 controls" -ForegroundColor Green
Write-Host "✓ Configuration Management (CM) - 4 controls" -ForegroundColor Green
Write-Host "✓ Risk Assessment (RA) - 3 controls" -ForegroundColor Green
Write-Host "✓ Identification and Authentication (IA) - 1 control" -ForegroundColor Green
Write-Host "✓ Media Protection (MP) - 1 control" -ForegroundColor Green
Write-Host ""
Write-Host "Total: 36 security controls covering FedRAMP High baseline" -ForegroundColor Green
Write-Host ""

Write-Host "Advanced Features Demonstrated:" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host "• Progress indicators for long-running operations" -ForegroundColor White
Write-Host "• CIA triad impact assessment for each finding" -ForegroundColor White
Write-Host "• Multiple output formats (HTML, JSON, CSV, Markdown)" -ForegroundColor White
Write-Host "• Azure Policy integration and continuous compliance" -ForegroundColor White
Write-Host "• Automated remediation recommendations" -ForegroundColor White
Write-Host "• Cloud Shell optimized execution" -ForegroundColor White
Write-Host ""

Write-Host "For production use:" -ForegroundColor Yellow
Write-Host "==================" -ForegroundColor Yellow
Write-Host "1. Customize notification emails for your security team" -ForegroundColor White
Write-Host "2. Schedule regular audits using Azure Automation" -ForegroundColor White
Write-Host "3. Integrate JSON output with your SIEM/GRC tools" -ForegroundColor White
Write-Host "4. Use policy compliance for continuous monitoring" -ForegroundColor White
Write-Host ""