# Reporting Module
# Generates comprehensive audit reports with CIA impact analysis and remediation guidance

function New-AuditReport {
    <#
    .SYNOPSIS
        Generates audit reports in multiple formats
    .DESCRIPTION
        Creates comprehensive security audit reports with findings, CIA impacts, and remediation guidance
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$AuditResults,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("JSON", "HTML", "CSV", "Markdown")]
        [string]$Format,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    switch ($Format) {
        "JSON" { Export-JsonReport -AuditResults $AuditResults -OutputPath $OutputPath }
        "HTML" { Export-HtmlReport -AuditResults $AuditResults -OutputPath $OutputPath }
        "CSV" { Export-CsvReport -AuditResults $AuditResults -OutputPath $OutputPath }
        "Markdown" { Export-MarkdownReport -AuditResults $AuditResults -OutputPath $OutputPath }
    }
}

function Export-JsonReport {
    param(
        [hashtable]$AuditResults,
        [string]$OutputPath
    )
    
    # Add report metadata
    $AuditResults.ReportMetadata = @{
        GeneratedBy = "Azure Cloud Shell Security Audit Tool"
        Version = "1.0"
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC" -AsUTC
        ComplianceFrameworks = @("FedRAMP High", "NIST 800-53 Rev 5")
    }
    
    # Convert to JSON with proper formatting
    $jsonOutput = $AuditResults | ConvertTo-Json -Depth 10
    $jsonOutput | Out-File $OutputPath -Encoding UTF8
    
    Write-Host "JSON report generated: $OutputPath" -ForegroundColor Green
}

function Export-HtmlReport {
    param(
        [hashtable]$AuditResults,
        [string]$OutputPath
    )
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Azure Security Audit Report - $($AuditResults.Metadata.SubscriptionId)</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background-color: #0078d4;
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        .summary-card h3 {
            margin: 0 0 10px 0;
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
        }
        .summary-card .value {
            font-size: 2.5em;
            font-weight: bold;
            margin: 0;
        }
        .pass { color: #107c10; }
        .fail { color: #d13438; }
        .warning { color: #ff8c00; }
        .info { color: #0078d4; }
        
        .cia-impact {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .cia-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-top: 15px;
        }
        .cia-item {
            text-align: center;
            padding: 15px;
            border-radius: 4px;
            background: #f8f9fa;
        }
        .cia-item.high { background-color: #fde7e9; color: #a80000; }
        .cia-item.medium { background-color: #fff4ce; color: #835c00; }
        .cia-item.low { background-color: #e7f3ff; color: #004578; }
        
        .control-section {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .control-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 2px solid #f0f0f0;
        }
        .control-title {
            margin: 0;
            font-size: 1.2em;
        }
        .status-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
        }
        .status-badge.pass { background-color: #e7f3e7; color: #107c10; }
        .status-badge.fail { background-color: #fde7e9; color: #d13438; }
        .status-badge.manual { background-color: #fff4ce; color: #835c00; }
        .status-badge.error { background-color: #f0f0f0; color: #666; }
        
        .findings, .remediation {
            margin-top: 15px;
        }
        .findings h4, .remediation h4 {
            margin: 0 0 10px 0;
            color: #666;
            font-size: 0.95em;
        }
        .findings ul, .remediation ul {
            margin: 0;
            padding-left: 20px;
        }
        .findings li, .remediation li {
            margin-bottom: 5px;
        }
        .remediation {
            background-color: #e7f3ff;
            padding: 15px;
            border-radius: 4px;
            border-left: 4px solid #0078d4;
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            color: #666;
            font-size: 0.9em;
        }
        
        @media print {
            body { background-color: white; }
            .control-section { box-shadow: none; border: 1px solid #ddd; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Azure Security Audit Report</h1>
        <p>Subscription: $($AuditResults.Metadata.SubscriptionId) | Generated: $($AuditResults.Metadata.AuditDate)</p>
        <p>Assessment Type: $($AuditResults.Metadata.AssessmentType) | Compliance: FedRAMP High & NIST 800-53</p>
    </div>
    
    <div class="summary-grid">
        <div class="summary-card">
            <h3>Total Controls</h3>
            <p class="value info">$($AuditResults.Summary.TotalControls)</p>
        </div>
        <div class="summary-card">
            <h3>Passed</h3>
            <p class="value pass">$($AuditResults.Summary.PassedControls)</p>
        </div>
        <div class="summary-card">
            <h3>Failed</h3>
            <p class="value fail">$($AuditResults.Summary.FailedControls)</p>
        </div>
        <div class="summary-card">
            <h3>Critical Findings</h3>
            <p class="value warning">$($AuditResults.Summary.CriticalFindings)</p>
        </div>
    </div>
    
    <div class="cia-impact">
        <h2>CIA Triad Impact Summary</h2>
        <div class="cia-grid">
            <div class="cia-item">
                <h3>Confidentiality</h3>
                <p>High: $($AuditResults.CIAImpact.Confidentiality.High)</p>
                <p>Medium: $($AuditResults.CIAImpact.Confidentiality.Medium)</p>
                <p>Low: $($AuditResults.CIAImpact.Confidentiality.Low)</p>
            </div>
            <div class="cia-item">
                <h3>Integrity</h3>
                <p>High: $($AuditResults.CIAImpact.Integrity.High)</p>
                <p>Medium: $($AuditResults.CIAImpact.Integrity.Medium)</p>
                <p>Low: $($AuditResults.CIAImpact.Integrity.Low)</p>
            </div>
            <div class="cia-item">
                <h3>Availability</h3>
                <p>High: $($AuditResults.CIAImpact.Availability.High)</p>
                <p>Medium: $($AuditResults.CIAImpact.Availability.Medium)</p>
                <p>Low: $($AuditResults.CIAImpact.Availability.Low)</p>
            </div>
        </div>
    </div>
"@
    
    # Add control results
    foreach ($control in $AuditResults.ControlResults) {
        $statusClass = switch ($control.Status) {
            "Pass" { "pass" }
            "Fail" { "fail" }
            "Manual" { "manual" }
            default { "error" }
        }
        
        $html += @"
    <div class="control-section">
        <div class="control-header">
            <h3 class="control-title">$($control.ControlId): $($control.ControlName)</h3>
            <span class="status-badge $statusClass">$($control.Status)</span>
        </div>
        
        <p><strong>NIST Family:</strong> $($control.NISTFamily) | <strong>FedRAMP Level:</strong> $($control.FedRAMPLevel)</p>
        
        <p><strong>CIA Impact:</strong> 
            Confidentiality: <span class="$($control.CIAImpact.Confidentiality.ToLower())">$($control.CIAImpact.Confidentiality)</span> | 
            Integrity: <span class="$($control.CIAImpact.Integrity.ToLower())">$($control.CIAImpact.Integrity)</span> | 
            Availability: <span class="$($control.CIAImpact.Availability.ToLower())">$($control.CIAImpact.Availability)</span>
        </p>
        
        <div class="findings">
            <h4>Findings</h4>
            <ul>
"@
        foreach ($finding in $control.Findings) {
            $html += "                <li>$finding</li>`n"
        }
        $html += "            </ul>`n        </div>`n"
        
        if ($control.Remediation.Count -gt 0) {
            $html += @"
        <div class="remediation">
            <h4>Remediation Recommendations</h4>
            <ul>
"@
            foreach ($remediation in $control.Remediation) {
                $html += "                <li>$remediation</li>`n"
            }
            $html += "            </ul>`n        </div>`n"
        }
        
        $html += "    </div>`n"
    }
    
    $html += @"
    <div class="footer">
        <p>Generated by Azure Cloud Shell Security Audit Tool v1.0</p>
        <p>This report provides security recommendations based on FedRAMP High and NIST 800-53 standards.</p>
        <p>For questions or support, please contact your security team.</p>
    </div>
</body>
</html>
"@
    
    $html | Out-File $OutputPath -Encoding UTF8
    Write-Host "HTML report generated: $OutputPath" -ForegroundColor Green
}

function Export-CsvReport {
    param(
        [hashtable]$AuditResults,
        [string]$OutputPath
    )
    
    $csvData = @()
    
    foreach ($control in $AuditResults.ControlResults) {
        $csvData += [PSCustomObject]@{
            ControlId = $control.ControlId
            ControlName = $control.ControlName
            NISTFamily = $control.NISTFamily
            FedRAMPLevel = $control.FedRAMPLevel
            Status = $control.Status
            CIAConfidentiality = $control.CIAImpact.Confidentiality
            CIAIntegrity = $control.CIAImpact.Integrity
            CIAAvailability = $control.CIAImpact.Availability
            FindingsCount = $control.Findings.Count
            Findings = $control.Findings -join "; "
            RemediationCount = $control.Remediation.Count
            Remediation = $control.Remediation -join "; "
            AuditDate = $AuditResults.Metadata.AuditDate
            SubscriptionId = $AuditResults.Metadata.SubscriptionId
        }
    }
    
    $csvData | Export-Csv -Path $OutputPath -NoTypeInformation
    Write-Host "CSV report generated: $OutputPath" -ForegroundColor Green
}

function Export-MarkdownReport {
    param(
        [hashtable]$AuditResults,
        [string]$OutputPath
    )
    
    $markdown = @"
# Azure Security Audit Report

**Subscription:** $($AuditResults.Metadata.SubscriptionId)  
**Audit Date:** $($AuditResults.Metadata.AuditDate)  
**Assessment Type:** $($AuditResults.Metadata.AssessmentType)  
**Compliance Frameworks:** FedRAMP High, NIST 800-53 Rev 5

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Controls Assessed | $($AuditResults.Summary.TotalControls) |
| Passed Controls | $($AuditResults.Summary.PassedControls) |
| Failed Controls | $($AuditResults.Summary.FailedControls) |
| Critical Findings | $($AuditResults.Summary.CriticalFindings) |

## CIA Triad Impact Analysis

### Confidentiality
- **High Impact:** $($AuditResults.CIAImpact.Confidentiality.High) findings
- **Medium Impact:** $($AuditResults.CIAImpact.Confidentiality.Medium) findings
- **Low Impact:** $($AuditResults.CIAImpact.Confidentiality.Low) findings

### Integrity
- **High Impact:** $($AuditResults.CIAImpact.Integrity.High) findings
- **Medium Impact:** $($AuditResults.CIAImpact.Integrity.Medium) findings
- **Low Impact:** $($AuditResults.CIAImpact.Integrity.Low) findings

### Availability
- **High Impact:** $($AuditResults.CIAImpact.Availability.High) findings
- **Medium Impact:** $($AuditResults.CIAImpact.Availability.Medium) findings
- **Low Impact:** $($AuditResults.CIAImpact.Availability.Low) findings

## Detailed Control Assessments

"@
    
    foreach ($control in $AuditResults.ControlResults) {
        $statusEmoji = switch ($control.Status) {
            "Pass" { "✅" }
            "Fail" { "❌" }
            "Manual" { "⚠️" }
            default { "❓" }
        }
        
        $markdown += @"

### $statusEmoji $($control.ControlId): $($control.ControlName)

**Status:** $($control.Status)  
**NIST Family:** $($control.NISTFamily)  
**FedRAMP Level:** $($control.FedRAMPLevel)  
**CIA Impact:** C:$($control.CIAImpact.Confidentiality) | I:$($control.CIAImpact.Integrity) | A:$($control.CIAImpact.Availability)

#### Findings
"@
        foreach ($finding in $control.Findings) {
            $markdown += "`n- $finding"
        }
        
        if ($control.Remediation.Count -gt 0) {
            $markdown += "`n`n#### Remediation Recommendations"
            foreach ($remediation in $control.Remediation) {
                $markdown += "`n- $remediation"
            }
        }
        
        $markdown += "`n"
    }
    
    $markdown += @"

---

*Generated by Azure Cloud Shell Security Audit Tool v1.0*
"@
    
    $markdown | Out-File $OutputPath -Encoding UTF8
    Write-Host "Markdown report generated: $OutputPath" -ForegroundColor Green
}

function Get-RemediationPriority {
    <#
    .SYNOPSIS
        Calculates remediation priority based on CIA impact and control status
    #>
    
    param(
        [hashtable]$Control
    )
    
    $priority = 0
    
    # Status weight
    switch ($Control.Status) {
        "Fail" { $priority += 30 }
        "Manual" { $priority += 10 }
        "Error" { $priority += 20 }
    }
    
    # CIA impact weight
    $ciaValues = @{
        "High" = 10
        "Medium" = 5
        "Low" = 1
    }
    
    $priority += $ciaValues[$Control.CIAImpact.Confidentiality]
    $priority += $ciaValues[$Control.CIAImpact.Integrity]
    $priority += $ciaValues[$Control.CIAImpact.Availability]
    
    return $priority
}

function Get-ComplianceScore {
    <#
    .SYNOPSIS
        Calculates overall compliance score
    #>
    
    param(
        [hashtable]$AuditResults
    )
    
    if ($AuditResults.Summary.TotalControls -eq 0) {
        return 0
    }
    
    $score = [math]::Round(
        ($AuditResults.Summary.PassedControls / $AuditResults.Summary.TotalControls) * 100, 
        2
    )
    
    return $score
}