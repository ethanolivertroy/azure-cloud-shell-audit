# Logging and Monitoring Control Checks
# Implements FedRAMP and NIST 800-53 audit and monitoring controls

function Test-LoggingControls {
    <#
    .SYNOPSIS
        Performs comprehensive logging and monitoring checks
    .DESCRIPTION
        Evaluates Azure logging and monitoring configuration against FedRAMP and NIST 800-53 controls
    #>
    
    param(
        [string]$SubscriptionId
    )
    
    $loggingResults = @()
    
    Show-ControlProgress -ControlId "AU" -ControlName "Audit and Accountability" -Current 0 -Total 5
    
    # AU-2: Audit Events
    $loggingResults += Test-AuditEvents -SubscriptionId $SubscriptionId
    Show-ControlProgress -ControlId "AU" -ControlName "Audit and Accountability" -Current 1 -Total 5
    
    # AU-3: Content of Audit Records
    $loggingResults += Test-AuditContent -SubscriptionId $SubscriptionId
    Show-ControlProgress -ControlId "AU" -ControlName "Audit and Accountability" -Current 2 -Total 5
    
    # AU-6: Audit Review, Analysis, and Reporting
    $loggingResults += Test-AuditReview -SubscriptionId $SubscriptionId
    Show-ControlProgress -ControlId "AU" -ControlName "Audit and Accountability" -Current 3 -Total 5
    
    # AU-9: Protection of Audit Information
    $loggingResults += Test-AuditProtection -SubscriptionId $SubscriptionId
    Show-ControlProgress -ControlId "AU" -ControlName "Audit and Accountability" -Current 4 -Total 5
    
    # SI-4: Information System Monitoring
    $loggingResults += Test-SystemMonitoring -SubscriptionId $SubscriptionId
    Show-ControlProgress -ControlId "AU" -ControlName "Audit and Accountability" -Current 5 -Total 5
    
    Complete-ControlProgress
    
    return $loggingResults
}

function Test-AuditEvents {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "AU-2"
        ControlName = "Audit Events"
        FedRAMPLevel = "High"
        NISTFamily = "Audit and Accountability"
        Status = "Unknown"
        CIAImpact = @{
            Confidentiality = "Medium"
            Integrity = "High"
            Availability = "Low"
        }
        Findings = @()
        Evidence = @()
        Remediation = @()
    }
    
    try {
        # Check Activity Log retention
        $activityLogProfile = Get-AzLogProfile -ErrorAction SilentlyContinue
        $hasValidRetention = $false
        
        if ($activityLogProfile) {
            $retentionDays = $activityLogProfile.RetentionPolicy.Days
            if ($activityLogProfile.RetentionPolicy.Enabled -and $retentionDays -ge 90) {
                $hasValidRetention = $true
                $result.Findings += "Activity log retention is set to $retentionDays days (meets 90-day requirement)"
            }
            else {
                $result.Findings += "Activity log retention is insufficient or disabled"
                $result.Remediation += "Configure activity log retention to at least 90 days"
            }
        }
        else {
            $result.Findings += "No activity log profile configured"
            $result.Remediation += "Create an activity log profile with appropriate retention"
        }
        
        # Check Diagnostic Settings on Key Resources
        $keyResourceTypes = @(
            "Microsoft.KeyVault/vaults",
            "Microsoft.Storage/storageAccounts",
            "Microsoft.Sql/servers",
            "Microsoft.Network/networkSecurityGroups"
        )
        
        $totalResources = 0
        $configuredResources = 0
        
        foreach ($resourceType in $keyResourceTypes) {
            $resources = Get-AzResource -ResourceType $resourceType -ErrorAction SilentlyContinue
            
            foreach ($resource in $resources) {
                $totalResources++
                
                # Check for diagnostic settings
                $diagnosticSettings = Get-AzDiagnosticSetting -ResourceId $resource.ResourceId -ErrorAction SilentlyContinue
                
                if ($diagnosticSettings -and $diagnosticSettings.Count -gt 0) {
                    $configuredResources++
                    
                    # Check if logs are enabled
                    $hasLogs = $false
                    foreach ($setting in $diagnosticSettings) {
                        if ($setting.Logs | Where-Object { $_.Enabled }) {
                            $hasLogs = $true
                            break
                        }
                    }
                    
                    if (-not $hasLogs) {
                        $result.Evidence += "$($resource.Name) has diagnostic settings but no logs enabled"
                    }
                }
                else {
                    $result.Evidence += "$($resource.Name) ($($resource.ResourceType)) has no diagnostic settings"
                }
            }
        }
        
        if ($totalResources -gt 0) {
            $diagnosticCoverage = [math]::Round(($configuredResources / $totalResources) * 100, 2)
            $result.Findings += "$diagnosticCoverage% of critical resources have diagnostic settings configured"
            
            if ($diagnosticCoverage -lt 100) {
                $result.Status = "Fail"
                $result.Remediation += "Enable diagnostic settings on all critical resources"
                $result.Remediation += "Configure logs to be sent to Log Analytics workspace or Storage Account"
            }
        }
        
        # Check for Log Analytics Workspace
        $workspaces = Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue
        if ($workspaces.Count -gt 0) {
            $result.Findings += "Found $($workspaces.Count) Log Analytics workspace(s)"
            
            foreach ($workspace in $workspaces) {
                $retentionDays = $workspace.RetentionInDays
                if ($retentionDays -lt 90) {
                    $result.Findings += "Workspace '$($workspace.Name)' has retention of $retentionDays days (below 90-day requirement)"
                    $result.Remediation += "Increase Log Analytics retention to at least 90 days"
                }
            }
        }
        else {
            $result.Findings += "No Log Analytics workspace found"
            $result.Remediation += "Deploy Log Analytics workspace for centralized logging"
            $result.Status = "Fail"
        }
        
        if ($result.Status -ne "Fail" -and $hasValidRetention) {
            $result.Status = "Pass"
        }
        elseif ($result.Status -eq "Unknown") {
            $result.Status = "Fail"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess audit events: $_"
    }
    
    return $result
}

function Test-AuditContent {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "AU-3"
        ControlName = "Content of Audit Records"
        FedRAMPLevel = "High"
        NISTFamily = "Audit and Accountability"
        Status = "Unknown"
        CIAImpact = @{
            Confidentiality = "Low"
            Integrity = "High"
            Availability = "Low"
        }
        Findings = @()
        Evidence = @()
        Remediation = @()
    }
    
    try {
        # Check if detailed audit logs are being collected
        $detailedLoggingEnabled = $true
        
        # Check Activity Log categories
        $activityLogInsights = Get-AzActivityLogAlert -ErrorAction SilentlyContinue
        if ($activityLogInsights.Count -gt 0) {
            $result.Findings += "Found $($activityLogInsights.Count) Activity Log alert(s) configured"
        }
        else {
            $result.Findings += "No Activity Log alerts configured"
            $result.Remediation += "Configure alerts for critical activities"
        }
        
        # Check for Azure Monitor Action Groups
        $actionGroups = Get-AzActionGroup -ErrorAction SilentlyContinue
        if ($actionGroups.Count -gt 0) {
            $result.Findings += "Found $($actionGroups.Count) Action Group(s) for alert notifications"
        }
        else {
            $detailedLoggingEnabled = $false
            $result.Findings += "No Action Groups configured for alert notifications"
            $result.Remediation += "Create Action Groups for security alert notifications"
        }
        
        # Check diagnostic setting details for completeness
        $sampleResources = Get-AzResource | Select-Object -First 5
        $completeSettings = 0
        
        foreach ($resource in $sampleResources) {
            $diagnosticSettings = Get-AzDiagnosticSetting -ResourceId $resource.ResourceId -ErrorAction SilentlyContinue
            
            if ($diagnosticSettings) {
                foreach ($setting in $diagnosticSettings) {
                    # Check if both logs and metrics are enabled
                    $hasLogs = $setting.Logs | Where-Object { $_.Enabled }
                    $hasMetrics = $setting.Metrics | Where-Object { $_.Enabled }
                    
                    if ($hasLogs -and $hasMetrics) {
                        $completeSettings++
                    }
                }
            }
        }
        
        if ($sampleResources.Count -gt 0) {
            $completenessRate = [math]::Round(($completeSettings / $sampleResources.Count) * 100, 2)
            $result.Findings += "Sample check: $completenessRate% of resources have complete diagnostic settings (logs + metrics)"
            
            if ($completenessRate -lt 80) {
                $detailedLoggingEnabled = $false
                $result.Remediation += "Enable both logs and metrics in diagnostic settings"
            }
        }
        
        # Check for required log fields
        $result.Findings += "Azure Activity Logs include: timestamp, user identity, source IP, resource, operation, and result"
        
        if ($detailedLoggingEnabled) {
            $result.Status = "Pass"
        }
        else {
            $result.Status = "Fail"
            $result.Remediation += "Ensure all audit logs capture required fields per NIST guidelines"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess audit content: $_"
    }
    
    return $result
}

function Test-AuditReview {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "AU-6"
        ControlName = "Audit Review, Analysis, and Reporting"
        FedRAMPLevel = "High"
        NISTFamily = "Audit and Accountability"
        Status = "Unknown"
        CIAImpact = @{
            Confidentiality = "Medium"
            Integrity = "High"
            Availability = "Low"
        }
        Findings = @()
        Evidence = @()
        Remediation = @()
    }
    
    try {
        $reviewCapabilities = 0
        $totalCapabilities = 4
        
        # Check for Azure Sentinel (now Microsoft Sentinel)
        $sentinelWorkspaces = Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue | 
            Where-Object { 
                $solutions = Get-AzOperationalInsightsIntelligencePack -ResourceGroupName $_.ResourceGroupName `
                    -WorkspaceName $_.Name -ErrorAction SilentlyContinue
                $solutions.Name -contains "SecurityInsights"
            }
        
        if ($sentinelWorkspaces) {
            $reviewCapabilities++
            $result.Findings += "Microsoft Sentinel is deployed for advanced security analytics"
            
            # Check for analytics rules
            foreach ($workspace in $sentinelWorkspaces) {
                # Note: Would need Sentinel API to check rules, simplified check here
                $result.Findings += "Sentinel workspace '$($workspace.Name)' configured for security monitoring"
            }
        }
        else {
            $result.Findings += "Microsoft Sentinel not deployed"
            $result.Remediation += "Deploy Microsoft Sentinel for advanced threat detection and response"
        }
        
        # Check for Security Center (now Defender for Cloud)
        $securityContacts = Get-AzSecurityContact -ErrorAction SilentlyContinue
        $pricingTiers = Get-AzSecurityPricing -ErrorAction SilentlyContinue
        
        if ($securityContacts) {
            $reviewCapabilities++
            $result.Findings += "Security contacts configured in Microsoft Defender for Cloud"
        }
        else {
            $result.Findings += "No security contacts configured"
            $result.Remediation += "Configure security contact information in Defender for Cloud"
        }
        
        if ($pricingTiers | Where-Object { $_.PricingTier -eq "Standard" }) {
            $reviewCapabilities++
            $result.Findings += "Microsoft Defender for Cloud Standard tier enabled"
        }
        else {
            $result.Findings += "Microsoft Defender for Cloud using Free tier only"
            $result.Remediation += "Enable Defender for Cloud Standard tier for advanced security features"
        }
        
        # Check for Log Analytics queries/alerts
        $workspaces = Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue
        $hasAlerts = $false
        
        foreach ($workspace in $workspaces) {
            $savedSearches = Get-AzOperationalInsightsSavedSearch -ResourceGroupName $workspace.ResourceGroupName `
                -WorkspaceName $workspace.Name -ErrorAction SilentlyContinue
            
            if ($savedSearches.Count -gt 0) {
                $hasAlerts = $true
                $result.Findings += "Workspace '$($workspace.Name)' has $($savedSearches.Count) saved searches/queries"
            }
        }
        
        if ($hasAlerts) {
            $reviewCapabilities++
        }
        else {
            $result.Remediation += "Create saved searches and alerts in Log Analytics for security events"
        }
        
        # Calculate compliance
        $complianceRate = [math]::Round(($reviewCapabilities / $totalCapabilities) * 100, 2)
        $result.Findings += "Audit review capabilities: $complianceRate% implemented"
        
        if ($reviewCapabilities -ge 3) {
            $result.Status = "Pass"
        }
        else {
            $result.Status = "Fail"
            $result.Remediation += "Implement automated log review and alerting capabilities"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess audit review capabilities: $_"
    }
    
    return $result
}

function Test-AuditProtection {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "AU-9"
        ControlName = "Protection of Audit Information"
        FedRAMPLevel = "High"
        NISTFamily = "Audit and Accountability"
        Status = "Unknown"
        CIAImpact = @{
            Confidentiality = "High"
            Integrity = "High"
            Availability = "Medium"
        }
        Findings = @()
        Evidence = @()
        Remediation = @()
    }
    
    try {
        $protectionIssues = 0
        
        # Check storage account immutability for log storage
        $diagnosticStorageAccounts = @()
        
        # Get diagnostic settings to find storage accounts used for logs
        $resources = Get-AzResource | Select-Object -First 10
        foreach ($resource in $resources) {
            $diagSettings = Get-AzDiagnosticSetting -ResourceId $resource.ResourceId -ErrorAction SilentlyContinue
            foreach ($setting in $diagSettings) {
                if ($setting.StorageAccountId) {
                    $diagnosticStorageAccounts += $setting.StorageAccountId
                }
            }
        }
        
        $diagnosticStorageAccounts = $diagnosticStorageAccounts | Select-Object -Unique
        
        foreach ($storageId in $diagnosticStorageAccounts) {
            $storage = Get-AzResource -ResourceId $storageId -ErrorAction SilentlyContinue
            if ($storage) {
                $storageAccount = Get-AzStorageAccount -ResourceGroupName $storage.ResourceGroupName `
                    -Name $storage.Name -ErrorAction SilentlyContinue
                
                # Check for immutability policies
                $context = $storageAccount.Context
                $containers = Get-AzStorageContainer -Context $context -ErrorAction SilentlyContinue
                
                $hasImmutability = $false
                foreach ($container in $containers | Where-Object { $_.Name -like "*logs*" -or $_.Name -like "*insights*" }) {
                    $legalHold = Get-AzRmStorageContainerLegalHold -ResourceGroupName $storage.ResourceGroupName `
                        -StorageAccountName $storage.Name -ContainerName $container.Name -ErrorAction SilentlyContinue
                    
                    if ($legalHold.HasLegalHold) {
                        $hasImmutability = $true
                        break
                    }
                }
                
                if (-not $hasImmutability) {
                    $protectionIssues++
                    $result.Evidence += "Storage account '$($storage.Name)' used for logs lacks immutability policies"
                }
            }
        }
        
        # Check RBAC on Log Analytics workspaces
        $workspaces = Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue
        foreach ($workspace in $workspaces) {
            $roleAssignments = Get-AzRoleAssignment -Scope $workspace.ResourceId -ErrorAction SilentlyContinue
            
            $writePermissions = $roleAssignments | Where-Object { 
                $_.RoleDefinitionName -in @("Owner", "Contributor", "Log Analytics Contributor")
            }
            
            if ($writePermissions.Count -gt 3) {
                $protectionIssues++
                $result.Evidence += "Workspace '$($workspace.Name)' has $($writePermissions.Count) users with write permissions"
                $result.Remediation += "Limit write access to Log Analytics workspace '$($workspace.Name)'"
            }
        }
        
        # Check for resource locks on logging resources
        $lockCount = 0
        foreach ($workspace in $workspaces) {
            $locks = Get-AzResourceLock -ResourceGroupName $workspace.ResourceGroupName `
                -ResourceName $workspace.Name -ResourceType $workspace.ResourceType -ErrorAction SilentlyContinue
            
            if ($locks | Where-Object { $_.Properties.Level -eq "CanNotDelete" }) {
                $lockCount++
            }
        }
        
        if ($workspaces.Count -gt 0) {
            $lockPercentage = [math]::Round(($lockCount / $workspaces.Count) * 100, 2)
            $result.Findings += "$lockPercentage% of Log Analytics workspaces have delete locks"
            
            if ($lockPercentage -lt 100) {
                $protectionIssues++
                $result.Remediation += "Apply CanNotDelete locks to all logging resources"
            }
        }
        
        if ($protectionIssues -eq 0) {
            $result.Status = "Pass"
            $result.Findings += "Audit information protection controls are properly configured"
        }
        else {
            $result.Status = "Fail"
            $result.Remediation += "Implement immutability policies for log storage"
            $result.Remediation += "Use RBAC to restrict access to audit logs"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess audit protection: $_"
    }
    
    return $result
}

function Test-SystemMonitoring {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "SI-4"
        ControlName = "Information System Monitoring"
        FedRAMPLevel = "High"
        NISTFamily = "System and Information Integrity"
        Status = "Unknown"
        CIAImpact = @{
            Confidentiality = "Medium"
            Integrity = "High"
            Availability = "Medium"
        }
        Findings = @()
        Evidence = @()
        Remediation = @()
    }
    
    try {
        $monitoringScore = 0
        $totalChecks = 5
        
        # Check Azure Monitor Alerts
        $alertRules = Get-AzMetricAlertRuleV2 -ErrorAction SilentlyContinue
        $activityAlerts = Get-AzActivityLogAlert -ErrorAction SilentlyContinue
        
        $totalAlerts = ($alertRules.Count + $activityAlerts.Count)
        if ($totalAlerts -gt 0) {
            $monitoringScore++
            $result.Findings += "Found $totalAlerts monitoring alerts configured"
            
            # Check for critical alerts
            $criticalAlerts = @(
                "Failed login attempts",
                "Privilege escalation",
                "Resource deletion",
                "Security policy changes"
            )
            
            $hasCriticalAlerts = $false
            foreach ($alert in $activityAlerts) {
                foreach ($critical in $criticalAlerts) {
                    if ($alert.Name -like "*$critical*" -or $alert.Description -like "*$critical*") {
                        $hasCriticalAlerts = $true
                        break
                    }
                }
            }
            
            if (-not $hasCriticalAlerts) {
                $result.Remediation += "Configure alerts for critical security events"
            }
        }
        else {
            $result.Findings += "No monitoring alerts configured"
            $result.Remediation += "Configure Azure Monitor alerts for security events"
        }
        
        # Check Network Watcher
        $networkWatchers = Get-AzNetworkWatcher -ErrorAction SilentlyContinue
        if ($networkWatchers.Count -gt 0) {
            $monitoringScore++
            $result.Findings += "Network Watcher deployed in $($networkWatchers.Count) region(s)"
            
            # Check for NSG flow logs
            $nsgs = Get-AzNetworkSecurityGroup
            $flowLogCount = 0
            
            foreach ($nsg in $nsgs | Select-Object -First 5) {
                $flowLogStatus = Get-AzNetworkWatcherFlowLogStatus -NetworkWatcherName $networkWatchers[0].Name `
                    -ResourceGroupName $networkWatchers[0].ResourceGroupName `
                    -TargetResourceId $nsg.Id -ErrorAction SilentlyContinue
                
                if ($flowLogStatus.Enabled) {
                    $flowLogCount++
                }
            }
            
            if ($flowLogCount -eq 0) {
                $result.Remediation += "Enable NSG flow logs for network monitoring"
            }
        }
        else {
            $result.Findings += "Network Watcher not deployed"
            $result.Remediation += "Deploy Network Watcher for network monitoring capabilities"
        }
        
        # Check Application Insights
        $appInsights = Get-AzApplicationInsights -ErrorAction SilentlyContinue
        if ($appInsights.Count -gt 0) {
            $monitoringScore++
            $result.Findings += "Application Insights deployed for $($appInsights.Count) application(s)"
        }
        
        # Check VM Insights
        $vms = Get-AzVM | Select-Object -First 5
        $vmInsightsCount = 0
        
        foreach ($vm in $vms) {
            $extensions = Get-AzVMExtension -ResourceGroupName $vm.ResourceGroupName `
                -VMName $vm.Name -ErrorAction SilentlyContinue
            
            if ($extensions | Where-Object { $_.ExtensionType -in @("MicrosoftMonitoringAgent", "OmsAgentForLinux") }) {
                $vmInsightsCount++
            }
        }
        
        if ($vms.Count -gt 0) {
            $vmInsightsPercentage = [math]::Round(($vmInsightsCount / $vms.Count) * 100, 2)
            $result.Findings += "VM Insights: $vmInsightsPercentage% of sampled VMs have monitoring agents"
            
            if ($vmInsightsPercentage -ge 80) {
                $monitoringScore++
            }
            else {
                $result.Remediation += "Deploy monitoring agents to all virtual machines"
            }
        }
        
        # Check Security Center/Defender status
        $securityStatus = Get-AzSecurityPricing -ErrorAction SilentlyContinue
        $defenderEnabled = $securityStatus | Where-Object { $_.PricingTier -eq "Standard" }
        
        if ($defenderEnabled.Count -gt 0) {
            $monitoringScore++
            $result.Findings += "Microsoft Defender enabled for: $($defenderEnabled.Name -join ', ')"
        }
        else {
            $result.Findings += "Microsoft Defender for Cloud not fully enabled"
            $result.Remediation += "Enable Microsoft Defender for all resource types"
        }
        
        # Calculate final score
        $monitoringPercentage = [math]::Round(($monitoringScore / $totalChecks) * 100, 2)
        $result.Findings += "Overall monitoring coverage: $monitoringPercentage%"
        
        if ($monitoringScore -ge 4) {
            $result.Status = "Pass"
        }
        elseif ($monitoringScore -ge 2) {
            $result.Status = "Partial"
        }
        else {
            $result.Status = "Fail"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess system monitoring: $_"
    }
    
    return $result
}