# Incident Response Control Checks
# Implements FedRAMP and NIST 800-53 incident response controls

function Test-IncidentResponseControls {
    <#
    .SYNOPSIS
        Performs comprehensive incident response readiness checks
    .DESCRIPTION
        Evaluates Azure incident response configuration against FedRAMP and NIST 800-53 controls
    #>
    
    param(
        [string]$SubscriptionId
    )
    
    $incidentResults = @()
    
    Show-ControlProgress -ControlId "IR" -ControlName "Incident Response" -Current 0 -Total 4
    
    # IR-4: Incident Handling
    $incidentResults += Test-IncidentHandling -SubscriptionId $SubscriptionId
    Show-ControlProgress -ControlId "IR" -ControlName "Incident Response" -Current 1 -Total 4
    
    # IR-5: Incident Monitoring
    $incidentResults += Test-IncidentMonitoring -SubscriptionId $SubscriptionId
    Show-ControlProgress -ControlId "IR" -ControlName "Incident Response" -Current 2 -Total 4
    
    # IR-6: Incident Reporting
    $incidentResults += Test-IncidentReporting -SubscriptionId $SubscriptionId
    Show-ControlProgress -ControlId "IR" -ControlName "Incident Response" -Current 3 -Total 4
    
    # IR-8: Incident Response Plan
    $incidentResults += Test-IncidentResponsePlan -SubscriptionId $SubscriptionId
    Show-ControlProgress -ControlId "IR" -ControlName "Incident Response" -Current 4 -Total 4
    
    Complete-ControlProgress
    
    return $incidentResults
}

function Test-IncidentHandling {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "IR-4"
        ControlName = "Incident Handling"
        FedRAMPLevel = "High"
        NISTFamily = "Incident Response"
        Status = "Unknown"
        CIAImpact = @{
            Confidentiality = "High"
            Integrity = "High"
            Availability = "High"
        }
        Findings = @()
        Evidence = @()
        Remediation = @()
    }
    
    try {
        $handlingCapabilities = 0
        $requiredCapabilities = 5
        
        # Check for Security Center/Defender incidents
        $securityAlerts = Get-AzSecurityAlert -ErrorAction SilentlyContinue | Select-Object -First 10
        if ($securityAlerts) {
            $result.Findings += "Microsoft Defender for Cloud is collecting security alerts"
            
            # Check alert handling status
            $handledAlerts = $securityAlerts | Where-Object { $_.Status -in @("Resolved", "Dismissed") }
            $handlingRate = 0
            if ($securityAlerts.Count -gt 0) {
                $handlingRate = [math]::Round(($handledAlerts.Count / $securityAlerts.Count) * 100, 2)
            }
            
            $result.Findings += "Alert handling rate: $handlingRate% of recent alerts have been addressed"
            
            if ($handlingRate -ge 80) {
                $handlingCapabilities++
            }
            else {
                $result.Remediation += "Improve incident response time - many alerts remain unhandled"
            }
        }
        else {
            $result.Findings += "No security alerts found or Microsoft Defender not configured"
            $result.Remediation += "Enable Microsoft Defender for Cloud to detect security incidents"
        }
        
        # Check for automated response (Logic Apps, Automation)
        $automationAccounts = Get-AzAutomationAccount -ErrorAction SilentlyContinue
        $logicApps = Get-AzResource -ResourceType "Microsoft.Logic/workflows" -ErrorAction SilentlyContinue
        
        if ($automationAccounts.Count -gt 0 -or $logicApps.Count -gt 0) {
            $handlingCapabilities++
            $result.Findings += "Found automation resources for incident response:"
            if ($automationAccounts.Count -gt 0) {
                $result.Findings += "- $($automationAccounts.Count) Automation Account(s)"
            }
            if ($logicApps.Count -gt 0) {
                $result.Findings += "- $($logicApps.Count) Logic App(s)"
                
                # Check for security-related Logic Apps
                $securityApps = $logicApps | Where-Object { 
                    $_.Name -like "*security*" -or $_.Name -like "*incident*" -or $_.Name -like "*alert*"
                }
                if ($securityApps) {
                    $handlingCapabilities++
                    $result.Findings += "Found $($securityApps.Count) security-focused Logic Apps"
                }
            }
        }
        else {
            $result.Findings += "No automation resources found for incident response"
            $result.Remediation += "Implement automated incident response using Logic Apps or Automation Runbooks"
        }
        
        # Check for Azure Sentinel (Security Orchestration)
        $sentinelWorkspaces = Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue | 
            Where-Object { 
                $solutions = Get-AzOperationalInsightsIntelligencePack -ResourceGroupName $_.ResourceGroupName `
                    -WorkspaceName $_.Name -ErrorAction SilentlyContinue
                $solutions.Name -contains "SecurityInsights"
            }
        
        if ($sentinelWorkspaces) {
            $handlingCapabilities++
            $result.Findings += "Microsoft Sentinel deployed for security orchestration"
            
            # Check for playbooks (simplified check)
            foreach ($workspace in $sentinelWorkspaces) {
                $rgName = $workspace.ResourceGroupName
                $playbooks = Get-AzResource -ResourceGroupName $rgName -ResourceType "Microsoft.Logic/workflows" `
                    -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*playbook*" }
                
                if ($playbooks) {
                    $handlingCapabilities++
                    $result.Findings += "Found $($playbooks.Count) Sentinel playbook(s) in resource group '$rgName'"
                }
            }
        }
        else {
            $result.Remediation += "Deploy Microsoft Sentinel for advanced incident handling and SOAR capabilities"
        }
        
        # Check for Action Groups (notification)
        $actionGroups = Get-AzActionGroup -ErrorAction SilentlyContinue
        $securityGroups = $actionGroups | Where-Object { 
            $_.Name -like "*security*" -or $_.Name -like "*incident*" -or $_.Name -like "*soc*"
        }
        
        if ($securityGroups) {
            $result.Findings += "Found $($securityGroups.Count) security-related Action Group(s) for notifications"
        }
        else {
            $result.Findings += "No dedicated security Action Groups found"
            $result.Remediation += "Create Action Groups for security incident notifications"
        }
        
        # Evaluate overall capability
        $capabilityScore = [math]::Round(($handlingCapabilities / $requiredCapabilities) * 100, 2)
        $result.Findings += "Incident handling capability score: $capabilityScore%"
        
        if ($handlingCapabilities -ge 3) {
            $result.Status = "Pass"
        }
        elseif ($handlingCapabilities -ge 2) {
            $result.Status = "Partial"
            $result.Remediation += "Enhance incident handling automation and orchestration"
        }
        else {
            $result.Status = "Fail"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess incident handling: $_"
    }
    
    return $result
}

function Test-IncidentMonitoring {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "IR-5"
        ControlName = "Incident Monitoring"
        FedRAMPLevel = "High"
        NISTFamily = "Incident Response"
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
        $monitoringPoints = 0
        
        # Check for continuous monitoring alerts
        $alertRules = Get-AzActivityLogAlert -ErrorAction SilentlyContinue
        $securityAlertRules = $alertRules | Where-Object {
            $_.Condition.AllOf.Field -match "security|incident|threat|attack|breach"
        }
        
        if ($securityAlertRules.Count -gt 0) {
            $monitoringPoints++
            $result.Findings += "Found $($securityAlertRules.Count) security-focused alert rules"
        }
        else {
            $result.Findings += "No security-specific alert rules configured"
            $result.Remediation += "Create alert rules for security incidents and threats"
        }
        
        # Check for threat intelligence feeds
        $sentinelWorkspaces = Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue | 
            Where-Object { 
                $solutions = Get-AzOperationalInsightsIntelligencePack -ResourceGroupName $_.ResourceGroupName `
                    -WorkspaceName $_.Name -ErrorAction SilentlyContinue
                $solutions.Name -contains "SecurityInsights"
            }
        
        if ($sentinelWorkspaces) {
            $result.Findings += "Microsoft Sentinel available for threat intelligence integration"
            $monitoringPoints++
            
            # Note: Checking actual TI feeds would require Sentinel API
            $result.Findings += "Manual verification required: Check Sentinel for configured threat intelligence feeds"
        }
        
        # Check Azure Security Center secure score
        try {
            $secureScore = Get-AzSecurityAssessment -ErrorAction SilentlyContinue | 
                Where-Object { $_.Name -eq "SecurityScore" }
            
            if ($secureScore) {
                $monitoringPoints++
                $result.Findings += "Security score monitoring is enabled"
            }
        }
        catch {
            $result.Findings += "Unable to retrieve security score information"
        }
        
        # Check for Security Center recommendations monitoring
        $assessments = Get-AzSecurityAssessment -ErrorAction SilentlyContinue | Select-Object -First 10
        if ($assessments) {
            $unhealthyAssessments = $assessments | Where-Object { $_.Status.Code -eq "Unhealthy" }
            $assessmentRate = 0
            if ($assessments.Count -gt 0) {
                $assessmentRate = [math]::Round((($assessments.Count - $unhealthyAssessments.Count) / $assessments.Count) * 100, 2)
            }
            
            $result.Findings += "Security assessment health: $assessmentRate% of checks are healthy"
            
            if ($assessmentRate -ge 70) {
                $monitoringPoints++
            }
            else {
                $result.Remediation += "Address security recommendations to improve monitoring coverage"
            }
        }
        
        # Check for SIEM integration
        $diagnosticSettings = Get-AzSubscriptionDiagnosticSetting -ErrorAction SilentlyContinue
        $siemIntegration = $diagnosticSettings | Where-Object {
            $_.EventHubAuthorizationRuleId -or $_.WorkspaceId
        }
        
        if ($siemIntegration) {
            $monitoringPoints++
            $result.Findings += "Subscription diagnostic settings configured for SIEM integration"
        }
        else {
            $result.Findings += "No SIEM integration detected at subscription level"
            $result.Remediation += "Configure diagnostic settings to send logs to SIEM/Log Analytics"
        }
        
        # Evaluate monitoring coverage
        if ($monitoringPoints -ge 4) {
            $result.Status = "Pass"
        }
        elseif ($monitoringPoints -ge 2) {
            $result.Status = "Partial"
        }
        else {
            $result.Status = "Fail"
        }
        
        $result.Findings += "Incident monitoring score: $monitoringPoints/5 capabilities detected"
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess incident monitoring: $_"
    }
    
    return $result
}

function Test-IncidentReporting {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "IR-6"
        ControlName = "Incident Reporting"
        FedRAMPLevel = "High"
        NISTFamily = "Incident Response"
        Status = "Unknown"
        CIAImpact = @{
            Confidentiality = "High"
            Integrity = "Medium"
            Availability = "Low"
        }
        Findings = @()
        Evidence = @()
        Remediation = @()
    }
    
    try {
        $reportingMechanisms = 0
        
        # Check Security Contacts
        $securityContacts = Get-AzSecurityContact -ErrorAction SilentlyContinue
        if ($securityContacts) {
            $reportingMechanisms++
            foreach ($contact in $securityContacts) {
                $result.Findings += "Security contact configured: $($contact.Email)"
                
                # Check notification settings
                if ($contact.AlertNotifications -eq "On") {
                    $reportingMechanisms++
                    $result.Findings += "- Alert notifications: Enabled"
                }
                else {
                    $result.Findings += "- Alert notifications: Disabled"
                    $result.Remediation += "Enable alert notifications for security contact"
                }
                
                if ($contact.NotificationsByRole -eq "On") {
                    $result.Findings += "- Role-based notifications: Enabled"
                }
            }
        }
        else {
            $result.Findings += "No security contacts configured"
            $result.Remediation += "Configure security contact information in Microsoft Defender for Cloud"
        }
        
        # Check Action Groups for incident reporting
        $actionGroups = Get-AzActionGroup -ErrorAction SilentlyContinue
        $reportingGroups = @()
        
        foreach ($group in $actionGroups) {
            # Check for email, SMS, or webhook actions
            $hasEmail = $group.EmailReceivers.Count -gt 0
            $hasSms = $group.SmsReceivers.Count -gt 0
            $hasWebhook = $group.WebhookReceivers.Count -gt 0
            $hasItsmReceiver = $group.ItsmReceivers.Count -gt 0
            
            if ($hasEmail -or $hasSms -or $hasWebhook -or $hasItsmReceiver) {
                $reportingGroups += $group
                
                if ($hasItsmReceiver) {
                    $reportingMechanisms++
                    $result.Findings += "ITSM integration found in Action Group '$($group.Name)'"
                }
            }
        }
        
        if ($reportingGroups.Count -gt 0) {
            $reportingMechanisms++
            $result.Findings += "Found $($reportingGroups.Count) Action Group(s) configured for notifications"
        }
        else {
            $result.Findings += "No Action Groups configured for incident notifications"
            $result.Remediation += "Create Action Groups with email/SMS/webhook for incident reporting"
        }
        
        # Check for Security Center email notifications
        $emailNotificationStatus = "Manual verification required"
        $result.Findings += "Security Center email notifications: $emailNotificationStatus"
        $result.Findings += "Verify weekly digest and alert emails are configured in Defender for Cloud"
        
        # Check for compliance reporting
        $policyAssignments = Get-AzPolicyAssignment -ErrorAction SilentlyContinue | 
            Where-Object { $_.Properties.DisplayName -like "*FedRAMP*" -or $_.Properties.DisplayName -like "*NIST*" }
        
        if ($policyAssignments) {
            $reportingMechanisms++
            $result.Findings += "Compliance policy assignments found for regulatory reporting"
        }
        
        # Check for Log Analytics scheduled queries (for reports)
        $workspaces = Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue
        foreach ($workspace in $workspaces | Select-Object -First 2) {
            $savedSearches = Get-AzOperationalInsightsSavedSearch -ResourceGroupName $workspace.ResourceGroupName `
                -WorkspaceName $workspace.Name -ErrorAction SilentlyContinue
            
            $reportQueries = $savedSearches | Where-Object { 
                $_.Properties.DisplayName -like "*report*" -or $_.Properties.DisplayName -like "*incident*" 
            }
            
            if ($reportQueries) {
                $result.Findings += "Found $($reportQueries.Count) saved queries for reporting in workspace '$($workspace.Name)'"
            }
        }
        
        # Evaluate reporting readiness
        if ($reportingMechanisms -ge 3) {
            $result.Status = "Pass"
        }
        elseif ($reportingMechanisms -ge 2) {
            $result.Status = "Partial"
            $result.Remediation += "Enhance incident reporting automation and integration"
        }
        else {
            $result.Status = "Fail"
            $result.Remediation += "Implement comprehensive incident reporting mechanisms"
        }
        
        # FedRAMP specific requirement
        $result.Findings += "FedRAMP requirement: Incidents must be reported within 1 hour"
        $result.Remediation += "Ensure incident reporting procedures meet FedRAMP timing requirements"
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess incident reporting: $_"
    }
    
    return $result
}

function Test-IncidentResponsePlan {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "IR-8"
        ControlName = "Incident Response Plan"
        FedRAMPLevel = "High"
        NISTFamily = "Incident Response"
        Status = "Unknown"
        CIAImpact = @{
            Confidentiality = "High"
            Integrity = "High"
            Availability = "High"
        }
        Findings = @()
        Evidence = @()
        Remediation = @()
    }
    
    try {
        $planElements = 0
        $requiredElements = 6
        
        # Check for runbooks (indicates documented procedures)
        $automationAccounts = Get-AzAutomationAccount -ErrorAction SilentlyContinue
        $incidentRunbooks = @()
        
        foreach ($account in $automationAccounts) {
            $runbooks = Get-AzAutomationRunbook -ResourceGroupName $account.ResourceGroupName `
                -AutomationAccountName $account.AutomationAccountName -ErrorAction SilentlyContinue
            
            $irRunbooks = $runbooks | Where-Object { 
                $_.Name -like "*incident*" -or $_.Name -like "*response*" -or 
                $_.Name -like "*security*" -or $_.Name -like "*breach*"
            }
            
            if ($irRunbooks) {
                $incidentRunbooks += $irRunbooks
            }
        }
        
        if ($incidentRunbooks.Count -gt 0) {
            $planElements++
            $result.Findings += "Found $($incidentRunbooks.Count) incident response runbook(s)"
            
            # Check if runbooks are published
            $publishedRunbooks = $incidentRunbooks | Where-Object { $_.State -eq "Published" }
            if ($publishedRunbooks.Count -eq $incidentRunbooks.Count) {
                $planElements++
                $result.Findings += "All incident response runbooks are published and ready"
            }
            else {
                $result.Findings += "Some runbooks are not published"
                $result.Remediation += "Publish all incident response runbooks"
            }
        }
        else {
            $result.Findings += "No incident response runbooks found"
            $result.Remediation += "Create automated runbooks for common incident response procedures"
        }
        
        # Check for documented contact information
        $securityContacts = Get-AzSecurityContact -ErrorAction SilentlyContinue
        if ($securityContacts -and $securityContacts.Email) {
            $planElements++
            $result.Findings += "Security contact information is documented"
        }
        else {
            $result.Findings += "No security contact information found"
            $result.Remediation += "Document security team contact information"
        }
        
        # Check for backup and recovery procedures
        $recoveryVaults = Get-AzRecoveryServicesVault -ErrorAction SilentlyContinue
        if ($recoveryVaults.Count -gt 0) {
            $planElements++
            $result.Findings += "Found $($recoveryVaults.Count) Recovery Services vault(s) for backup/recovery"
            
            # Check for backup policies
            foreach ($vault in $recoveryVaults | Select-Object -First 2) {
                $policies = Get-AzRecoveryServicesBackupProtectionPolicy -VaultId $vault.ID -ErrorAction SilentlyContinue
                if ($policies) {
                    $result.Findings += "Vault '$($vault.Name)' has $($policies.Count) backup policies configured"
                }
            }
        }
        else {
            $result.Findings += "No Recovery Services vaults found"
            $result.Remediation += "Implement backup and recovery procedures for incident response"
        }
        
        # Check for Security Playbooks (Logic Apps)
        $logicApps = Get-AzResource -ResourceType "Microsoft.Logic/workflows" -ErrorAction SilentlyContinue
        $securityPlaybooks = $logicApps | Where-Object { 
            $_.Name -like "*playbook*" -or $_.Name -like "*incident*" -or $_.Name -like "*security*"
        }
        
        if ($securityPlaybooks.Count -gt 0) {
            $planElements++
            $result.Findings += "Found $($securityPlaybooks.Count) security playbook(s)"
        }
        else {
            $result.Findings += "No security playbooks (Logic Apps) found"
            $result.Remediation += "Create Logic App playbooks for automated incident response"
        }
        
        # Check for Key Vault (for incident response credentials/secrets)
        $keyVaults = Get-AzKeyVault -ErrorAction SilentlyContinue
        $irKeyVaults = $keyVaults | Where-Object { 
            $_.VaultName -like "*incident*" -or $_.VaultName -like "*response*" -or 
            $_.VaultName -like "*security*" -or $_.Tags.Purpose -eq "IncidentResponse"
        }
        
        if ($irKeyVaults -or $keyVaults.Count -gt 0) {
            $planElements++
            $result.Findings += "Key Vault available for incident response credentials"
        }
        
        # Manual verification items
        $result.Findings += @(
            "Manual verification required:",
            "- Incident response plan document exists and is up to date",
            "- IR team roles and responsibilities are defined",
            "- Communication plan for stakeholders is documented",
            "- Lessons learned process is established"
        )
        
        # Calculate readiness score
        $readinessScore = [math]::Round(($planElements / $requiredElements) * 100, 2)
        $result.Findings += "Incident response plan readiness: $readinessScore%"
        
        if ($planElements -ge 4) {
            $result.Status = "Pass"
        }
        elseif ($planElements -ge 2) {
            $result.Status = "Partial"
            $result.Remediation += "Complete incident response plan documentation and automation"
        }
        else {
            $result.Status = "Fail"
            $result.Remediation += "Develop comprehensive incident response plan with automated procedures"
        }
        
        # FedRAMP specific
        $result.Remediation += "Ensure IR plan is tested annually per FedRAMP requirements"
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess incident response plan: $_"
    }
    
    return $result
}