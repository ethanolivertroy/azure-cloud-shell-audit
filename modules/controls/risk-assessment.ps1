# Risk Assessment Control Checks
# Implements FedRAMP and NIST 800-53 risk assessment controls

function Test-RiskAssessmentControls {
    <#
    .SYNOPSIS
        Performs comprehensive risk assessment checks
    .DESCRIPTION
        Evaluates Azure risk assessment capabilities against FedRAMP and NIST 800-53 controls
    #>
    
    param(
        [string]$SubscriptionId
    )
    
    $riskResults = @()
    
    Show-ControlProgress -ControlId "RA" -ControlName "Risk Assessment" -Current 0 -Total 3
    
    # RA-3: Risk Assessment
    $riskResults += Test-RiskAssessmentProcess -SubscriptionId $SubscriptionId
    Show-ControlProgress -ControlId "RA" -ControlName "Risk Assessment" -Current 1 -Total 3
    
    # RA-5: Vulnerability Scanning
    $riskResults += Test-VulnerabilityScanning -SubscriptionId $SubscriptionId
    Show-ControlProgress -ControlId "RA" -ControlName "Risk Assessment" -Current 2 -Total 3
    
    # RA-7: Risk Response
    $riskResults += Test-RiskResponse -SubscriptionId $SubscriptionId
    Show-ControlProgress -ControlId "RA" -ControlName "Risk Assessment" -Current 3 -Total 3
    
    Complete-ControlProgress
    
    return $riskResults
}

function Test-RiskAssessmentProcess {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "RA-3"
        ControlName = "Risk Assessment"
        FedRAMPLevel = "High"
        NISTFamily = "Risk Assessment"
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
        $riskAssessmentCapabilities = 0
        
        # Check Azure Security Center Secure Score
        $secureScore = Get-AzSecurityAssessment -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -like "*secure*score*" }
        
        if ($secureScore) {
            $riskAssessmentCapabilities++
            $result.Findings += "Microsoft Defender for Cloud Secure Score provides risk assessment"
        }
        else {
            $result.Findings += "Unable to retrieve Secure Score information"
        }
        
        # Check for security assessments
        $assessments = Get-AzSecurityAssessment -ErrorAction SilentlyContinue | Select-Object -First 20
        if ($assessments) {
            $unhealthyAssessments = $assessments | Where-Object { $_.Status.Code -eq "Unhealthy" }
            $assessmentRate = 0
            if ($assessments.Count -gt 0) {
                $assessmentRate = [math]::Round((($assessments.Count - $unhealthyAssessments.Count) / $assessments.Count) * 100, 2)
            }
            
            $riskAssessmentCapabilities++
            $result.Findings += "Security assessment health rate: $assessmentRate%"
            $result.Findings += "Total assessments: $($assessments.Count), Unhealthy: $($unhealthyAssessments.Count)"
            
            if ($assessmentRate -lt 80) {
                $result.Evidence += "High number of unhealthy security assessments indicates elevated risk"
                $result.Remediation += "Address unhealthy security assessments to reduce risk exposure"
            }
        }
        
        # Check for regulatory compliance assessments
        $complianceAssessments = Get-AzSecurityRegulatoryComplianceStandard -ErrorAction SilentlyContinue
        if ($complianceAssessments) {
            $riskAssessmentCapabilities++
            $result.Findings += "Regulatory compliance assessments available"
            
            foreach ($standard in $complianceAssessments | Select-Object -First 3) {
                $controls = Get-AzSecurityRegulatoryComplianceControl -StandardName $standard.Name -ErrorAction SilentlyContinue
                if ($controls) {
                    $passedControls = $controls | Where-Object { $_.State -eq "Passed" }
                    $complianceRate = [math]::Round(($passedControls.Count / $controls.Count) * 100, 2)
                    $result.Findings += "Compliance standard '$($standard.Name)': $complianceRate% compliant"
                }
            }
        }
        
        # Check for Azure Policy compliance (risk indicator)
        $policyStates = Get-AzPolicyState -Filter "ComplianceState eq 'NonCompliant'" -Top 50 -ErrorAction SilentlyContinue
        if ($policyStates) {
            $riskAssessmentCapabilities++
            $result.Findings += "Policy compliance monitoring: $($policyStates.Count) non-compliant resources detected"
            
            # Categorize by severity
            $criticalPolicies = $policyStates | Where-Object { 
                $_.PolicyDefinitionName -like "*security*" -or $_.PolicyDefinitionName -like "*encryption*"
            }
            
            if ($criticalPolicies) {
                $result.Evidence += "Critical policy violations: $($criticalPolicies.Count) security-related non-compliance issues"
                $result.Remediation += "Prioritize remediation of security policy violations"
            }
        }
        
        # Check for Microsoft Sentinel risk indicators
        $sentinelWorkspaces = Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue | 
            Where-Object { 
                $solutions = Get-AzOperationalInsightsIntelligencePack -ResourceGroupName $_.ResourceGroupName `
                    -WorkspaceName $_.Name -ErrorAction SilentlyContinue
                $solutions.Name -contains "SecurityInsights"
            }
        
        if ($sentinelWorkspaces) {
            $riskAssessmentCapabilities++
            $result.Findings += "Microsoft Sentinel provides advanced risk analytics"
            
            # Note: Real implementation would query Sentinel for incidents and risk scores
            $result.Findings += "Manual verification: Check Sentinel for active incidents and risk indicators"
        }
        
        # Check for business impact analysis indicators
        $resourceGroups = Get-AzResourceGroup
        $taggedForBIA = $resourceGroups | Where-Object { 
            $_.Tags -and ($_.Tags.ContainsKey("BusinessImpact") -or $_.Tags.ContainsKey("Criticality"))
        }
        
        if ($taggedForBIA.Count -gt 0) {
            $riskAssessmentCapabilities++
            $biaRate = [math]::Round(($taggedForBIA.Count / $resourceGroups.Count) * 100, 2)
            $result.Findings += "Business impact classification: $biaRate% of resource groups tagged"
        }
        else {
            $result.Findings += "No business impact analysis tags found"
            $result.Remediation += "Implement business impact classification tags for risk assessment"
        }
        
        # Evaluate risk assessment maturity
        $result.Findings += "Risk assessment capabilities: $riskAssessmentCapabilities/5"
        
        if ($riskAssessmentCapabilities -ge 4) {
            $result.Status = "Pass"
        }
        elseif ($riskAssessmentCapabilities -ge 2) {
            $result.Status = "Partial"
        }
        else {
            $result.Status = "Fail"
        }
        
        # Standard recommendations
        if ($riskAssessmentCapabilities -lt 3) {
            $result.Remediation += "Enable Microsoft Defender for Cloud for comprehensive risk assessment"
            $result.Remediation += "Implement regular security assessments and compliance monitoring"
            $result.Remediation += "Deploy Microsoft Sentinel for advanced threat analytics"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess risk assessment process: $_"
    }
    
    return $result
}

function Test-VulnerabilityScanning {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "RA-5"
        ControlName = "Vulnerability Scanning"
        FedRAMPLevel = "High"
        NISTFamily = "Risk Assessment"
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
        $scanningMechanisms = 0
        
        # Check Microsoft Defender for Cloud vulnerability assessment
        $assessments = Get-AzSecurityAssessment -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -like "*vulnerability*" -or $_.Name -like "*security*" }
        
        if ($assessments) {
            $scanningMechanisms++
            $vulnerabilityAssessments = $assessments | Where-Object { $_.Name -like "*vulnerability*" }
            $result.Findings += "Vulnerability assessments available: $($vulnerabilityAssessments.Count) checks"
            
            $criticalFindings = $assessments | Where-Object { 
                $_.Status.Code -eq "Unhealthy" -and $_.Status.Severity -eq "High"
            }
            
            if ($criticalFindings) {
                $result.Evidence += "Critical vulnerabilities detected: $($criticalFindings.Count) high-severity findings"
                $result.Remediation += "Address critical vulnerability findings immediately"
            }
        }
        
        # Check SQL vulnerability assessment
        $sqlServers = Get-AzSqlServer -ErrorAction SilentlyContinue
        $vaEnabledServers = 0
        
        foreach ($server in $sqlServers) {
            $vaSettings = Get-AzSqlServerVulnerabilityAssessmentSetting -ResourceGroupName $server.ResourceGroupName `
                -ServerName $server.ServerName -ErrorAction SilentlyContinue
            
            if ($vaSettings.IsEnabled) {
                $vaEnabledServers++
                
                # Check for recent scans
                $databases = Get-AzSqlDatabase -ServerName $server.ServerName `
                    -ResourceGroupName $server.ResourceGroupName -ErrorAction SilentlyContinue
                
                foreach ($db in $databases | Select-Object -First 2) {
                    $scans = Get-AzSqlDatabaseVulnerabilityAssessmentScanRecord -ResourceGroupName $server.ResourceGroupName `
                        -ServerName $server.ServerName -DatabaseName $db.DatabaseName -ErrorAction SilentlyContinue
                    
                    if ($scans) {
                        $recentScan = $scans | Sort-Object StartTime -Descending | Select-Object -First 1
                        $daysSinceLastScan = ((Get-Date) - $recentScan.StartTime).Days
                        
                        if ($daysSinceLastScan -le 30) {
                            $result.Findings += "SQL Database '$($db.DatabaseName)' scanned $daysSinceLastScan days ago"
                        }
                        else {
                            $result.Evidence += "SQL Database '$($db.DatabaseName)' last scanned $daysSinceLastScan days ago"
                        }
                    }
                }
            }
        }
        
        if ($sqlServers.Count -gt 0) {
            $sqlVaRate = [math]::Round(($vaEnabledServers / $sqlServers.Count) * 100, 2)
            $result.Findings += "SQL vulnerability assessment coverage: $sqlVaRate%"
            
            if ($vaEnabledServers -gt 0) {
                $scanningMechanisms++
            }
            
            if ($sqlVaRate -lt 100) {
                $result.Remediation += "Enable vulnerability assessment on all SQL servers"
            }
        }
        
        # Check container vulnerability scanning
        $containerRegistries = Get-AzContainerRegistry -ErrorAction SilentlyContinue
        foreach ($registry in $containerRegistries) {
            # Check for vulnerability scanning capability
            if ($registry.ZoneRedundancy -or $registry.NetworkRuleBypassOptions) {
                $scanningMechanisms++
                $result.Findings += "Container registry '$($registry.Name)' has advanced features for vulnerability scanning"
                break
            }
        }
        
        if ($containerRegistries.Count -gt 0 -and $scanningMechanisms -lt 3) {
            $result.Remediation += "Enable container image vulnerability scanning in Azure Container Registry"
        }
        
        # Check for third-party vulnerability scanners (via VM extensions)
        $vms = Get-AzVM | Select-Object -First 10
        $scannedVMs = 0
        
        foreach ($vm in $vms) {
            $extensions = Get-AzVMExtension -ResourceGroupName $vm.ResourceGroupName `
                -VMName $vm.Name -ErrorAction SilentlyContinue
            
            # Look for security/vulnerability scanning extensions
            $securityExtensions = $extensions | Where-Object { 
                $_.ExtensionType -like "*security*" -or $_.ExtensionType -like "*vulnerability*" -or
                $_.ExtensionType -like "*qualys*" -or $_.ExtensionType -like "*rapid7*" -or
                $_.ExtensionType -like "*tenable*"
            }
            
            if ($securityExtensions) {
                $scannedVMs++
            }
        }
        
        if ($vms.Count -gt 0) {
            $vmScanRate = [math]::Round(($scannedVMs / $vms.Count) * 100, 2)
            $result.Findings += "VM vulnerability scanning coverage: $vmScanRate%"
            
            if ($scannedVMs -gt 0) {
                $scanningMechanisms++
            }
            
            if ($vmScanRate -lt 90) {
                $result.Remediation += "Deploy vulnerability scanning agents to all virtual machines"
            }
        }
        
        # Check for web application vulnerability scanning
        $appServices = Get-AzWebApp -ErrorAction SilentlyContinue | Select-Object -First 5
        foreach ($app in $appServices) {
            $config = Get-AzWebApp -ResourceGroupName $app.ResourceGroup -Name $app.Name
            
            # Check for security scanning configurations
            if ($config.SiteConfig.RemoteDebuggingEnabled -eq $false -and $config.HttpsOnly) {
                $result.Findings += "Web App '$($app.Name)' has security hardening applied"
            }
        }
        
        # Check for network vulnerability scanning
        $networkWatchers = Get-AzNetworkWatcher -ErrorAction SilentlyContinue
        if ($networkWatchers.Count -gt 0) {
            $result.Findings += "Network Watcher available for network security analysis"
            # Note: Would need additional checks for actual vulnerability scanning configuration
        }
        
        # Check for Azure Security Center recommendations (vulnerability-related)
        $securityRecommendations = Get-AzSecurityAssessment -ErrorAction SilentlyContinue | 
            Where-Object { 
                $_.Status.Code -eq "Unhealthy" -and 
                ($_.Name -like "*patch*" -or $_.Name -like "*update*" -or $_.Name -like "*vulnerability*")
            }
        
        if ($securityRecommendations) {
            $result.Evidence += "Security recommendations indicate missing patches/updates: $($securityRecommendations.Count) items"
        }
        
        # Evaluate scanning coverage
        $result.Findings += "Vulnerability scanning mechanisms: $scanningMechanisms/5"
        
        if ($scanningMechanisms -ge 4) {
            $result.Status = "Pass"
        }
        elseif ($scanningMechanisms -ge 2) {
            $result.Status = "Partial"
        }
        else {
            $result.Status = "Fail"
        }
        
        if ($scanningMechanisms -lt 3) {
            $result.Remediation += "Implement comprehensive vulnerability scanning across all asset types"
            $result.Remediation += "Enable automated vulnerability assessments and regular scanning schedules"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess vulnerability scanning: $_"
    }
    
    return $result
}

function Test-RiskResponse {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "RA-7"
        ControlName = "Risk Response"
        FedRAMPLevel = "High"
        NISTFamily = "Risk Assessment"
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
        $responseCapabilities = 0
        
        # Check for automated remediation tasks
        $remediationTasks = Get-AzPolicyRemediation -ErrorAction SilentlyContinue
        if ($remediationTasks) {
            $responseCapabilities++
            $activeRemediations = $remediationTasks | Where-Object { 
                $_.Properties.ProvisioningState -in @("Running", "Accepted", "Created")
            }
            
            $result.Findings += "Policy remediation tasks: $($remediationTasks.Count) total, $($activeRemediations.Count) active"
            
            if ($activeRemediations.Count -gt 0) {
                $result.Findings += "Automated risk response is active"
            }
        }
        else {
            $result.Findings += "No automated policy remediation tasks found"
            $result.Remediation += "Implement automated remediation for policy violations"
        }
        
        # Check for Logic Apps used for automated response
        $logicApps = Get-AzResource -ResourceType "Microsoft.Logic/workflows" -ErrorAction SilentlyContinue
        $responseApps = $logicApps | Where-Object { 
            $_.Name -like "*remediat*" -or $_.Name -like "*response*" -or 
            $_.Name -like "*security*" -or $_.Name -like "*alert*"
        }
        
        if ($responseApps) {
            $responseCapabilities++
            $result.Findings += "Automated response workflows: $($responseApps.Count) Logic Apps for risk response"
        }
        else {
            $result.Remediation += "Create Logic Apps for automated incident response workflows"
        }
        
        # Check for Azure Automation runbooks for response
        $automationAccounts = Get-AzAutomationAccount -ErrorAction SilentlyContinue
        $responseRunbooks = @()
        
        foreach ($account in $automationAccounts) {
            $runbooks = Get-AzAutomationRunbook -ResourceGroupName $account.ResourceGroupName `
                -AutomationAccountName $account.AutomationAccountName -ErrorAction SilentlyContinue
            
            $securityRunbooks = $runbooks | Where-Object { 
                $_.Name -like "*security*" -or $_.Name -like "*remediat*" -or 
                $_.Name -like "*response*" -or $_.Name -like "*patch*"
            }
            
            if ($securityRunbooks) {
                $responseRunbooks += $securityRunbooks
            }
        }
        
        if ($responseRunbooks.Count -gt 0) {
            $responseCapabilities++
            $result.Findings += "Security response runbooks: $($responseRunbooks.Count) automated procedures"
        }
        
        # Check for Security Center auto-provisioning (automated agent deployment)
        $autoProvisioningSettings = Get-AzSecurityAutoProvisioningSetting -ErrorAction SilentlyContinue
        $enabledAutoProvisioning = $autoProvisioningSettings | Where-Object { $_.AutoProvision -eq "On" }
        
        if ($enabledAutoProvisioning) {
            $responseCapabilities++
            $result.Findings += "Auto-provisioning enabled for security agents"
        }
        else {
            $result.Remediation += "Enable auto-provisioning for security monitoring agents"
        }
        
        # Check for backup and disaster recovery capabilities
        $recoveryVaults = Get-AzRecoveryServicesVault -ErrorAction SilentlyContinue
        if ($recoveryVaults.Count -gt 0) {
            $responseCapabilities++
            $result.Findings += "Backup and recovery capabilities: $($recoveryVaults.Count) Recovery Services vaults"
            
            # Check for backup policies
            foreach ($vault in $recoveryVaults | Select-Object -First 2) {
                $policies = Get-AzRecoveryServicesBackupProtectionPolicy -VaultId $vault.ID -ErrorAction SilentlyContinue
                if ($policies) {
                    $result.Findings += "Vault '$($vault.Name)' has $($policies.Count) backup policies"
                }
            }
        }
        else {
            $result.Remediation += "Implement backup and disaster recovery for risk mitigation"
        }
        
        # Check for resource locks (prevent accidental changes)
        $resourceGroups = Get-AzResourceGroup | Select-Object -First 10
        $lockedGroups = 0
        
        foreach ($rg in $resourceGroups) {
            $locks = Get-AzResourceLock -ResourceGroupName $rg.ResourceGroupName -ErrorAction SilentlyContinue
            if ($locks) {
                $lockedGroups++
            }
        }
        
        if ($lockedGroups -gt 0) {
            $lockRate = [math]::Round(($lockedGroups / $resourceGroups.Count) * 100, 2)
            $result.Findings += "Resource protection: $lockRate% of sampled resource groups have locks"
            
            if ($lockRate -ge 20) {
                $responseCapabilities++
            }
        }
        
        # Check for alert action groups (response to alerts)
        $actionGroups = Get-AzActionGroup -ErrorAction SilentlyContinue
        $responseGroups = $actionGroups | Where-Object { 
            $_.Name -like "*security*" -or $_.Name -like "*incident*" -or 
            $_.Name -like "*response*" -or $_.Name -like "*remediat*"
        }
        
        if ($responseGroups) {
            $result.Findings += "Alert response groups: $($responseGroups.Count) action groups for incident response"
        }
        
        # Evaluate response maturity
        $result.Findings += "Risk response capabilities: $responseCapabilities/6"
        
        if ($responseCapabilities -ge 4) {
            $result.Status = "Pass"
        }
        elseif ($responseCapabilities -ge 2) {
            $result.Status = "Partial"
        }
        else {
            $result.Status = "Fail"
        }
        
        # Standard recommendations
        if ($responseCapabilities -lt 3) {
            $result.Remediation += "Develop automated risk response procedures"
            $result.Remediation += "Implement backup and disaster recovery plans"
            $result.Remediation += "Create incident response workflows and runbooks"
        }
        
        # FedRAMP specific
        $result.Remediation += "Ensure risk response procedures are documented and tested per FedRAMP requirements"
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess risk response: $_"
    }
    
    return $result
}