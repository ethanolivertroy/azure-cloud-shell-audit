# System and Information Integrity Control Checks
# Implements FedRAMP and NIST 800-53 system integrity controls

function Test-SystemIntegrityControls {
    <#
    .SYNOPSIS
        Performs comprehensive system and information integrity checks
    .DESCRIPTION
        Evaluates Azure system integrity against FedRAMP and NIST 800-53 controls
    #>
    
    param(
        [string]$SubscriptionId
    )
    
    $integrityResults = @()
    
    Show-ControlProgress -ControlId "SI" -ControlName "System and Information Integrity" -Current 0 -Total 5
    
    # SI-2: Flaw Remediation
    $integrityResults += Test-FlawRemediation -SubscriptionId $SubscriptionId
    Show-ControlProgress -ControlId "SI" -ControlName "System and Information Integrity" -Current 1 -Total 5
    
    # SI-3: Malicious Code Protection
    $integrityResults += Test-MaliciousCodeProtection -SubscriptionId $SubscriptionId
    Show-ControlProgress -ControlId "SI" -ControlName "System and Information Integrity" -Current 2 -Total 5
    
    # SI-4: Information System Monitoring (already implemented in logging.ps1, but checking different aspects)
    $integrityResults += Test-IntegrityMonitoring -SubscriptionId $SubscriptionId
    Show-ControlProgress -ControlId "SI" -ControlName "System and Information Integrity" -Current 3 -Total 5
    
    # SI-7: Software, Firmware, and Information Integrity
    $integrityResults += Test-SoftwareIntegrity -SubscriptionId $SubscriptionId
    Show-ControlProgress -ControlId "SI" -ControlName "System and Information Integrity" -Current 4 -Total 5
    
    # SI-10: Information Input Validation
    $integrityResults += Test-InputValidation -SubscriptionId $SubscriptionId
    Show-ControlProgress -ControlId "SI" -ControlName "System and Information Integrity" -Current 5 -Total 5
    
    Complete-ControlProgress
    
    return $integrityResults
}

function Test-FlawRemediation {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "SI-2"
        ControlName = "Flaw Remediation"
        FedRAMPLevel = "High"
        NISTFamily = "System and Information Integrity"
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
        $patchingIssues = 0
        
        # Check Update Management solution
        $automationAccounts = Get-AzAutomationAccount -ErrorAction SilentlyContinue
        $updateManagementEnabled = $false
        
        foreach ($account in $automationAccounts) {
            $updateConfigs = Get-AzAutomationSoftwareUpdateConfiguration -ResourceGroupName $account.ResourceGroupName `
                -AutomationAccountName $account.AutomationAccountName -ErrorAction SilentlyContinue
            
            if ($updateConfigs) {
                $updateManagementEnabled = $true
                $result.Findings += "Update Management configured in automation account '$($account.AutomationAccountName)'"
                $result.Findings += "Found $($updateConfigs.Count) update configuration(s)"
                break
            }
        }
        
        if (-not $updateManagementEnabled) {
            $patchingIssues++
            $result.Findings += "No Update Management solution found"
            $result.Remediation += "Deploy Azure Update Management for centralized patch management"
        }
        
        # Check VM update status via Security Center
        $vms = Get-AzVM | Select-Object -First 10
        $assessments = Get-AzSecurityAssessment -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -like "*update*" -or $_.Name -like "*patch*" }
        
        $unhealthyVMs = 0
        foreach ($assessment in $assessments) {
            if ($assessment.Status.Code -eq "Unhealthy") {
                $unhealthyVMs++
            }
        }
        
        if ($vms.Count -gt 0 -and $assessments) {
            $patchComplianceRate = [math]::Round((($vms.Count - $unhealthyVMs) / $vms.Count) * 100, 2)
            $result.Findings += "VM patch compliance rate: $patchComplianceRate%"
            
            if ($patchComplianceRate -lt 95) {
                $patchingIssues++
                $result.Remediation += "Address missing security updates on virtual machines"
            }
        }
        else {
            $result.Findings += "Unable to determine VM patch status"
        }
        
        # Check for automatic updates policy
        $updatePolicies = Get-AzPolicyAssignment -ErrorAction SilentlyContinue | Where-Object {
            $_.Properties.DisplayName -like "*update*" -or $_.Properties.DisplayName -like "*patch*"
        }
        
        if ($updatePolicies.Count -gt 0) {
            $result.Findings += "Found $($updatePolicies.Count) update-related policies"
        }
        else {
            $patchingIssues++
            $result.Remediation += "Implement Azure Policies to enforce automatic updates"
        }
        
        # Check container image vulnerability scanning
        $containerRegistries = Get-AzContainerRegistry -ErrorAction SilentlyContinue
        if ($containerRegistries.Count -gt 0) {
            foreach ($registry in $containerRegistries) {
                if ($registry.ZoneRedundancy -or $registry.PublicNetworkAccess -eq "Disabled") {
                    $result.Findings += "Container registry '$($registry.Name)' has security features enabled"
                }
                else {
                    $result.Evidence += "Container registry '$($registry.Name)' may need security hardening"
                }
            }
        }
        
        # Check for vulnerability assessment
        $sqlServers = Get-AzSqlServer -ErrorAction SilentlyContinue
        $vaEnabledServers = 0
        
        foreach ($server in $sqlServers) {
            $vaSettings = Get-AzSqlServerVulnerabilityAssessmentSetting -ResourceGroupName $server.ResourceGroupName `
                -ServerName $server.ServerName -ErrorAction SilentlyContinue
            
            if ($vaSettings.IsEnabled) {
                $vaEnabledServers++
            }
        }
        
        if ($sqlServers.Count -gt 0) {
            $vaRate = [math]::Round(($vaEnabledServers / $sqlServers.Count) * 100, 2)
            $result.Findings += "SQL Server vulnerability assessment coverage: $vaRate%"
            
            if ($vaRate -lt 100) {
                $patchingIssues++
                $result.Remediation += "Enable vulnerability assessment on all SQL servers"
            }
        }
        
        if ($patchingIssues -eq 0) {
            $result.Status = "Pass"
        }
        elseif ($patchingIssues -le 2) {
            $result.Status = "Partial"
        }
        else {
            $result.Status = "Fail"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess flaw remediation: $_"
    }
    
    return $result
}

function Test-MaliciousCodeProtection {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "SI-3"
        ControlName = "Malicious Code Protection"
        FedRAMPLevel = "High"
        NISTFamily = "System and Information Integrity"
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
        $protectionGaps = 0
        
        # Check VM antimalware protection
        $vms = Get-AzVM | Select-Object -First 10
        $protectedVMs = 0
        
        foreach ($vm in $vms) {
            $extensions = Get-AzVMExtension -ResourceGroupName $vm.ResourceGroupName `
                -VMName $vm.Name -ErrorAction SilentlyContinue
            
            $hasAntimalware = $extensions | Where-Object { 
                $_.ExtensionType -in @("IaaSAntimalware", "LinuxDiagnostic", "CustomScriptExtension") -or
                $_.Name -like "*antimalware*" -or $_.Name -like "*defender*"
            }
            
            if ($hasAntimalware) {
                $protectedVMs++
            }
            else {
                $result.Evidence += "VM '$($vm.Name)' may not have antimalware protection"
            }
        }
        
        if ($vms.Count -gt 0) {
            $protectionRate = [math]::Round(($protectedVMs / $vms.Count) * 100, 2)
            $result.Findings += "VM antimalware coverage: $protectionRate%"
            
            if ($protectionRate -lt 95) {
                $protectionGaps++
                $result.Remediation += "Deploy antimalware solutions to all virtual machines"
            }
        }
        
        # Check Microsoft Defender for Cloud coverage
        $defenderPlans = Get-AzSecurityPricing -ErrorAction SilentlyContinue
        $enabledPlans = $defenderPlans | Where-Object { $_.PricingTier -eq "Standard" }
        
        if ($enabledPlans) {
            $result.Findings += "Microsoft Defender enabled for: $($enabledPlans.Name -join ', ')"
            
            # Check specifically for Defender for Servers
            if ($enabledPlans.Name -contains "VirtualMachines") {
                $result.Findings += "Microsoft Defender for Servers provides advanced threat protection"
            }
            else {
                $protectionGaps++
                $result.Remediation += "Enable Microsoft Defender for Servers for advanced threat protection"
            }
        }
        else {
            $protectionGaps++
            $result.Findings += "Microsoft Defender for Cloud not fully enabled"
            $result.Remediation += "Enable Microsoft Defender for Cloud Standard tier"
        }
        
        # Check for container security
        $aks = Get-AzAksCluster -ErrorAction SilentlyContinue
        if ($aks.Count -gt 0) {
            foreach ($cluster in $aks) {
                if ($cluster.AddonProfiles.omsAgent.Enabled) {
                    $result.Findings += "AKS cluster '$($cluster.Name)' has monitoring enabled"
                }
                else {
                    $result.Evidence += "AKS cluster '$($cluster.Name)' lacks monitoring (security blind spot)"
                }
                
                # Check for Azure Policy on AKS
                if ($cluster.AddonProfiles.azurepolicy.Enabled) {
                    $result.Findings += "AKS cluster '$($cluster.Name)' has Azure Policy enabled for security"
                }
                else {
                    $protectionGaps++
                    $result.Remediation += "Enable Azure Policy on AKS cluster '$($cluster.Name)'"
                }
            }
        }
        
        # Check App Service security
        $webApps = Get-AzWebApp -ErrorAction SilentlyContinue | Select-Object -First 5
        foreach ($app in $webApps) {
            $config = Get-AzWebApp -ResourceGroupName $app.ResourceGroup -Name $app.Name
            
            # Check if using managed identity (reduces attack surface)
            if ($config.Identity) {
                $result.Findings += "Web App '$($app.Name)' uses managed identity"
            }
            
            # Check for HTTPS only
            if (-not $config.HttpsOnly) {
                $result.Evidence += "Web App '$($app.Name)' allows HTTP traffic (security risk)"
            }
        }
        
        # Check for threat intelligence integration
        $sentinelWorkspaces = Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue | 
            Where-Object { 
                $solutions = Get-AzOperationalInsightsIntelligencePack -ResourceGroupName $_.ResourceGroupName `
                    -WorkspaceName $_.Name -ErrorAction SilentlyContinue
                $solutions.Name -contains "SecurityInsights"
            }
        
        if ($sentinelWorkspaces) {
            $result.Findings += "Microsoft Sentinel provides threat intelligence and behavioral analytics"
        }
        else {
            $protectionGaps++
            $result.Remediation += "Deploy Microsoft Sentinel for advanced threat detection"
        }
        
        # Check for file integrity monitoring
        $changeTrackingSolutions = Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue | ForEach-Object {
            $solutions = Get-AzOperationalInsightsIntelligencePack -ResourceGroupName $_.ResourceGroupName `
                -WorkspaceName $_.Name -ErrorAction SilentlyContinue
            $solutions | Where-Object { $_.Name -eq "ChangeTracking" }
        }
        
        if ($changeTrackingSolutions) {
            $result.Findings += "Change Tracking solution provides file integrity monitoring"
        }
        else {
            $result.Remediation += "Enable Change Tracking solution for file integrity monitoring"
        }
        
        if ($protectionGaps -eq 0) {
            $result.Status = "Pass"
        }
        elseif ($protectionGaps -le 2) {
            $result.Status = "Partial"
        }
        else {
            $result.Status = "Fail"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess malicious code protection: $_"
    }
    
    return $result
}

function Test-IntegrityMonitoring {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "SI-4"
        ControlName = "System Integrity Monitoring"
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
        $monitoringCapabilities = 0
        
        # Check for file integrity monitoring
        $automationAccounts = Get-AzAutomationAccount -ErrorAction SilentlyContinue
        foreach ($account in $automationAccounts) {
            $changeTrackingEnabled = Get-AzAutomationSolutionVariable -ResourceGroupName $account.ResourceGroupName `
                -AutomationAccountName $account.AutomationAccountName -Name "ChangeTracking" -ErrorAction SilentlyContinue
            
            if ($changeTrackingEnabled) {
                $monitoringCapabilities++
                $result.Findings += "File integrity monitoring enabled via Change Tracking"
                break
            }
        }
        
        # Check for security event monitoring
        $securityAlerts = Get-AzSecurityAlert -ErrorAction SilentlyContinue | Select-Object -First 5
        if ($securityAlerts) {
            $monitoringCapabilities++
            $result.Findings += "Security event monitoring active - found recent alerts"
            
            $highSeverityAlerts = $securityAlerts | Where-Object { $_.AlertSeverity -eq "High" }
            if ($highSeverityAlerts) {
                $result.Evidence += "High severity alerts detected - requires immediate attention"
            }
        }
        
        # Check for Azure Monitor metrics and alerts
        $metricAlerts = Get-AzMetricAlertRuleV2 -ErrorAction SilentlyContinue
        $integrityAlerts = $metricAlerts | Where-Object {
            $_.Name -like "*integrity*" -or $_.Description -like "*integrity*" -or
            $_.Name -like "*security*" -or $_.Description -like "*security*"
        }
        
        if ($integrityAlerts) {
            $monitoringCapabilities++
            $result.Findings += "Found $($integrityAlerts.Count) integrity-related metric alerts"
        }
        
        # Check for log-based monitoring
        $workspaces = Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue
        foreach ($workspace in $workspaces | Select-Object -First 2) {
            $savedSearches = Get-AzOperationalInsightsSavedSearch -ResourceGroupName $workspace.ResourceGroupName `
                -WorkspaceName $workspace.Name -ErrorAction SilentlyContinue
            
            $integrityQueries = $savedSearches | Where-Object { 
                $_.Properties.DisplayName -like "*integrity*" -or $_.Properties.DisplayName -like "*security*" 
            }
            
            if ($integrityQueries) {
                $monitoringCapabilities++
                $result.Findings += "Custom integrity monitoring queries found in workspace '$($workspace.Name)'"
                break
            }
        }
        
        # Check for compliance monitoring
        $complianceAssessments = Get-AzSecurityAssessment -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -like "*compliance*" -or $_.Name -like "*integrity*" }
        
        if ($complianceAssessments) {
            $monitoringCapabilities++
            $result.Findings += "Compliance and integrity assessments are being monitored"
        }
        
        # Check for Azure Sentinel UEBA (User and Entity Behavior Analytics)
        $sentinelWorkspaces = Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue | 
            Where-Object { 
                $solutions = Get-AzOperationalInsightsIntelligencePack -ResourceGroupName $_.ResourceGroupName `
                    -WorkspaceName $_.Name -ErrorAction SilentlyContinue
                $solutions.Name -contains "SecurityInsights"
            }
        
        if ($sentinelWorkspaces) {
            $monitoringCapabilities++
            $result.Findings += "Microsoft Sentinel provides behavioral analytics for integrity monitoring"
        }
        
        # Evaluate monitoring coverage
        $result.Findings += "Integrity monitoring capabilities: $monitoringCapabilities/5"
        
        if ($monitoringCapabilities -ge 4) {
            $result.Status = "Pass"
        }
        elseif ($monitoringCapabilities -ge 2) {
            $result.Status = "Partial"
        }
        else {
            $result.Status = "Fail"
            $result.Remediation += "Implement comprehensive integrity monitoring solution"
        }
        
        if ($monitoringCapabilities -lt 3) {
            $result.Remediation += "Enable file integrity monitoring via Change Tracking"
            $result.Remediation += "Configure security event monitoring and alerting"
            $result.Remediation += "Deploy Microsoft Sentinel for advanced analytics"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess integrity monitoring: $_"
    }
    
    return $result
}

function Test-SoftwareIntegrity {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "SI-7"
        ControlName = "Software, Firmware, and Information Integrity"
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
        $integrityMechanisms = 0
        
        # Check for code signing and trusted publishers
        $keyVaults = Get-AzKeyVault
        $signingCertificates = 0
        
        foreach ($kv in $keyVaults) {
            $certificates = Get-AzKeyVaultCertificate -VaultName $kv.VaultName -ErrorAction SilentlyContinue
            $signingCerts = $certificates | Where-Object { 
                $_.Tags.Purpose -eq "CodeSigning" -or $_.Name -like "*sign*" 
            }
            
            if ($signingCerts) {
                $signingCertificates += $signingCerts.Count
            }
        }
        
        if ($signingCertificates -gt 0) {
            $integrityMechanisms++
            $result.Findings += "Found $signingCertificates code signing certificate(s) in Key Vault"
        }
        else {
            $result.Findings += "No code signing certificates found in Key Vaults"
            $result.Remediation += "Implement code signing for software integrity verification"
        }
        
        # Check for container image scanning
        $containerRegistries = Get-AzContainerRegistry -ErrorAction SilentlyContinue
        foreach ($registry in $containerRegistries) {
            # Check for vulnerability scanning
            if ($registry.ZoneRedundancy) {
                $result.Findings += "Container registry '$($registry.Name)' has enterprise features enabled"
                $integrityMechanisms++
                break
            }
        }
        
        # Check for DevOps security practices
        $devopsProjects = Get-AzResource -ResourceType "Microsoft.DevTestLab/labs" -ErrorAction SilentlyContinue
        if ($devopsProjects) {
            $result.Findings += "DevTest Labs found - check for secure development practices"
        }
        
        # Check for Azure Policy Guest Configuration (ensures software compliance)
        $guestConfigPolicies = Get-AzPolicyAssignment -ErrorAction SilentlyContinue | Where-Object {
            $_.Properties.DisplayName -like "*guest*" -or $_.Properties.DisplayName -like "*configuration*"
        }
        
        if ($guestConfigPolicies) {
            $integrityMechanisms++
            $result.Findings += "Guest Configuration policies found for software compliance"
        }
        else {
            $result.Remediation += "Implement Guest Configuration policies for software integrity checks"
        }
        
        # Check for Azure Attestation service
        $attestationProviders = Get-AzResource -ResourceType "Microsoft.Attestation/attestationProviders" -ErrorAction SilentlyContinue
        if ($attestationProviders) {
            $integrityMechanisms++
            $result.Findings += "Azure Attestation service configured for integrity verification"
        }
        
        # Check for secure boot and other firmware protections on VMs
        $vms = Get-AzVM | Select-Object -First 5
        $secureBootVMs = 0
        
        foreach ($vm in $vms) {
            # Check if VM supports secure boot (Gen 2 VMs)
            if ($vm.StorageProfile.ImageReference.Sku -like "*gen2*" -or 
                $vm.HardwareProfile.VmSize -like "*s_v*") {
                $secureBootVMs++
            }
        }
        
        if ($vms.Count -gt 0) {
            $secureBootRate = [math]::Round(($secureBootVMs / $vms.Count) * 100, 2)
            $result.Findings += "Secure boot capable VMs: $secureBootRate%"
            
            if ($secureBootRate -ge 50) {
                $integrityMechanisms++
            }
            else {
                $result.Remediation += "Use Generation 2 VMs with secure boot capability"
            }
        }
        
        # Check for application integrity monitoring
        $appInsights = Get-AzApplicationInsights -ErrorAction SilentlyContinue
        if ($appInsights) {
            $result.Findings += "Application Insights available for application integrity monitoring"
        }
        
        if ($integrityMechanisms -ge 3) {
            $result.Status = "Pass"
        }
        elseif ($integrityMechanisms -ge 1) {
            $result.Status = "Partial"
        }
        else {
            $result.Status = "Fail"
        }
        
        $result.Findings += "Software integrity mechanisms: $integrityMechanisms/5"
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess software integrity: $_"
    }
    
    return $result
}

function Test-InputValidation {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "SI-10"
        ControlName = "Information Input Validation"
        FedRAMPLevel = "High"
        NISTFamily = "System and Information Integrity"
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
        $validationMechanisms = 0
        
        # Check for Web Application Firewall
        $appGateways = Get-AzApplicationGateway -ErrorAction SilentlyContinue
        $wafEnabled = $appGateways | Where-Object { 
            $_.WebApplicationFirewallConfiguration -and $_.WebApplicationFirewallConfiguration.Enabled 
        }
        
        if ($wafEnabled) {
            $validationMechanisms++
            $result.Findings += "Web Application Firewall enabled on $($wafEnabled.Count) Application Gateway(s)"
            
            foreach ($gw in $wafEnabled) {
                $wafMode = $gw.WebApplicationFirewallConfiguration.FirewallMode
                $result.Findings += "- WAF '$($gw.Name)' mode: $wafMode"
                
                if ($wafMode -ne "Prevention") {
                    $result.Remediation += "Set WAF to Prevention mode on '$($gw.Name)' for active protection"
                }
            }
        }
        else {
            $result.Findings += "No Web Application Firewall protection found"
            $result.Remediation += "Enable WAF on Application Gateways for input validation"
        }
        
        # Check for Azure Front Door with WAF
        $frontDoors = Get-AzResource -ResourceType "Microsoft.Network/frontDoors" -ErrorAction SilentlyContinue
        if ($frontDoors) {
            $validationMechanisms++
            $result.Findings += "Azure Front Door available for global input validation"
        }
        
        # Check for API Management policies
        $apiMgmt = Get-AzApiManagement -ErrorAction SilentlyContinue
        if ($apiMgmt) {
            $validationMechanisms++
            $result.Findings += "API Management service can provide input validation policies"
            
            foreach ($service in $apiMgmt) {
                $result.Findings += "API Management service: '$($service.Name)' - verify validation policies are configured"
            }
        }
        else {
            $result.Remediation += "Consider API Management for centralized input validation"
        }
        
        # Check for Azure Functions with input validation
        $functionApps = Get-AzFunctionApp -ErrorAction SilentlyContinue | Select-Object -First 3
        foreach ($app in $functionApps) {
            $config = Get-AzFunctionApp -ResourceGroupName $app.ResourceGroup -Name $app.Name
            
            # Check for authentication requirements
            if ($config.SiteConfig.AuthSettings.Enabled) {
                $result.Findings += "Function App '$($app.Name)' has authentication enabled"
            }
        }
        
        # Check for Logic Apps input validation
        $logicApps = Get-AzResource -ResourceType "Microsoft.Logic/workflows" -ErrorAction SilentlyContinue | Select-Object -First 3
        if ($logicApps) {
            $result.Findings += "Logic Apps found - verify input validation in workflow definitions"
            $result.Findings += "Manual review required: Check Logic App triggers and actions for input validation"
        }
        
        # Check for network-level input validation
        $nsgs = Get-AzNetworkSecurityGroup | Select-Object -First 5
        $validationRules = 0
        
        foreach ($nsg in $nsgs) {
            # Look for rules that might indicate input validation
            $restrictiveRules = $nsg.SecurityRules | Where-Object {
                $_.Access -eq "Deny" -and $_.Direction -eq "Inbound" -and $_.Priority -lt 1000
            }
            
            if ($restrictiveRules) {
                $validationRules++
            }
        }
        
        if ($validationRules -gt 0) {
            $validationMechanisms++
            $result.Findings += "Network Security Groups have restrictive inbound rules"
        }
        
        # Check for SQL injection protection
        $sqlServers = Get-AzSqlServer -ErrorAction SilentlyContinue
        foreach ($server in $sqlServers) {
            $threatDetection = Get-AzSqlServerThreatDetectionSetting -ResourceGroupName $server.ResourceGroupName `
                -ServerName $server.ServerName -ErrorAction SilentlyContinue
            
            if ($threatDetection.ThreatDetectionState -eq "Enabled") {
                $validationMechanisms++
                $result.Findings += "SQL Server '$($server.ServerName)' has threat detection enabled"
                break
            }
        }
        
        # Provide manual verification recommendations
        $result.Findings += @(
            "Manual verification required:",
            "- Application code implements input validation",
            "- Database stored procedures validate inputs",
            "- API endpoints sanitize and validate inputs",
            "- File upload functionality validates file types and content"
        )
        
        if ($validationMechanisms -ge 3) {
            $result.Status = "Pass"
        }
        elseif ($validationMechanisms -ge 1) {
            $result.Status = "Partial"
        }
        else {
            $result.Status = "Fail"
        }
        
        $result.Findings += "Input validation mechanisms detected: $validationMechanisms/5"
        
        if ($validationMechanisms -lt 2) {
            $result.Remediation += "Implement comprehensive input validation strategy"
            $result.Remediation += "Enable WAF and threat detection services"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess input validation: $_"
    }
    
    return $result
}