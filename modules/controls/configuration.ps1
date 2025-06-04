# Configuration Management Control Checks
# Implements FedRAMP and NIST 800-53 configuration management controls

function Test-ConfigurationManagementControls {
    <#
    .SYNOPSIS
        Performs comprehensive configuration management checks
    .DESCRIPTION
        Evaluates Azure configuration management against FedRAMP and NIST 800-53 controls
    #>
    
    param(
        [string]$SubscriptionId
    )
    
    $configResults = @()
    
    Show-ControlProgress -ControlId "CM" -ControlName "Configuration Management" -Current 0 -Total 4
    
    # CM-2: Baseline Configuration
    $configResults += Test-BaselineConfiguration -SubscriptionId $SubscriptionId
    Show-ControlProgress -ControlId "CM" -ControlName "Configuration Management" -Current 1 -Total 4
    
    # CM-3: Configuration Change Control
    $configResults += Test-ChangeControl -SubscriptionId $SubscriptionId
    Show-ControlProgress -ControlId "CM" -ControlName "Configuration Management" -Current 2 -Total 4
    
    # CM-6: Configuration Settings
    $configResults += Test-ConfigurationSettings -SubscriptionId $SubscriptionId
    Show-ControlProgress -ControlId "CM" -ControlName "Configuration Management" -Current 3 -Total 4
    
    # CM-8: Information System Component Inventory
    $configResults += Test-ComponentInventory -SubscriptionId $SubscriptionId
    Show-ControlProgress -ControlId "CM" -ControlName "Configuration Management" -Current 4 -Total 4
    
    Complete-ControlProgress
    
    return $configResults
}

function Test-BaselineConfiguration {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "CM-2"
        ControlName = "Baseline Configuration"
        FedRAMPLevel = "High"
        NISTFamily = "Configuration Management"
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
        $baselineIssues = 0
        
        # Check Azure Policy for configuration baselines
        $baselinePolicies = Get-AzPolicyAssignment -ErrorAction SilentlyContinue | Where-Object {
            $_.Properties.DisplayName -like "*baseline*" -or 
            $_.Properties.DisplayName -like "*configuration*" -or
            $_.Properties.DisplayName -like "*security benchmark*"
        }
        
        if ($baselinePolicies.Count -gt 0) {
            $result.Findings += "Found $($baselinePolicies.Count) baseline configuration policies"
            
            # Check compliance of baseline policies
            foreach ($policy in $baselinePolicies) {
                $compliance = Get-AzPolicyState -PolicyAssignmentName $policy.Name `
                    -Filter "PolicyAssignmentId eq '$($policy.PolicyAssignmentId)'" -Top 1 -ErrorAction SilentlyContinue
                
                if ($compliance -and $compliance.ComplianceState -ne "Compliant") {
                    $baselineIssues++
                    $result.Evidence += "Policy '$($policy.Properties.DisplayName)' is non-compliant"
                }
            }
        }
        else {
            $baselineIssues++
            $result.Findings += "No baseline configuration policies found"
            $result.Remediation += "Assign Azure Security Benchmark or CIS baseline policies"
        }
        
        # Check for Azure Automation State Configuration (DSC)
        $automationAccounts = Get-AzAutomationAccount -ErrorAction SilentlyContinue
        $dscConfigurations = @()
        
        foreach ($account in $automationAccounts) {
            $configs = Get-AzAutomationDscConfiguration -ResourceGroupName $account.ResourceGroupName `
                -AutomationAccountName $account.AutomationAccountName -ErrorAction SilentlyContinue
            
            if ($configs) {
                $dscConfigurations += $configs
            }
        }
        
        if ($dscConfigurations.Count -gt 0) {
            $result.Findings += "Found $($dscConfigurations.Count) DSC configuration(s) for baseline management"
            
            # Check DSC node compliance
            foreach ($account in $automationAccounts) {
                $nodes = Get-AzAutomationDscNode -ResourceGroupName $account.ResourceGroupName `
                    -AutomationAccountName $account.AutomationAccountName -ErrorAction SilentlyContinue
                
                if ($nodes) {
                    $compliantNodes = $nodes | Where-Object { $_.Status -eq "Compliant" }
                    $complianceRate = 0
                    if ($nodes.Count -gt 0) {
                        $complianceRate = [math]::Round(($compliantNodes.Count / $nodes.Count) * 100, 2)
                    }
                    
                    $result.Findings += "DSC compliance rate in '$($account.AutomationAccountName)': $complianceRate%"
                    
                    if ($complianceRate -lt 90) {
                        $baselineIssues++
                        $result.Remediation += "Address DSC configuration drift in automation account '$($account.AutomationAccountName)'"
                    }
                }
            }
        }
        else {
            $result.Findings += "No DSC configurations found for automated baseline management"
            $result.Remediation += "Consider implementing Azure Automation State Configuration for baseline management"
        }
        
        # Check VM baseline compliance via Guest Configuration
        $vms = Get-AzVM | Select-Object -First 10
        $guestConfiguredVMs = 0
        
        foreach ($vm in $vms) {
            $extensions = Get-AzVMExtension -ResourceGroupName $vm.ResourceGroupName `
                -VMName $vm.Name -ErrorAction SilentlyContinue
            
            $hasGuestConfig = $extensions | Where-Object { 
                $_.ExtensionType -in @("ConfigurationforWindows", "ConfigurationforLinux")
            }
            
            if ($hasGuestConfig) {
                $guestConfiguredVMs++
            }
        }
        
        if ($vms.Count -gt 0) {
            $guestConfigRate = [math]::Round(($guestConfiguredVMs / $vms.Count) * 100, 2)
            $result.Findings += "Guest Configuration coverage: $guestConfigRate% of sampled VMs"
            
            if ($guestConfigRate -lt 80) {
                $baselineIssues++
                $result.Remediation += "Deploy Guest Configuration extension to more VMs for baseline monitoring"
            }
        }
        
        # Check for template-based deployments (ARM/Bicep)
        $deployments = Get-AzResourceGroupDeployment -ResourceGroupName (Get-AzResourceGroup | Select-Object -First 1).ResourceGroupName `
            -ErrorAction SilentlyContinue | Select-Object -First 5
        
        if ($deployments) {
            $result.Findings += "Infrastructure as Code detected - deployments found"
        }
        else {
            $result.Findings += "No recent ARM/Bicep deployments found"
            $result.Remediation += "Use Infrastructure as Code (ARM templates/Bicep) for consistent baseline deployments"
        }
        
        if ($baselineIssues -eq 0) {
            $result.Status = "Pass"
        }
        elseif ($baselineIssues -le 2) {
            $result.Status = "Partial"
        }
        else {
            $result.Status = "Fail"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess baseline configuration: $_"
    }
    
    return $result
}

function Test-ChangeControl {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "CM-3"
        ControlName = "Configuration Change Control"
        FedRAMPLevel = "High"
        NISTFamily = "Configuration Management"
        Status = "Unknown"
        CIAImpact = @{
            Confidentiality = "Medium"
            Integrity = "High"
            Availability = "High"
        }
        Findings = @()
        Evidence = @()
        Remediation = @()
    }
    
    try {
        $changeControlMechanisms = 0
        
        # Check Activity Log for change tracking
        $changes = Get-AzActivityLog -StartTime (Get-Date).AddDays(-7) -MaxRecord 50 -ErrorAction SilentlyContinue | 
            Where-Object { $_.OperationName.Value -like "*write*" -or $_.OperationName.Value -like "*delete*" }
        
        if ($changes) {
            $result.Findings += "Found $($changes.Count) configuration changes in the last 7 days"
            $changeControlMechanisms++
            
            # Check for changes by non-service principals (human users)
            $humanChanges = $changes | Where-Object { 
                $_.Caller -notlike "*@microsoft.com" -and 
                $_.Caller -notlike "*serviceprincipal*" -and
                $_.Caller -ne "Unknown"
            }
            
            if ($humanChanges) {
                $result.Findings += "Human-initiated changes: $($humanChanges.Count) (requires approval tracking)"
                $result.Evidence += "Recent changes by: $($humanChanges.Caller | Select-Object -Unique -First 5)"
            }
        }
        
        # Check for resource locks (prevent unauthorized changes)
        $resourceGroups = Get-AzResourceGroup | Select-Object -First 10
        $lockedResources = 0
        $totalResources = 0
        
        foreach ($rg in $resourceGroups) {
            $locks = Get-AzResourceLock -ResourceGroupName $rg.ResourceGroupName -ErrorAction SilentlyContinue
            if ($locks) {
                $lockedResources += $locks.Count
            }
            
            $resources = Get-AzResource -ResourceGroupName $rg.ResourceGroupName -ErrorAction SilentlyContinue
            $totalResources += $resources.Count
        }
        
        if ($totalResources -gt 0) {
            $lockPercentage = [math]::Round(($lockedResources / $totalResources) * 100, 2)
            $result.Findings += "Resource lock coverage: $lockPercentage% of sampled resources"
            
            if ($lockPercentage -gt 10) {
                $changeControlMechanisms++
            }
            else {
                $result.Remediation += "Apply resource locks to critical resources to prevent unauthorized changes"
            }
        }
        
        # Check for Azure DevOps/GitHub integration (CI/CD pipeline controls)
        $automationAccounts = Get-AzAutomationAccount -ErrorAction SilentlyContinue
        $sourceControlConnections = @()
        
        foreach ($account in $automationAccounts) {
            $sourceControl = Get-AzAutomationSourceControl -ResourceGroupName $account.ResourceGroupName `
                -AutomationAccountName $account.AutomationAccountName -ErrorAction SilentlyContinue
            
            if ($sourceControl) {
                $sourceControlConnections += $sourceControl
            }
        }
        
        if ($sourceControlConnections.Count -gt 0) {
            $changeControlMechanisms++
            $result.Findings += "Source control integration found: $($sourceControlConnections.Count) connection(s)"
        }
        else {
            $result.Findings += "No source control integration found"
            $result.Remediation += "Integrate with Azure DevOps or GitHub for change control workflows"
        }
        
        # Check for Azure Policy deny effects (prevent non-compliant changes)
        $denyPolicies = Get-AzPolicyAssignment -ErrorAction SilentlyContinue | ForEach-Object {
            $definition = Get-AzPolicyDefinition -Id $_.Properties.PolicyDefinitionId -ErrorAction SilentlyContinue
            if ($definition.Properties.PolicyRule.then.effect -eq "deny") {
                $_
            }
        }
        
        if ($denyPolicies.Count -gt 0) {
            $changeControlMechanisms++
            $result.Findings += "Found $($denyPolicies.Count) policies with deny effect for change prevention"
        }
        else {
            $result.Remediation += "Implement Azure Policies with deny effects to prevent unauthorized configurations"
        }
        
        # Check for RBAC controls on management operations
        $roleAssignments = Get-AzRoleAssignment | Where-Object { 
            $_.RoleDefinitionName -in @("Owner", "Contributor") 
        }
        
        if ($roleAssignments.Count -le 10) {
            $changeControlMechanisms++
            $result.Findings += "Limited privileged access: $($roleAssignments.Count) users with Owner/Contributor rights"
        }
        else {
            $result.Findings += "High number of privileged users: $($roleAssignments.Count) with change permissions"
            $result.Remediation += "Review and minimize users with Owner/Contributor access"
        }
        
        # Evaluate change control maturity
        if ($changeControlMechanisms -ge 4) {
            $result.Status = "Pass"
        }
        elseif ($changeControlMechanisms -ge 2) {
            $result.Status = "Partial"
        }
        else {
            $result.Status = "Fail"
        }
        
        $result.Findings += "Change control mechanisms detected: $changeControlMechanisms/5"
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess change control: $_"
    }
    
    return $result
}

function Test-ConfigurationSettings {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "CM-6"
        ControlName = "Configuration Settings"
        FedRAMPLevel = "High"
        NISTFamily = "Configuration Management"
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
        $configurationIssues = 0
        
        # Check security configuration policies
        $securityPolicies = Get-AzPolicyAssignment -ErrorAction SilentlyContinue | Where-Object {
            $_.Properties.DisplayName -match "security|configuration|hardening|CIS|NIST"
        }
        
        if ($securityPolicies.Count -gt 0) {
            $result.Findings += "Found $($securityPolicies.Count) security configuration policies"
            
            # Check compliance rate
            $nonCompliantPolicies = 0
            foreach ($policy in $securityPolicies | Select-Object -First 10) {
                $compliance = Get-AzPolicyState -PolicyAssignmentName $policy.Name `
                    -Filter "ComplianceState eq 'NonCompliant'" -Top 1 -ErrorAction SilentlyContinue
                
                if ($compliance) {
                    $nonCompliantPolicies++
                }
            }
            
            $complianceRate = [math]::Round((($securityPolicies.Count - $nonCompliantPolicies) / $securityPolicies.Count) * 100, 2)
            $result.Findings += "Security policy compliance rate: $complianceRate%"
            
            if ($complianceRate -lt 90) {
                $configurationIssues++
                $result.Remediation += "Address non-compliant security configuration policies"
            }
        }
        else {
            $configurationIssues++
            $result.Findings += "No security configuration policies found"
            $result.Remediation += "Implement security configuration policies (e.g., CIS benchmarks)"
        }
        
        # Check VM security configurations
        $vms = Get-AzVM | Select-Object -First 5
        $secureVMs = 0
        
        foreach ($vm in $vms) {
            $securityFeatures = 0
            
            # Check for disk encryption
            $diskEncryption = Get-AzVMDiskEncryptionStatus -ResourceGroupName $vm.ResourceGroupName `
                -VMName $vm.Name -ErrorAction SilentlyContinue
            
            if ($diskEncryption -and $diskEncryption.OsVolumeEncrypted -eq "Encrypted") {
                $securityFeatures++
            }
            
            # Check for monitoring agent
            $extensions = Get-AzVMExtension -ResourceGroupName $vm.ResourceGroupName `
                -VMName $vm.Name -ErrorAction SilentlyContinue
            
            if ($extensions | Where-Object { $_.ExtensionType -in @("MicrosoftMonitoringAgent", "OmsAgentForLinux") }) {
                $securityFeatures++
            }
            
            # Check for antimalware
            if ($extensions | Where-Object { $_.ExtensionType -in @("IaaSAntimalware", "LinuxDiagnostic") }) {
                $securityFeatures++
            }
            
            if ($securityFeatures -ge 2) {
                $secureVMs++
            }
        }
        
        if ($vms.Count -gt 0) {
            $vmSecurityRate = [math]::Round(($secureVMs / $vms.Count) * 100, 2)
            $result.Findings += "VM security configuration rate: $vmSecurityRate%"
            
            if ($vmSecurityRate -lt 80) {
                $configurationIssues++
                $result.Remediation += "Improve VM security configurations (encryption, monitoring, antimalware)"
            }
        }
        
        # Check network security configurations
        $nsgs = Get-AzNetworkSecurityGroup | Select-Object -First 5
        $secureNSGs = 0
        
        foreach ($nsg in $nsgs) {
            $hasRestrictiveRules = $false
            
            # Check for default deny rules
            foreach ($rule in $nsg.SecurityRules) {
                if ($rule.Direction -eq "Inbound" -and $rule.Access -eq "Deny" -and $rule.Priority -gt 1000) {
                    $hasRestrictiveRules = $true
                    break
                }
            }
            
            if ($hasRestrictiveRules) {
                $secureNSGs++
            }
        }
        
        if ($nsgs.Count -gt 0) {
            $nsgSecurityRate = [math]::Round(($secureNSGs / $nsgs.Count) * 100, 2)
            $result.Findings += "NSG security configuration rate: $nsgSecurityRate%"
            
            if ($nsgSecurityRate -lt 100) {
                $configurationIssues++
                $result.Remediation += "Review and harden Network Security Group rules"
            }
        }
        
        # Check storage account security settings
        $storageAccounts = Get-AzStorageAccount | Select-Object -First 5
        $secureStorageAccounts = 0
        
        foreach ($storage in $storageAccounts) {
            $securitySettings = 0
            
            if ($storage.EnableHttpsTrafficOnly) {
                $securitySettings++
            }
            
            if ($storage.MinimumTlsVersion -eq "TLS1_2") {
                $securitySettings++
            }
            
            if ($storage.AllowBlobPublicAccess -eq $false) {
                $securitySettings++
            }
            
            if ($securitySettings -ge 2) {
                $secureStorageAccounts++
            }
        }
        
        if ($storageAccounts.Count -gt 0) {
            $storageSecurityRate = [math]::Round(($secureStorageAccounts / $storageAccounts.Count) * 100, 2)
            $result.Findings += "Storage security configuration rate: $storageSecurityRate%"
            
            if ($storageSecurityRate -lt 100) {
                $configurationIssues++
                $result.Remediation += "Harden storage account security settings"
            }
        }
        
        if ($configurationIssues -eq 0) {
            $result.Status = "Pass"
        }
        elseif ($configurationIssues -le 2) {
            $result.Status = "Partial"
        }
        else {
            $result.Status = "Fail"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess configuration settings: $_"
    }
    
    return $result
}

function Test-ComponentInventory {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "CM-8"
        ControlName = "Information System Component Inventory"
        FedRAMPLevel = "High"
        NISTFamily = "Configuration Management"
        Status = "Unknown"
        CIAImpact = @{
            Confidentiality = "Low"
            Integrity = "Medium"
            Availability = "Medium"
        }
        Findings = @()
        Evidence = @()
        Remediation = @()
    }
    
    try {
        $inventoryCapabilities = 0
        
        # Check Azure Resource Graph for comprehensive inventory
        try {
            $totalResources = Search-AzGraph -Query "Resources | count" -ErrorAction SilentlyContinue
            if ($totalResources) {
                $inventoryCapabilities++
                $result.Findings += "Azure Resource Graph available for comprehensive inventory"
                $result.Findings += "Total resources in subscription: $($totalResources.Count_)"
            }
        }
        catch {
            $result.Findings += "Azure Resource Graph not accessible for inventory queries"
        }
        
        # Check for resource tagging (helps with inventory classification)
        $resources = Get-AzResource | Select-Object -First 20
        $taggedResources = $resources | Where-Object { $_.Tags -and $_.Tags.Count -gt 0 }
        
        if ($resources.Count -gt 0) {
            $taggingRate = [math]::Round(($taggedResources.Count / $resources.Count) * 100, 2)
            $result.Findings += "Resource tagging rate: $taggingRate%"
            
            if ($taggingRate -ge 70) {
                $inventoryCapabilities++
            }
            else {
                $result.Remediation += "Improve resource tagging for better inventory management"
            }
        }
        
        # Check for Azure Automation Inventory feature
        $automationAccounts = Get-AzAutomationAccount -ErrorAction SilentlyContinue
        foreach ($account in $automationAccounts) {
            # Check if Inventory solution is enabled
            $workspace = Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($workspace) {
                $solutions = Get-AzOperationalInsightsIntelligencePack -ResourceGroupName $workspace.ResourceGroupName `
                    -WorkspaceName $workspace.Name -ErrorAction SilentlyContinue
                
                if ($solutions | Where-Object { $_.Name -eq "ChangeTracking" }) {
                    $inventoryCapabilities++
                    $result.Findings += "Change Tracking and Inventory solution enabled"
                    break
                }
            }
        }
        
        if ($inventoryCapabilities -lt 2) {
            $result.Remediation += "Enable Azure Automation Change Tracking and Inventory solution"
        }
        
        # Check for VM inventory coverage
        $vms = Get-AzVM | Select-Object -First 10
        $inventoryEnabledVMs = 0
        
        foreach ($vm in $vms) {
            $extensions = Get-AzVMExtension -ResourceGroupName $vm.ResourceGroupName `
                -VMName $vm.Name -ErrorAction SilentlyContinue
            
            if ($extensions | Where-Object { $_.ExtensionType -in @("MicrosoftMonitoringAgent", "OmsAgentForLinux") }) {
                $inventoryEnabledVMs++
            }
        }
        
        if ($vms.Count -gt 0) {
            $vmInventoryRate = [math]::Round(($inventoryEnabledVMs / $vms.Count) * 100, 2)
            $result.Findings += "VM inventory coverage: $vmInventoryRate%"
            
            if ($vmInventoryRate -ge 80) {
                $inventoryCapabilities++
            }
            else {
                $result.Remediation += "Deploy monitoring agents to more VMs for inventory tracking"
            }
        }
        
        # Check for Azure Security Center asset inventory
        try {
            $assessments = Get-AzSecurityAssessment -ErrorAction SilentlyContinue | Select-Object -First 5
            if ($assessments) {
                $inventoryCapabilities++
                $result.Findings += "Microsoft Defender for Cloud provides security asset inventory"
            }
        }
        catch {
            $result.Findings += "Microsoft Defender for Cloud asset inventory not accessible"
        }
        
        # Check for software inventory in storage accounts
        $storageAccounts = Get-AzStorageAccount | Select-Object -First 3
        foreach ($storage in $storageAccounts) {
            try {
                $inventoryPolicies = Get-AzStorageBlobInventoryPolicy -StorageAccount $storage -ErrorAction SilentlyContinue
                if ($inventoryPolicies) {
                    $result.Findings += "Storage account '$($storage.StorageAccountName)' has blob inventory policies"
                    break
                }
            }
            catch {
                # Continue to next storage account
            }
        }
        
        # Evaluate inventory maturity
        $result.Findings += "Inventory capabilities score: $inventoryCapabilities/5"
        
        if ($inventoryCapabilities -ge 4) {
            $result.Status = "Pass"
        }
        elseif ($inventoryCapabilities -ge 2) {
            $result.Status = "Partial"
        }
        else {
            $result.Status = "Fail"
        }
        
        # Standard recommendations
        $result.Recommendations = @(
            "Implement comprehensive asset tagging strategy",
            "Use Azure Resource Graph for advanced inventory queries",
            "Enable Change Tracking and Inventory solution",
            "Maintain up-to-date inventory documentation"
        )
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess component inventory: $_"
    }
    
    return $result
}