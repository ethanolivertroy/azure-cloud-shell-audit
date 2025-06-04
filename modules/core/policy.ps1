# Azure Policy Integration Module
# Provides continuous compliance monitoring through Azure Policy

function Test-PolicyCompliance {
    <#
    .SYNOPSIS
        Evaluates Azure Policy compliance for FedRAMP and NIST controls
    .DESCRIPTION
        Checks policy assignments, compliance state, and remediation tasks
    #>
    
    param(
        [string]$SubscriptionId
    )
    
    $policyResults = @{
        TotalPolicies = 0
        CompliantPolicies = 0
        NonCompliantPolicies = 0
        CompliancePercentage = 0
        PolicyFindings = @()
        RemediationTasks = @()
        Recommendations = @()
    }
    
    try {
        Write-Host "  Checking Azure Policy compliance..." -ForegroundColor Yellow
        
        # Get all policy assignments
        $policyAssignments = Get-AzPolicyAssignment -ErrorAction SilentlyContinue
        
        # Filter for security and compliance related policies
        $compliancePolicies = $policyAssignments | Where-Object {
            $_.Properties.DisplayName -match "FedRAMP|NIST|Security|Compliance|CIS|ISO|SOC" -or
            $_.Properties.Description -match "security|compliance|audit"
        }
        
        if ($compliancePolicies.Count -eq 0) {
            $policyResults.PolicyFindings += "No compliance-focused policy assignments found"
            $policyResults.Recommendations += "Assign Azure Policy initiatives for FedRAMP High or NIST 800-53"
            return $policyResults
        }
        
        $policyResults.PolicyFindings += "Found $($compliancePolicies.Count) compliance-related policy assignments"
        
        # Check compliance state for each policy
        foreach ($assignment in $compliancePolicies) {
            Show-Spinner -Message "Evaluating policy: $($assignment.Properties.DisplayName)"
            
            # Get compliance state
            $compliance = Get-AzPolicyState -PolicyAssignmentName $assignment.Name `
                -Filter "PolicyAssignmentId eq '$($assignment.PolicyAssignmentId)'" `
                -Top 1 -ErrorAction SilentlyContinue
            
            if ($compliance) {
                $policyResults.TotalPolicies++
                
                if ($compliance.ComplianceState -eq "Compliant") {
                    $policyResults.CompliantPolicies++
                }
                else {
                    $policyResults.NonCompliantPolicies++
                    $policyResults.PolicyFindings += "Non-compliant: $($assignment.Properties.DisplayName)"
                    
                    # Get non-compliant resources
                    $nonCompliantResources = Get-AzPolicyState -PolicyAssignmentName $assignment.Name `
                        -Filter "ComplianceState eq 'NonCompliant' and PolicyAssignmentId eq '$($assignment.PolicyAssignmentId)'" `
                        -Top 10 -ErrorAction SilentlyContinue
                    
                    if ($nonCompliantResources) {
                        foreach ($resource in $nonCompliantResources) {
                            $policyResults.PolicyFindings += "  - Resource: $($resource.ResourceId.Split('/')[-1]) | Reason: $($resource.PolicyDefinitionAction)"
                        }
                    }
                }
            }
        }
        
        # Calculate compliance percentage
        if ($policyResults.TotalPolicies -gt 0) {
            $policyResults.CompliancePercentage = [math]::Round(
                ($policyResults.CompliantPolicies / $policyResults.TotalPolicies) * 100, 2
            )
        }
        
        # Check for remediation tasks
        $remediationTasks = Get-AzPolicyRemediation -ErrorAction SilentlyContinue
        
        if ($remediationTasks) {
            $activeTasks = $remediationTasks | Where-Object { 
                $_.Properties.ProvisioningState -in @("Running", "Evaluating", "Accepted")
            }
            
            if ($activeTasks) {
                $policyResults.RemediationTasks += "Found $($activeTasks.Count) active remediation tasks"
                foreach ($task in $activeTasks) {
                    $policyResults.RemediationTasks += "  - $($task.Name): $($task.Properties.ProvisioningState)"
                }
            }
            
            $failedTasks = $remediationTasks | Where-Object { 
                $_.Properties.ProvisioningState -eq "Failed"
            }
            
            if ($failedTasks) {
                $policyResults.RemediationTasks += "Found $($failedTasks.Count) failed remediation tasks requiring attention"
                $policyResults.Recommendations += "Review and retry failed policy remediation tasks"
            }
        }
        
        # Check for specific compliance initiatives
        $initiatives = @{
            "FedRAMP High" = "d5264498-16f4-418a-b659-fa7ef418175f"
            "NIST SP 800-53 Rev. 5" = "179d1daa-458f-4e47-8086-2a68d0d6c38f"
            "Azure Security Benchmark" = "1f3afdf9-d0c9-4c3d-847f-89da613e70a8"
        }
        
        foreach ($initiative in $initiatives.GetEnumerator()) {
            $assigned = $policyAssignments | Where-Object { 
                $_.Properties.PolicyDefinitionId -like "*$($initiative.Value)*"
            }
            
            if ($assigned) {
                $policyResults.PolicyFindings += "✓ $($initiative.Key) initiative is assigned"
            }
            else {
                $policyResults.Recommendations += "Consider assigning '$($initiative.Key)' policy initiative"
            }
        }
        
    }
    catch {
        $policyResults.PolicyFindings += "Error evaluating policy compliance: $_"
    }
    
    return $policyResults
}

function New-CompliancePolicyAssignment {
    <#
    .SYNOPSIS
        Creates policy assignments for FedRAMP/NIST compliance
    .DESCRIPTION
        Assigns recommended policy initiatives for continuous compliance monitoring
    #>
    
    param(
        [string]$SubscriptionId,
        [ValidateSet("FedRAMP", "NIST", "Both")]
        [string]$ComplianceFramework = "Both"
    )
    
    $assignments = @()
    
    # Policy initiative IDs
    $initiatives = @{
        "FedRAMP High" = "/providers/Microsoft.Authorization/policySetDefinitions/d5264498-16f4-418a-b659-fa7ef418175f"
        "NIST SP 800-53 Rev. 5" = "/providers/Microsoft.Authorization/policySetDefinitions/179d1daa-458f-4e47-8086-2a68d0d6c38f"
    }
    
    try {
        $scope = "/subscriptions/$SubscriptionId"
        
        if ($ComplianceFramework -in @("FedRAMP", "Both")) {
            Write-Host "Assigning FedRAMP High policy initiative..." -ForegroundColor Yellow
            
            $fedRampAssignment = New-AzPolicyAssignment `
                -Name "FedRAMPHigh-$(Get-Random -Maximum 9999)" `
                -DisplayName "FedRAMP High Compliance" `
                -Scope $scope `
                -PolicyDefinition $initiatives["FedRAMP High"] `
                -AssignIdentity `
                -Location "eastus" `
                -ErrorAction Stop
                
            $assignments += $fedRampAssignment
            Write-Host "✓ FedRAMP High policy initiative assigned successfully" -ForegroundColor Green
        }
        
        if ($ComplianceFramework -in @("NIST", "Both")) {
            Write-Host "Assigning NIST 800-53 policy initiative..." -ForegroundColor Yellow
            
            $nistAssignment = New-AzPolicyAssignment `
                -Name "NIST80053-$(Get-Random -Maximum 9999)" `
                -DisplayName "NIST SP 800-53 Rev. 5 Compliance" `
                -Scope $scope `
                -PolicyDefinition $initiatives["NIST SP 800-53 Rev. 5"] `
                -AssignIdentity `
                -Location "eastus" `
                -ErrorAction Stop
                
            $assignments += $nistAssignment
            Write-Host "✓ NIST 800-53 policy initiative assigned successfully" -ForegroundColor Green
        }
        
        # Create remediation tasks for the assignments
        foreach ($assignment in $assignments) {
            Write-Host "Creating remediation task for $($assignment.Properties.DisplayName)..." -ForegroundColor Yellow
            
            $remediation = Start-AzPolicyRemediation `
                -Name "Remediate-$($assignment.Name)" `
                -PolicyAssignmentId $assignment.PolicyAssignmentId `
                -ErrorAction SilentlyContinue
                
            if ($remediation) {
                Write-Host "✓ Remediation task created: $($remediation.Name)" -ForegroundColor Green
            }
        }
        
    }
    catch {
        Write-Error "Failed to create policy assignment: $_"
        return $null
    }
    
    return $assignments
}

function Get-PolicyComplianceReport {
    <#
    .SYNOPSIS
        Generates a detailed policy compliance report
    .DESCRIPTION
        Creates a comprehensive report of policy compliance status with control mapping
    #>
    
    param(
        [string]$SubscriptionId
    )
    
    $report = @{
        GeneratedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        SubscriptionId = $SubscriptionId
        ComplianceFrameworks = @()
        OverallCompliance = 0
        ControlMapping = @{}
        NonCompliantResources = @()
        Recommendations = @()
    }
    
    try {
        # Get policy compliance data
        $policyCompliance = Test-PolicyCompliance -SubscriptionId $SubscriptionId
        
        $report.OverallCompliance = $policyCompliance.CompliancePercentage
        
        # Map policies to controls
        $policyStates = Get-AzPolicyState -SubscriptionId $SubscriptionId `
            -Filter "ComplianceState eq 'NonCompliant'" -Top 100 -ErrorAction SilentlyContinue
        
        foreach ($state in $policyStates) {
            $policyDef = Get-AzPolicyDefinition -Id $state.PolicyDefinitionId -ErrorAction SilentlyContinue
            
            if ($policyDef.Properties.Metadata.category -eq "Regulatory Compliance") {
                $controlId = $policyDef.Properties.Metadata.additionalMetadataId
                
                if ($controlId) {
                    if (-not $report.ControlMapping.ContainsKey($controlId)) {
                        $report.ControlMapping[$controlId] = @{
                            PolicyName = $policyDef.Properties.DisplayName
                            NonCompliantCount = 0
                            Resources = @()
                        }
                    }
                    
                    $report.ControlMapping[$controlId].NonCompliantCount++
                    $report.ControlMapping[$controlId].Resources += $state.ResourceId
                }
            }
            
            $report.NonCompliantResources += @{
                ResourceId = $state.ResourceId
                PolicyName = $state.PolicyDefinitionName
                Timestamp = $state.Timestamp
            }
        }
        
        # Generate recommendations based on findings
        if ($report.OverallCompliance -lt 80) {
            $report.Recommendations += "Overall compliance is below 80%. Review and remediate non-compliant resources."
        }
        
        if ($report.NonCompliantResources.Count -gt 20) {
            $report.Recommendations += "High number of non-compliant resources detected. Consider automated remediation."
        }
        
        # Check for missing initiatives
        $assignedInitiatives = Get-AzPolicyAssignment | Where-Object {
            $_.Properties.PolicyDefinitionId -like "*/policySetDefinitions/*"
        }
        
        $hasFedramp = $assignedInitiatives | Where-Object { 
            $_.Properties.DisplayName -like "*FedRAMP*" 
        }
        
        $hasNist = $assignedInitiatives | Where-Object { 
            $_.Properties.DisplayName -like "*NIST*" 
        }
        
        if (-not $hasFedramp) {
            $report.Recommendations += "FedRAMP policy initiative not assigned. Consider assigning for continuous compliance."
        }
        
        if (-not $hasNist) {
            $report.Recommendations += "NIST 800-53 policy initiative not assigned. Consider assigning for continuous compliance."
        }
        
    }
    catch {
        Write-Error "Failed to generate policy compliance report: $_"
    }
    
    return $report
}

function Enable-ContinuousCompliance {
    <#
    .SYNOPSIS
        Enables continuous compliance monitoring through Azure Policy
    .DESCRIPTION
        Sets up policy assignments, alerts, and automated remediation for ongoing compliance
    #>
    
    param(
        [string]$SubscriptionId,
        [string]$ContactEmail
    )
    
    Write-Host "Enabling continuous compliance monitoring..." -ForegroundColor Cyan
    
    try {
        # Step 1: Assign compliance policies
        Write-Host ""
        Write-Host "Step 1: Assigning compliance policy initiatives..." -ForegroundColor Yellow
        $assignments = New-CompliancePolicyAssignment -SubscriptionId $SubscriptionId -ComplianceFramework "Both"
        
        if (-not $assignments) {
            Write-Error "Failed to create policy assignments"
            return
        }
        
        # Step 2: Create action group for notifications
        Write-Host ""
        Write-Host "Step 2: Creating notification action group..." -ForegroundColor Yellow
        
        $actionGroup = New-AzActionGroup `
            -Name "ComplianceAlerts" `
            -ResourceGroupName "rg-compliance-monitoring" `
            -ShortName "Compliance" `
            -EmailReceiver @{
                Name = "ComplianceTeam"
                EmailAddress = $ContactEmail
                UseCommonAlertSchema = $true
            } -ErrorAction SilentlyContinue
            
        if ($actionGroup) {
            Write-Host "✓ Action group created for compliance notifications" -ForegroundColor Green
        }
        
        # Step 3: Create activity log alerts for policy events
        Write-Host ""
        Write-Host "Step 3: Creating compliance monitoring alerts..." -ForegroundColor Yellow
        
        $alertRule = New-AzActivityLogAlert `
            -Name "PolicyComplianceChanges" `
            -ResourceGroupName "rg-compliance-monitoring" `
            -Location "Global" `
            -Condition @{
                Field = "category"
                Equal = "Policy"
            } `
            -Action @{
                ActionGroupId = $actionGroup.Id
            } -ErrorAction SilentlyContinue
            
        if ($alertRule) {
            Write-Host "✓ Activity log alert created for policy compliance changes" -ForegroundColor Green
        }
        
        # Step 4: Enable automatic remediation
        Write-Host ""
        Write-Host "Step 4: Configuring automatic remediation..." -ForegroundColor Yellow
        
        foreach ($assignment in $assignments) {
            # Get policy definitions in the initiative
            $initiative = Get-AzPolicySetDefinition -Id $assignment.Properties.PolicyDefinitionId
            
            # Create remediation task for policies that support it
            $remediationCount = 0
            foreach ($policyRef in $initiative.Properties.PolicyDefinitions) {
                $policyDef = Get-AzPolicyDefinition -Id $policyRef.policyDefinitionId -ErrorAction SilentlyContinue
                
                if ($policyDef.Properties.PolicyRule.then.effect -in @("DeployIfNotExists", "Modify")) {
                    $remediation = Start-AzPolicyRemediation `
                        -Name "AutoRemediate-$(Get-Random -Maximum 9999)" `
                        -PolicyAssignmentId $assignment.PolicyAssignmentId `
                        -PolicyDefinitionReferenceId $policyRef.policyDefinitionReferenceId `
                        -ErrorAction SilentlyContinue
                        
                    if ($remediation) {
                        $remediationCount++
                    }
                }
            }
            
            Write-Host "✓ Created $remediationCount automatic remediation tasks for $($assignment.Properties.DisplayName)" -ForegroundColor Green
        }
        
        Write-Host ""
        Write-Host "Continuous compliance monitoring enabled successfully!" -ForegroundColor Green
        Write-Host "You will receive notifications at: $ContactEmail" -ForegroundColor Green
        
    }
    catch {
        Write-Error "Failed to enable continuous compliance: $_"
    }
}

# Export functions
Export-ModuleMember -Function @(
    'Test-PolicyCompliance',
    'New-CompliancePolicyAssignment',
    'Get-PolicyComplianceReport',
    'Enable-ContinuousCompliance'
)