# Identity and Access Management (IAM) Control Checks
# Implements FedRAMP and NIST 800-53 IAM controls

function Test-IAMControls {
    <#
    .SYNOPSIS
        Performs comprehensive IAM security checks
    .DESCRIPTION
        Evaluates Azure IAM configuration against FedRAMP and NIST 800-53 controls
    #>
    
    param(
        [string]$SubscriptionId
    )
    
    $iamResults = @()
    
    # AC-2: Account Management
    $iamResults += Test-AccountManagement -SubscriptionId $SubscriptionId
    
    # AC-3: Access Enforcement
    $iamResults += Test-AccessEnforcement -SubscriptionId $SubscriptionId
    
    # AC-6: Least Privilege
    $iamResults += Test-LeastPrivilege -SubscriptionId $SubscriptionId
    
    # IA-2: Multi-Factor Authentication
    $iamResults += Test-MultifactorAuthentication -SubscriptionId $SubscriptionId
    
    return $iamResults
}

function Test-AccountManagement {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "AC-2"
        ControlName = "Account Management"
        FedRAMPLevel = "High"
        NISTFamily = "Access Control"
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
        # Check for orphaned accounts
        $allUsers = Get-AzADUser -ErrorAction SilentlyContinue
        $activeUsers = Get-AzRoleAssignment | Select-Object -ExpandProperty SignInName -Unique
        
        # Check for service principals without recent activity
        $servicePrincipals = Get-AzADServicePrincipal -ErrorAction SilentlyContinue
        
        # Analyze account lifecycle
        $staleAccounts = 0
        $noMFAAccounts = 0
        
        foreach ($user in $allUsers) {
            # Check last sign-in (would require Azure AD Premium in real implementation)
            # This is a simplified check
            if ($user.UserPrincipalName -notin $activeUsers) {
                $staleAccounts++
            }
        }
        
        if ($staleAccounts -eq 0) {
            $result.Status = "Pass"
            $result.Findings += "No stale user accounts detected"
        }
        else {
            $result.Status = "Fail"
            $result.Findings += "Found $staleAccounts potentially stale user accounts"
            $result.Remediation += "Review and remove inactive user accounts"
            $result.Remediation += "Implement automated account lifecycle management"
        }
        
        # Guest user check
        $guestUsers = $allUsers | Where-Object { $_.UserType -eq "Guest" }
        if ($guestUsers.Count -gt 0) {
            $result.Findings += "Found $($guestUsers.Count) guest users in the directory"
            $result.Remediation += "Review guest user access and ensure business justification"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess account management: $_"
    }
    
    return $result
}

function Test-AccessEnforcement {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "AC-3"
        ControlName = "Access Enforcement"
        FedRAMPLevel = "High"
        NISTFamily = "Access Control"
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
        # Check for custom roles with excessive permissions
        $customRoles = Get-AzRoleDefinition -Custom
        $riskyPermissions = @("*", "Microsoft.Authorization/*", "Microsoft.KeyVault/vaults/*")
        
        foreach ($role in $customRoles) {
            $hasRiskyPerms = $false
            foreach ($action in $role.Actions) {
                if ($action -in $riskyPermissions) {
                    $hasRiskyPerms = $true
                    break
                }
            }
            
            if ($hasRiskyPerms) {
                $result.Status = "Fail"
                $result.Findings += "Custom role '$($role.Name)' has overly broad permissions"
                $result.Remediation += "Review and restrict permissions for custom role '$($role.Name)'"
            }
        }
        
        # Check for role assignments at subscription level
        $subLevelAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$SubscriptionId" | 
            Where-Object { $_.RoleDefinitionName -in @("Owner", "Contributor") }
        
        if ($subLevelAssignments.Count -gt 5) {
            $result.Findings += "Found $($subLevelAssignments.Count) high-privilege assignments at subscription level"
            $result.Remediation += "Minimize subscription-level privileged role assignments"
        }
        
        if ($result.Status -ne "Fail") {
            $result.Status = "Pass"
            $result.Findings += "Access enforcement controls are properly configured"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess access enforcement: $_"
    }
    
    return $result
}

function Test-LeastPrivilege {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "AC-6"
        ControlName = "Least Privilege"
        FedRAMPLevel = "High"
        NISTFamily = "Access Control"
        Status = "Unknown"
        CIAImpact = @{
            Confidentiality = "High"
            Integrity = "High"
            Availability = "Low"
        }
        Findings = @()
        Evidence = @()
        Remediation = @()
    }
    
    try {
        # Check for users with multiple high-privilege roles
        $roleAssignments = Get-AzRoleAssignment
        $userRoleCounts = @{}
        
        foreach ($assignment in $roleAssignments) {
            if ($assignment.ObjectType -eq "User") {
                if (-not $userRoleCounts.ContainsKey($assignment.SignInName)) {
                    $userRoleCounts[$assignment.SignInName] = @()
                }
                if ($assignment.RoleDefinitionName -in @("Owner", "Contributor", "User Access Administrator")) {
                    $userRoleCounts[$assignment.SignInName] += $assignment.RoleDefinitionName
                }
            }
        }
        
        $violationCount = 0
        foreach ($user in $userRoleCounts.Keys) {
            if ($userRoleCounts[$user].Count -gt 1) {
                $violationCount++
                $result.Findings += "User '$user' has multiple high-privilege roles: $($userRoleCounts[$user] -join ', ')"
            }
        }
        
        if ($violationCount -eq 0) {
            $result.Status = "Pass"
            $result.Findings += "No least privilege violations detected"
        }
        else {
            $result.Status = "Fail"
            $result.Remediation += "Review and consolidate role assignments following least privilege principle"
            $result.Remediation += "Use Azure PIM for just-in-time access to privileged roles"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess least privilege: $_"
    }
    
    return $result
}

function Test-MultifactorAuthentication {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "IA-2"
        ControlName = "Multi-Factor Authentication"
        FedRAMPLevel = "High"
        NISTFamily = "Identification and Authentication"
        Status = "Unknown"
        CIAImpact = @{
            Confidentiality = "High"
            Integrity = "High"
            Availability = "Low"
        }
        Findings = @()
        Evidence = @()
        Remediation = @()
    }
    
    try {
        # Check if Conditional Access policies exist (requires Azure AD Premium)
        # This is a simplified check - real implementation would use Graph API
        
        $result.Status = "Manual"
        $result.Findings += "MFA configuration requires Azure AD Premium and Graph API access"
        $result.Findings += "Manually verify that MFA is enforced for all users, especially privileged accounts"
        $result.Remediation += "Enable MFA for all users using Conditional Access policies"
        $result.Remediation += "Enforce MFA for all administrative actions"
        $result.Remediation += "Configure risk-based authentication policies"
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess MFA configuration: $_"
    }
    
    return $result
}