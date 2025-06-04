#!/usr/bin/env pwsh
#Requires -Version 7.0

<#
.SYNOPSIS
    Unit tests for IAM Control modules
.DESCRIPTION
    Comprehensive tests for Identity and Access Management controls
.NOTES
    Uses Pester testing framework
#>

BeforeAll {
    # Import the modules to test
    $projectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . "$projectRoot/modules/controls/iam.ps1"
    . "$projectRoot/modules/core/logging.ps1"
    
    # Mock Azure commands for testing
    Mock Get-AzADUser { return @() }
    Mock Get-AzRoleAssignment { return @() }
    Mock Get-AzRoleDefinition { return @() }
    Mock Get-AzPolicyAssignment { return @() }
    Mock Write-AuditLog { }
}

Describe "Test-AccountManagement" {
    Context "When no users exist" {
        BeforeEach {
            Mock Get-AzADUser { return @() }
            Mock Get-AzRoleAssignment { return @() }
        }
        
        It "Should return Pass status with no stale accounts" {
            $result = Test-AccountManagement -SubscriptionId "test-sub-id"
            
            $result.ControlId | Should -Be "AC-2"
            $result.Status | Should -Be "Pass"
            $result.Findings | Should -Contain "No stale user accounts detected"
        }
    }
    
    Context "When guest users exist" {
        BeforeEach {
            Mock Get-AzADUser { 
                return @(
                    @{ UserPrincipalName = "user1@domain.com"; UserType = "Member" },
                    @{ UserPrincipalName = "guest@external.com"; UserType = "Guest" }
                )
            }
        }
        
        It "Should identify guest users" {
            $result = Test-AccountManagement -SubscriptionId "test-sub-id"
            
            $result.Findings | Should -Contain "Found 1 guest users in the directory"
            $result.Remediation | Should -Contain "Review guest user access and ensure business justification"
        }
    }
    
    Context "When Azure AD is not accessible" {
        BeforeEach {
            Mock Get-AzADUser { throw "Access denied" }
        }
        
        It "Should handle errors gracefully" {
            $result = Test-AccountManagement -SubscriptionId "test-sub-id"
            
            $result.Status | Should -Be "Error"
            $result.Findings | Should -Match "Failed to assess account management.*"
        }
    }
}

Describe "Test-AccessEnforcement" {
    Context "When custom roles have excessive permissions" {
        BeforeEach {
            Mock Get-AzRoleDefinition -ParameterFilter { $Custom } {
                return @(
                    @{
                        Name = "Custom Overprivileged Role"
                        Actions = @("*", "Microsoft.Authorization/*")
                    }
                )
            }
            Mock Get-AzRoleAssignment {
                return @(
                    @{ RoleDefinitionName = "Owner"; SignInName = "user1@domain.com" },
                    @{ RoleDefinitionName = "Contributor"; SignInName = "user2@domain.com" }
                )
            }
        }
        
        It "Should identify risky custom roles" {
            $result = Test-AccessEnforcement -SubscriptionId "test-sub-id"
            
            $result.Status | Should -Be "Fail"
            $result.Findings | Should -Contain "Custom role 'Custom Overprivileged Role' has overly broad permissions"
            $result.Remediation | Should -Contain "Review and restrict permissions for custom role 'Custom Overprivileged Role'"
        }
    }
    
    Context "When subscription-level assignments are minimal" {
        BeforeEach {
            Mock Get-AzRoleDefinition -ParameterFilter { $Custom } { return @() }
            Mock Get-AzRoleAssignment {
                return @(
                    @{ RoleDefinitionName = "Owner"; SignInName = "user1@domain.com" }
                )
            }
        }
        
        It "Should pass with minimal high-privilege assignments" {
            $result = Test-AccessEnforcement -SubscriptionId "test-sub-id"
            
            $result.Status | Should -Be "Pass"
            $result.Findings | Should -Contain "Access enforcement controls are properly configured"
        }
    }
}

Describe "Test-LeastPrivilege" {
    Context "When users have multiple high-privilege roles" {
        BeforeEach {
            Mock Get-AzRoleAssignment {
                return @(
                    @{ 
                        ObjectType = "User"
                        SignInName = "overprivileged@domain.com"
                        RoleDefinitionName = "Owner"
                    },
                    @{ 
                        ObjectType = "User"
                        SignInName = "overprivileged@domain.com"
                        RoleDefinitionName = "User Access Administrator"
                    },
                    @{ 
                        ObjectType = "User"
                        SignInName = "normal@domain.com"
                        RoleDefinitionName = "Contributor"
                    }
                )
            }
        }
        
        It "Should identify least privilege violations" {
            $result = Test-LeastPrivilege -SubscriptionId "test-sub-id"
            
            $result.Status | Should -Be "Fail"
            $result.Findings | Should -Contain "User 'overprivileged@domain.com' has multiple high-privilege roles: Owner, User Access Administrator"
            $result.Remediation | Should -Contain "Review and consolidate role assignments following least privilege principle"
        }
    }
    
    Context "When users have single appropriate roles" {
        BeforeEach {
            Mock Get-AzRoleAssignment {
                return @(
                    @{ 
                        ObjectType = "User"
                        SignInName = "user1@domain.com"
                        RoleDefinitionName = "Contributor"
                    },
                    @{ 
                        ObjectType = "User"
                        SignInName = "user2@domain.com"
                        RoleDefinitionName = "Reader"
                    }
                )
            }
        }
        
        It "Should pass with appropriate role assignments" {
            $result = Test-LeastPrivilege -SubscriptionId "test-sub-id"
            
            $result.Status | Should -Be "Pass"
            $result.Findings | Should -Contain "No least privilege violations detected"
        }
    }
}

Describe "Test-MultifactorAuthentication" {
    Context "Always manual verification required" {
        It "Should return Manual status for MFA check" {
            $result = Test-MultifactorAuthentication -SubscriptionId "test-sub-id"
            
            $result.ControlId | Should -Be "IA-2"
            $result.Status | Should -Be "Manual"
            $result.Findings | Should -Contain "MFA configuration requires Azure AD Premium and Graph API access"
            $result.Remediation | Should -Contain "Enable MFA for all users using Conditional Access policies"
        }
    }
}

Describe "Control Result Structure Validation" {
    It "Should return properly structured results for all IAM controls" {
        $controls = @(
            Test-AccountManagement -SubscriptionId "test-sub-id",
            Test-AccessEnforcement -SubscriptionId "test-sub-id",
            Test-LeastPrivilege -SubscriptionId "test-sub-id",
            Test-MultifactorAuthentication -SubscriptionId "test-sub-id"
        )
        
        foreach ($control in $controls) {
            # Validate required properties
            $control.ControlId | Should -Not -BeNullOrEmpty
            $control.ControlName | Should -Not -BeNullOrEmpty
            $control.FedRAMPLevel | Should -Be "High"
            $control.NISTFamily | Should -Not -BeNullOrEmpty
            $control.Status | Should -BeIn @("Pass", "Fail", "Manual", "Error")
            
            # Validate CIA Impact structure
            $control.CIAImpact | Should -Not -BeNull
            $control.CIAImpact.Confidentiality | Should -BeIn @("High", "Medium", "Low")
            $control.CIAImpact.Integrity | Should -BeIn @("High", "Medium", "Low")
            $control.CIAImpact.Availability | Should -BeIn @("High", "Medium", "Low")
            
            # Validate arrays
            $control.Findings | Should -BeOfType [System.Object[]]
            $control.Evidence | Should -BeOfType [System.Object[]]
            $control.Remediation | Should -BeOfType [System.Object[]]
        }
    }
}

Describe "Error Handling" {
    Context "When Azure commands fail" {
        BeforeEach {
            Mock Get-AzRoleAssignment { throw "Service unavailable" }
        }
        
        It "Should handle Azure service failures gracefully" {
            $result = Test-AccessEnforcement -SubscriptionId "test-sub-id"
            
            $result.Status | Should -Be "Error"
            $result.Findings | Should -Match "Failed to assess access enforcement.*"
        }
    }
}

Describe "CIA Impact Validation" {
    It "Should have appropriate CIA impact ratings for IAM controls" {
        $accountMgmt = Test-AccountManagement -SubscriptionId "test-sub-id"
        $accessEnforce = Test-AccessEnforcement -SubscriptionId "test-sub-id"
        $leastPriv = Test-LeastPrivilege -SubscriptionId "test-sub-id"
        $mfa = Test-MultifactorAuthentication -SubscriptionId "test-sub-id"
        
        # Account Management should have high confidentiality impact
        $accountMgmt.CIAImpact.Confidentiality | Should -Be "High"
        
        # Access Enforcement should have high confidentiality and integrity impact
        $accessEnforce.CIAImpact.Confidentiality | Should -Be "High"
        $accessEnforce.CIAImpact.Integrity | Should -Be "High"
        
        # Least Privilege should have high confidentiality and integrity impact
        $leastPriv.CIAImpact.Confidentiality | Should -Be "High"
        $leastPriv.CIAImpact.Integrity | Should -Be "High"
        
        # MFA should have high confidentiality and integrity impact
        $mfa.CIAImpact.Confidentiality | Should -Be "High"
        $mfa.CIAImpact.Integrity | Should -Be "High"
    }
}