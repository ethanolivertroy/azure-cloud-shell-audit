# Authentication and Permission Module
# Handles Azure authentication and validates required permissions

function Test-AzureAuthentication {
    <#
    .SYNOPSIS
        Validates Azure authentication and permissions
    .DESCRIPTION
        Checks if the user is authenticated to Azure and has necessary read permissions
    #>
    
    try {
        $context = Get-AzContext
        if (-not $context) {
            throw "Not authenticated to Azure. Please run 'Connect-AzAccount' first."
        }
        
        Write-Verbose "Authenticated as: $($context.Account.Id)"
        Write-Verbose "Subscription: $($context.Subscription.Name) ($($context.Subscription.Id))"
        
        return $true
    }
    catch {
        Write-Error "Authentication check failed: $_"
        return $false
    }
}

function Test-RequiredPermissions {
    <#
    .SYNOPSIS
        Validates that the user has required read permissions
    .DESCRIPTION
        Checks for necessary RBAC permissions to perform security audits
    #>
    
    param(
        [string]$SubscriptionId
    )
    
    $requiredPermissions = @(
        "Microsoft.Authorization/*/read",
        "Microsoft.Security/*/read",
        "Microsoft.Resources/subscriptions/resourceGroups/read",
        "Microsoft.Compute/*/read",
        "Microsoft.Network/*/read",
        "Microsoft.Storage/*/read"
    )
    
    $hasPermissions = $true
    $missingPermissions = @()
    
    Write-Verbose "Checking required permissions..."
    
    # Get current user's role assignments
    try {
        $userId = (Get-AzContext).Account.Id
        $roleAssignments = Get-AzRoleAssignment -SignInName $userId -Scope "/subscriptions/$SubscriptionId" -ErrorAction SilentlyContinue
        
        if ($roleAssignments | Where-Object { $_.RoleDefinitionName -in @("Owner", "Contributor", "Reader", "Security Reader") }) {
            Write-Verbose "User has sufficient built-in roles"
            return @{
                HasPermissions = $true
                MissingPermissions = @()
            }
        }
    }
    catch {
        Write-Warning "Could not validate permissions: $_"
    }
    
    return @{
        HasPermissions = $hasPermissions
        MissingPermissions = $missingPermissions
    }
}