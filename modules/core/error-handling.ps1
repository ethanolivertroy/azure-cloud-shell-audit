# Error Handling and Resilience Module
# Provides comprehensive error handling, rate limiting, and recovery mechanisms

$script:RateLimitConfig = @{
    MaxCallsPerMinute = 300
    CallCount = 0
    LastResetTime = Get-Date
    RetryDelayMs = 1000
    MaxRetries = 3
}

$script:ErrorMetrics = @{
    TotalErrors = 0
    APIErrors = 0
    PermissionErrors = 0
    NetworkErrors = 0
    UnknownErrors = 0
}

function Initialize-ErrorHandling {
    <#
    .SYNOPSIS
        Initializes the error handling system
    .DESCRIPTION
        Sets up error tracking, rate limiting, and recovery mechanisms
    #>
    
    param(
        [int]$MaxCallsPerMinute = 300,
        [int]$RetryDelayMs = 1000,
        [int]$MaxRetries = 3
    )
    
    $script:RateLimitConfig.MaxCallsPerMinute = $MaxCallsPerMinute
    $script:RateLimitConfig.RetryDelayMs = $RetryDelayMs
    $script:RateLimitConfig.MaxRetries = $MaxRetries
    
    # Reset error metrics
    $script:ErrorMetrics.TotalErrors = 0
    $script:ErrorMetrics.APIErrors = 0
    $script:ErrorMetrics.PermissionErrors = 0
    $script:ErrorMetrics.NetworkErrors = 0
    $script:ErrorMetrics.UnknownErrors = 0
    
    Write-AuditLog -Message "Error handling system initialized" -Level "Info"
}

function Invoke-AzureCommandWithRetry {
    <#
    .SYNOPSIS
        Executes Azure commands with automatic retry and rate limiting
    .DESCRIPTION
        Wraps Azure PowerShell commands with resilience patterns
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [ScriptBlock]$Command,
        
        [string]$OperationName = "Azure Operation",
        
        [int]$MaxRetries = $script:RateLimitConfig.MaxRetries,
        
        [int]$RetryDelayMs = $script:RateLimitConfig.RetryDelayMs,
        
        [switch]$SuppressErrors
    )
    
    # Check rate limiting
    Test-RateLimit
    
    $attempt = 0
    $lastError = $null
    
    while ($attempt -lt $MaxRetries) {
        $attempt++
        
        try {
            Write-Verbose "Executing $OperationName (attempt $attempt/$MaxRetries)"
            
            # Execute the command
            $result = & $Command
            
            # Increment call count for rate limiting
            $script:RateLimitConfig.CallCount++
            
            # Log successful operation
            if ($attempt -gt 1) {
                Write-AuditLog -Message "$OperationName succeeded on attempt $attempt" -Level "Info"
            }
            
            return $result
        }
        catch {
            $lastError = $_
            $script:ErrorMetrics.TotalErrors++
            
            # Categorize the error
            $errorCategory = Get-ErrorCategory -Error $_
            
            switch ($errorCategory) {
                "RateLimit" {
                    Write-Warning "$OperationName: Rate limit exceeded, waiting..."
                    Start-Sleep -Milliseconds ($RetryDelayMs * 2)
                }
                "Network" {
                    $script:ErrorMetrics.NetworkErrors++
                    Write-Warning "$OperationName: Network error (attempt $attempt/$MaxRetries): $($_.Exception.Message)"
                    Start-Sleep -Milliseconds $RetryDelayMs
                }
                "Permission" {
                    $script:ErrorMetrics.PermissionErrors++
                    if (-not $SuppressErrors) {
                        Write-Warning "$OperationName: Permission denied - $($_.Exception.Message)"
                    }
                    # Don't retry permission errors
                    break
                }
                "API" {
                    $script:ErrorMetrics.APIErrors++
                    Write-Warning "$OperationName: API error (attempt $attempt/$MaxRetries): $($_.Exception.Message)"
                    Start-Sleep -Milliseconds $RetryDelayMs
                }
                default {
                    $script:ErrorMetrics.UnknownErrors++
                    Write-Warning "$OperationName: Unknown error (attempt $attempt/$MaxRetries): $($_.Exception.Message)"
                    Start-Sleep -Milliseconds $RetryDelayMs
                }
            }
            
            # Log the error
            Write-AuditLog -Message "$OperationName failed (attempt $attempt): $($_.Exception.Message)" -Level "Warning" -Context @{
                ErrorCategory = $errorCategory
                Attempt = $attempt
                MaxRetries = $MaxRetries
            }
        }
    }
    
    # All retries exhausted
    if (-not $SuppressErrors) {
        $errorMessage = "$OperationName failed after $MaxRetries attempts. Last error: $($lastError.Exception.Message)"
        Write-Error $errorMessage
        Write-AuditLog -Message $errorMessage -Level "Error"
    }
    
    return $null
}

function Test-RateLimit {
    <#
    .SYNOPSIS
        Checks and enforces rate limiting
    #>
    
    $now = Get-Date
    $minutesElapsed = ($now - $script:RateLimitConfig.LastResetTime).TotalMinutes
    
    # Reset counter every minute
    if ($minutesElapsed -ge 1) {
        $script:RateLimitConfig.CallCount = 0
        $script:RateLimitConfig.LastResetTime = $now
    }
    
    # Check if we're approaching the limit
    if ($script:RateLimitConfig.CallCount -ge $script:RateLimitConfig.MaxCallsPerMinute) {
        $sleepTime = 60 - ($minutesElapsed * 60)
        Write-Warning "Rate limit reached. Waiting $([math]::Round($sleepTime, 1)) seconds..."
        Start-Sleep -Seconds $sleepTime
        
        # Reset after sleeping
        $script:RateLimitConfig.CallCount = 0
        $script:RateLimitConfig.LastResetTime = Get-Date
    }
}

function Get-ErrorCategory {
    <#
    .SYNOPSIS
        Categorizes errors for appropriate handling
    #>
    
    param([System.Management.Automation.ErrorRecord]$Error)
    
    $errorMessage = $Error.Exception.Message.ToLower()
    $errorType = $Error.Exception.GetType().Name
    
    # Rate limiting errors
    if ($errorMessage -match "throttl|rate.?limit|too many requests" -or $Error.Exception.Response.StatusCode -eq 429) {
        return "RateLimit"
    }
    
    # Network errors
    if ($errorMessage -match "network|timeout|connection|dns|socket" -or 
        $errorType -match "HttpRequestException|SocketException|TimeoutException") {
        return "Network"
    }
    
    # Permission errors
    if ($errorMessage -match "forbidden|unauthorized|access.?denied|insufficient.?privilege" -or
        $Error.Exception.Response.StatusCode -in @(401, 403)) {
        return "Permission"
    }
    
    # API errors
    if ($errorMessage -match "bad.?request|not.?found|conflict|internal.?server" -or
        $errorType -match "CloudException|RestException") {
        return "API"
    }
    
    return "Unknown"
}

function Test-AzureConnectivity {
    <#
    .SYNOPSIS
        Tests Azure connectivity and authentication
    .DESCRIPTION
        Validates that the environment can connect to Azure services
    #>
    
    param(
        [string]$SubscriptionId
    )
    
    $connectivityResult = @{
        IsAuthenticated = $false
        HasSubscriptionAccess = $false
        HasRequiredPermissions = $false
        CanAccessResourceManager = $false
        CanAccessGraph = $false
        Errors = @()
        Warnings = @()
    }
    
    try {
        # Test authentication
        $context = Invoke-AzureCommandWithRetry -Command { Get-AzContext } -OperationName "Get Azure Context" -SuppressErrors
        
        if ($context) {
            $connectivityResult.IsAuthenticated = $true
            Write-AuditLog -Message "Azure authentication validated" -Level "Info"
        }
        else {
            $connectivityResult.Errors += "Not authenticated to Azure. Run Connect-AzAccount first."
            return $connectivityResult
        }
        
        # Test subscription access
        if ($SubscriptionId) {
            $subscription = Invoke-AzureCommandWithRetry -Command { 
                Get-AzSubscription -SubscriptionId $SubscriptionId 
            } -OperationName "Get Subscription" -SuppressErrors
            
            if ($subscription) {
                $connectivityResult.HasSubscriptionAccess = $true
                Write-AuditLog -Message "Subscription access validated: $($subscription.Name)" -Level "Info"
            }
            else {
                $connectivityResult.Errors += "Cannot access subscription: $SubscriptionId"
                return $connectivityResult
            }
        }
        
        # Test Resource Manager access
        $resourceGroups = Invoke-AzureCommandWithRetry -Command { 
            Get-AzResourceGroup | Select-Object -First 1 
        } -OperationName "Test Resource Manager Access" -SuppressErrors
        
        if ($resourceGroups) {
            $connectivityResult.CanAccessResourceManager = $true
        }
        else {
            $connectivityResult.Warnings += "Limited Resource Manager access detected"
        }
        
        # Test basic permissions
        $roleAssignments = Invoke-AzureCommandWithRetry -Command { 
            Get-AzRoleAssignment -SignInName $context.Account.Id -ErrorAction SilentlyContinue | Select-Object -First 1
        } -OperationName "Test Permissions" -SuppressErrors
        
        if ($roleAssignments) {
            $connectivityResult.HasRequiredPermissions = $true
        }
        else {
            $connectivityResult.Warnings += "Cannot verify role assignments - may have limited permissions"
        }
        
        # Test Graph access (for some controls)
        try {
            $users = Invoke-AzureCommandWithRetry -Command { 
                Get-AzADUser | Select-Object -First 1 
            } -OperationName "Test Graph Access" -SuppressErrors
            
            if ($users) {
                $connectivityResult.CanAccessGraph = $true
            }
        }
        catch {
            $connectivityResult.Warnings += "Limited Azure AD Graph access - some controls may be skipped"
        }
        
    }
    catch {
        $connectivityResult.Errors += "Connectivity test failed: $($_.Exception.Message)"
        Write-AuditLog -Message "Azure connectivity test failed: $($_.Exception.Message)" -Level "Error"
    }
    
    return $connectivityResult
}

function Get-ErrorMetrics {
    <#
    .SYNOPSIS
        Returns error metrics for the current session
    #>
    
    return $script:ErrorMetrics.PSObject.Copy()
}

function Reset-ErrorMetrics {
    <#
    .SYNOPSIS
        Resets error metrics
    #>
    
    $script:ErrorMetrics.TotalErrors = 0
    $script:ErrorMetrics.APIErrors = 0
    $script:ErrorMetrics.PermissionErrors = 0
    $script:ErrorMetrics.NetworkErrors = 0
    $script:ErrorMetrics.UnknownErrors = 0
}

function Test-LargeEnvironmentSupport {
    <#
    .SYNOPSIS
        Tests support for large Azure environments
    .DESCRIPTION
        Validates that the tool can handle environments with many resources
    #>
    
    param([string]$SubscriptionId)
    
    $environmentStats = @{
        ResourceCount = 0
        ResourceGroupCount = 0
        EstimatedAuditTime = 0
        PerformanceWarnings = @()
        Recommendations = @()
    }
    
    try {
        # Count resources efficiently
        $resourceGroups = Invoke-AzureCommandWithRetry -Command { 
            Get-AzResourceGroup 
        } -OperationName "Count Resource Groups"
        
        $environmentStats.ResourceGroupCount = $resourceGroups.Count
        
        # Sample resource count (avoid full enumeration)
        $sampleRG = $resourceGroups | Select-Object -First 5
        $avgResourcesPerRG = 0
        
        foreach ($rg in $sampleRG) {
            $resources = Invoke-AzureCommandWithRetry -Command { 
                Get-AzResource -ResourceGroupName $rg.ResourceGroupName 
            } -OperationName "Sample Resource Count"
            
            $avgResourcesPerRG += $resources.Count
        }
        
        if ($sampleRG.Count -gt 0) {
            $avgResourcesPerRG = $avgResourcesPerRG / $sampleRG.Count
            $environmentStats.ResourceCount = [math]::Round($avgResourcesPerRG * $resourceGroups.Count)
        }
        
        # Estimate audit time
        $baseTimePerResource = 0.1  # seconds
        $environmentStats.EstimatedAuditTime = [math]::Round(($environmentStats.ResourceCount * $baseTimePerResource) / 60, 1)
        
        # Generate performance warnings and recommendations
        if ($environmentStats.ResourceCount -gt 5000) {
            $environmentStats.PerformanceWarnings += "Large environment detected ($($environmentStats.ResourceCount) resources)"
            $environmentStats.Recommendations += "Consider using -AssessmentType QuickScan for faster results"
            $environmentStats.Recommendations += "Run audits during off-peak hours to avoid rate limiting"
        }
        
        if ($environmentStats.ResourceGroupCount -gt 100) {
            $environmentStats.PerformanceWarnings += "Many resource groups detected ($($environmentStats.ResourceGroupCount))"
            $environmentStats.Recommendations += "Consider auditing specific resource groups or control families"
        }
        
        if ($environmentStats.EstimatedAuditTime -gt 30) {
            $environmentStats.PerformanceWarnings += "Estimated audit time: $($environmentStats.EstimatedAuditTime) minutes"
            $environmentStats.Recommendations += "Use progress indicators to monitor long-running audits"
        }
        
    }
    catch {
        Write-AuditLog -Message "Failed to assess environment size: $($_.Exception.Message)" -Level "Warning"
    }
    
    return $environmentStats
}

# Export functions
Export-ModuleMember -Function @(
    'Initialize-ErrorHandling',
    'Invoke-AzureCommandWithRetry',
    'Test-RateLimit',
    'Get-ErrorCategory',
    'Test-AzureConnectivity',
    'Get-ErrorMetrics',
    'Reset-ErrorMetrics',
    'Test-LargeEnvironmentSupport'
)