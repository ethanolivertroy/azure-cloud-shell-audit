# Configuration Management Module
# Provides configuration file support and multi-subscription capabilities

$script:DefaultConfig = @{
    General = @{
        OutputPath = "./reports"
        OutputFormat = "HTML"
        AssessmentType = "Full"
        EnablePolicyCompliance = $false
        EnableContinuousCompliance = $false
        MaxConcurrentSubscriptions = 5
        EnableDetailedLogging = $true
    }
    Controls = @{
        DefaultControls = "*"
        SkippedControls = @()
        CustomControlMappings = @{}
    }
    Security = @{
        EnableInputValidation = $true
        EnableAuditTrail = $true
        SanitizeOutput = $true
        MaxExecutionTimeMinutes = 120
    }
    Performance = @{
        MaxCallsPerMinute = 300
        RetryDelayMs = 1000
        MaxRetries = 3
        BatchSize = 50
    }
    Notifications = @{
        EmailSettings = @{
            Enabled = $false
            SmtpServer = ""
            From = ""
            To = @()
        }
        WebhookSettings = @{
            Enabled = $false
            Url = ""
            Headers = @{}
        }
    }
    Enterprise = @{
        EnableAuditTrail = $true
        AuditTrailPath = "./audit-trails"
        EnableSIEMIntegration = $false
        SIEMEndpoint = ""
        EnableScheduling = $false
    }
}

function Import-AuditConfiguration {
    <#
    .SYNOPSIS
        Imports configuration from a file
    .DESCRIPTION
        Loads configuration settings from JSON file with validation
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigPath,
        
        [switch]$ValidateOnly
    )
    
    $configResult = @{
        IsValid = $false
        Configuration = $null
        ValidationErrors = @()
        ValidationWarnings = @()
    }
    
    try {
        # Validate file path
        $pathValidation = Test-InputSecurity -Input $ConfigPath -InputType 'Path'
        if (-not $pathValidation.IsValid) {
            $configResult.ValidationErrors += $pathValidation.SecurityIssues
            return $configResult
        }
        
        # Check if file exists
        if (-not (Test-Path $ConfigPath)) {
            $configResult.ValidationErrors += "Configuration file not found: $ConfigPath"
            return $configResult
        }
        
        # Read and parse JSON
        $configContent = Get-Content $ConfigPath -Raw -ErrorAction Stop
        $userConfig = $configContent | ConvertFrom-Json -AsHashtable -ErrorAction Stop
        
        # Merge with default configuration
        $mergedConfig = Merge-Configuration -DefaultConfig $script:DefaultConfig -UserConfig $userConfig
        
        # Validate configuration
        $validation = Test-ConfigurationSecurity -Configuration $mergedConfig
        $configResult.ValidationErrors += $validation.SecurityIssues
        $configResult.ValidationWarnings += $validation.Warnings
        
        if ($validation.IsValid) {
            $configResult.IsValid = $true
            $configResult.Configuration = $mergedConfig
            
            if (-not $ValidateOnly) {
                # Apply configuration
                Apply-Configuration -Configuration $mergedConfig
                Write-AuditLog -Message "Configuration loaded from: $ConfigPath" -Level "Info"
            }
        }
        
    }
    catch {
        $configResult.ValidationErrors += "Failed to load configuration: $($_.Exception.Message)"
    }
    
    return $configResult
}

function Export-AuditConfiguration {
    <#
    .SYNOPSIS
        Exports current configuration to a file
    .DESCRIPTION
        Saves current configuration settings to JSON file
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigPath,
        
        [hashtable]$Configuration = $script:DefaultConfig,
        
        [switch]$IncludeComments
    )
    
    try {
        # Validate output path
        $pathValidation = Test-OutputSecurity -OutputPath $ConfigPath -CreateIfNotExists
        if (-not $pathValidation.IsValid) {
            throw "Invalid output path: $($pathValidation.SecurityIssues -join ', ')"
        }
        
        # Sanitize configuration before export
        $sanitizedConfig = Protect-SensitiveData -Data $Configuration
        
        if ($IncludeComments) {
            # Add comments to the JSON
            $configWithComments = Add-ConfigurationComments -Configuration $sanitizedConfig
            $configWithComments | ConvertTo-Json -Depth 10 | Out-File $pathValidation.SanitizedPath -Encoding UTF8
        }
        else {
            $sanitizedConfig | ConvertTo-Json -Depth 10 | Out-File $pathValidation.SanitizedPath -Encoding UTF8
        }
        
        Write-AuditLog -Message "Configuration exported to: $($pathValidation.SanitizedPath)" -Level "Info"
        return $true
        
    }
    catch {
        Write-Error "Failed to export configuration: $($_.Exception.Message)"
        return $false
    }
}

function New-DefaultConfiguration {
    <#
    .SYNOPSIS
        Creates a new default configuration file
    .DESCRIPTION
        Generates a template configuration file with comments
    #>
    
    param(
        [string]$OutputPath = "./audit-config.json"
    )
    
    $configTemplate = Add-ConfigurationComments -Configuration $script:DefaultConfig
    
    try {
        Export-AuditConfiguration -ConfigPath $OutputPath -Configuration $configTemplate -IncludeComments
        Write-Host "Default configuration created: $OutputPath" -ForegroundColor Green
        Write-Host "Edit this file to customize your audit settings." -ForegroundColor Yellow
    }
    catch {
        Write-Error "Failed to create default configuration: $($_.Exception.Message)"
    }
}

function Test-ConfigurationSecurity {
    <#
    .SYNOPSIS
        Validates configuration for security issues
    .DESCRIPTION
        Checks configuration settings for potential security problems
    #>
    
    param([hashtable]$Configuration)
    
    $validation = @{
        IsValid = $true
        SecurityIssues = @()
        Warnings = @()
    }
    
    # Validate email settings
    if ($Configuration.Notifications.EmailSettings.Enabled) {
        $emailTo = $Configuration.Notifications.EmailSettings.To
        foreach ($email in $emailTo) {
            $emailValidation = Test-InputSecurity -Input $email -InputType 'Email'
            if (-not $emailValidation.IsValid) {
                $validation.SecurityIssues += "Invalid email address: $email"
                $validation.IsValid = $false
            }
        }
    }
    
    # Validate webhook URLs
    if ($Configuration.Notifications.WebhookSettings.Enabled) {
        $webhookUrl = $Configuration.Notifications.WebhookSettings.Url
        if ($webhookUrl -and -not ($webhookUrl -match '^https://')) {
            $validation.SecurityIssues += "Webhook URL must use HTTPS"
            $validation.IsValid = $false
        }
    }
    
    # Validate paths
    $paths = @(
        $Configuration.General.OutputPath,
        $Configuration.Enterprise.AuditTrailPath
    )
    
    foreach ($path in $paths) {
        if ($path) {
            $pathValidation = Test-InputSecurity -Input $path -InputType 'Path'
            if (-not $pathValidation.IsValid) {
                $validation.SecurityIssues += "Invalid path: $path"
                $validation.IsValid = $false
            }
        }
    }
    
    # Validate performance settings
    if ($Configuration.Performance.MaxCallsPerMinute -gt 1000) {
        $validation.Warnings += "High API call rate may trigger throttling"
    }
    
    if ($Configuration.Security.MaxExecutionTimeMinutes -gt 240) {
        $validation.Warnings += "Long execution time may cause timeouts"
    }
    
    # Validate control settings
    if ($Configuration.Controls.DefaultControls -eq "*" -and $Configuration.General.AssessmentType -eq "QuickScan") {
        $validation.Warnings += "QuickScan with all controls may still take significant time"
    }
    
    return $validation
}

function Start-MultiSubscriptionAudit {
    <#
    .SYNOPSIS
        Runs audit across multiple Azure subscriptions
    .DESCRIPTION
        Executes security audit across multiple subscriptions with parallel processing
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$SubscriptionIds,
        
        [hashtable]$Configuration = $script:DefaultConfig,
        
        [int]$MaxConcurrent = 5,
        
        [switch]$ContinueOnError
    )
    
    $auditResults = @{
        StartTime = Get-Date
        EndTime = $null
        TotalSubscriptions = $SubscriptionIds.Count
        CompletedSubscriptions = 0
        FailedSubscriptions = 0
        Results = @{}
        Errors = @{}
        Summary = @{
            TotalControls = 0
            PassedControls = 0
            FailedControls = 0
            CriticalFindings = 0
        }
    }
    
    Write-Host "Starting multi-subscription audit for $($SubscriptionIds.Count) subscription(s)..." -ForegroundColor Cyan
    Write-Host "Max concurrent audits: $MaxConcurrent" -ForegroundColor Yellow
    Write-Host ""
    
    # Validate subscriptions first
    $validSubscriptions = @()
    foreach ($subId in $SubscriptionIds) {
        $validation = Test-InputSecurity -Input $subId -InputType 'SubscriptionId'
        if ($validation.IsValid) {
            $validSubscriptions += $subId
        }
        else {
            $auditResults.Errors[$subId] = "Invalid subscription ID format"
            $auditResults.FailedSubscriptions++
        }
    }
    
    if ($validSubscriptions.Count -eq 0) {
        throw "No valid subscription IDs provided"
    }
    
    # Process subscriptions in batches
    $processed = 0
    $batches = @()
    
    for ($i = 0; $i -lt $validSubscriptions.Count; $i += $MaxConcurrent) {
        $batchEnd = [Math]::Min($i + $MaxConcurrent - 1, $validSubscriptions.Count - 1)
        $batches += ,@($validSubscriptions[$i..$batchEnd])
    }
    
    foreach ($batch in $batches) {
        Write-Host "Processing batch of $($batch.Count) subscription(s)..." -ForegroundColor Yellow
        
        # Start parallel jobs for this batch
        $jobs = @()
        
        foreach ($subId in $batch) {
            $jobScript = {
                param($SubscriptionId, $ModulePath, $Configuration)
                
                # Import required modules in job context
                . "$ModulePath/audit.ps1"
                
                try {
                    # Run the audit
                    $result = Start-AzureSecurityAudit -SubscriptionId $SubscriptionId -Configuration $Configuration
                    return @{
                        Success = $true
                        SubscriptionId = $SubscriptionId
                        Result = $result
                    }
                }
                catch {
                    return @{
                        Success = $false
                        SubscriptionId = $SubscriptionId
                        Error = $_.Exception.Message
                    }
                }
            }
            
            $job = Start-Job -ScriptBlock $jobScript -ArgumentList $subId, $PSScriptRoot, $Configuration
            $jobs += @{
                Job = $job
                SubscriptionId = $subId
            }
        }
        
        # Wait for batch to complete
        Write-Host "Waiting for batch to complete..." -ForegroundColor Gray
        
        foreach ($jobInfo in $jobs) {
            $job = $jobInfo.Job
            $subId = $jobInfo.SubscriptionId
            
            # Wait for job with timeout
            $timeoutMinutes = $Configuration.Security.MaxExecutionTimeMinutes
            $completed = Wait-Job -Job $job -Timeout ($timeoutMinutes * 60)
            
            if ($completed) {
                $jobResult = Receive-Job -Job $job
                
                if ($jobResult.Success) {
                    $auditResults.Results[$subId] = $jobResult.Result
                    $auditResults.CompletedSubscriptions++
                    
                    # Update summary
                    $subResult = $jobResult.Result
                    $auditResults.Summary.TotalControls += $subResult.Summary.TotalControls
                    $auditResults.Summary.PassedControls += $subResult.Summary.PassedControls
                    $auditResults.Summary.FailedControls += $subResult.Summary.FailedControls
                    $auditResults.Summary.CriticalFindings += $subResult.Summary.CriticalFindings
                    
                    Write-Host "✓ Completed audit for subscription: $subId" -ForegroundColor Green
                }
                else {
                    $auditResults.Errors[$subId] = $jobResult.Error
                    $auditResults.FailedSubscriptions++
                    Write-Host "✗ Failed audit for subscription: $subId - $($jobResult.Error)" -ForegroundColor Red
                    
                    if (-not $ContinueOnError) {
                        Write-Host "Stopping multi-subscription audit due to error" -ForegroundColor Red
                        break
                    }
                }
            }
            else {
                $auditResults.Errors[$subId] = "Audit timed out after $timeoutMinutes minutes"
                $auditResults.FailedSubscriptions++
                Write-Host "✗ Timeout for subscription: $subId" -ForegroundColor Red
                
                # Stop the timed-out job
                Stop-Job -Job $job
            }
            
            # Clean up job
            Remove-Job -Job $job -Force
        }
        
        Write-Host ""
    }
    
    $auditResults.EndTime = Get-Date
    $duration = $auditResults.EndTime - $auditResults.StartTime
    
    Write-Host "Multi-subscription audit completed!" -ForegroundColor Cyan
    Write-Host "Duration: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor White
    Write-Host "Successful: $($auditResults.CompletedSubscriptions)" -ForegroundColor Green
    Write-Host "Failed: $($auditResults.FailedSubscriptions)" -ForegroundColor Red
    
    return $auditResults
}

function Merge-Configuration {
    <#
    .SYNOPSIS
        Merges user configuration with default configuration
    .DESCRIPTION
        Deep merges configuration hashtables, user settings override defaults
    #>
    
    param(
        [hashtable]$DefaultConfig,
        [hashtable]$UserConfig
    )
    
    $merged = $DefaultConfig.Clone()
    
    foreach ($key in $UserConfig.Keys) {
        if ($merged.ContainsKey($key)) {
            if ($merged[$key] -is [hashtable] -and $UserConfig[$key] -is [hashtable]) {
                # Recursively merge nested hashtables
                $merged[$key] = Merge-Configuration -DefaultConfig $merged[$key] -UserConfig $UserConfig[$key]
            }
            else {
                # Override with user value
                $merged[$key] = $UserConfig[$key]
            }
        }
        else {
            # Add new user setting
            $merged[$key] = $UserConfig[$key]
        }
    }
    
    return $merged
}

function Apply-Configuration {
    <#
    .SYNOPSIS
        Applies configuration settings to the audit system
    .DESCRIPTION
        Configures modules based on loaded configuration
    #>
    
    param([hashtable]$Configuration)
    
    # Apply error handling configuration
    if (Get-Command Initialize-ErrorHandling -ErrorAction SilentlyContinue) {
        Initialize-ErrorHandling -MaxCallsPerMinute $Configuration.Performance.MaxCallsPerMinute `
                                -RetryDelayMs $Configuration.Performance.RetryDelayMs `
                                -MaxRetries $Configuration.Performance.MaxRetries
    }
    
    # Apply security configuration
    if (Get-Command Enable-SecurityAuditing -ErrorAction SilentlyContinue -and $Configuration.Security.EnableAuditTrail) {
        Enable-SecurityAuditing
    }
    
    # Apply logging configuration
    if (Get-Command Initialize-AuditLog -ErrorAction SilentlyContinue -and $Configuration.General.EnableDetailedLogging) {
        Initialize-AuditLog -Level "Info"
    }
    
    Write-AuditLog -Message "Configuration applied successfully" -Level "Info"
}

function Add-ConfigurationComments {
    <#
    .SYNOPSIS
        Adds helpful comments to configuration for template generation
    .DESCRIPTION
        Enhances configuration with documentation for user guidance
    #>
    
    param([hashtable]$Configuration)
    
    # This is a simplified version - in a real implementation,
    # you would add JSON comments or create a documented template
    $enhanced = $Configuration.Clone()
    $enhanced["_documentation"] = @{
        General = "Basic audit settings and output configuration"
        Controls = "Control family selection and customization"
        Security = "Security and validation settings"
        Performance = "Rate limiting and retry configuration"
        Notifications = "Email and webhook notification settings"
        Enterprise = "Advanced features for enterprise use"
    }
    
    return $enhanced
}

# Export functions
Export-ModuleMember -Function @(
    'Import-AuditConfiguration',
    'Export-AuditConfiguration',
    'New-DefaultConfiguration',
    'Test-ConfigurationSecurity',
    'Start-MultiSubscriptionAudit',
    'Merge-Configuration',
    'Apply-Configuration'
)