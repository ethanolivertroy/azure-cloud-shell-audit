# Security and Input Validation Module
# Provides comprehensive input validation, sanitization, and security hardening

$script:SecurityConfig = @{
    MaxInputLength = 1000
    AllowedFileExtensions = @('.json', '.csv', '.txt', '.md', '.html')
    BlockedPatterns = @(
        '<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>',  # Script tags
        'javascript:',                                        # JavaScript URLs
        'data:text\/html',                                   # Data URLs
        'vbscript:',                                         # VBScript
        '\$\([^)]*\)',                                      # PowerShell subexpressions
        '`[^`]*`',                                          # PowerShell backticks
        '&[^;]+;'                                           # HTML entities
    )
    TrustedDomains = @(
        'management.azure.com',
        'graph.microsoft.com',
        'login.microsoftonline.com'
    )
}

function Test-InputSecurity {
    <#
    .SYNOPSIS
        Validates and sanitizes user input for security
    .DESCRIPTION
        Comprehensive input validation to prevent injection attacks and malicious input
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Input,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet('SubscriptionId', 'Email', 'Path', 'ControlFamily', 'ResourceId', 'General')]
        [string]$InputType,
        
        [switch]$AllowEmpty
    )
    
    $validationResult = @{
        IsValid = $false
        SanitizedInput = $Input
        SecurityIssues = @()
        Warnings = @()
    }
    
    # Check for empty input
    if ([string]::IsNullOrWhiteSpace($Input)) {
        if ($AllowEmpty) {
            $validationResult.IsValid = $true
            return $validationResult
        }
        else {
            $validationResult.SecurityIssues += "Input cannot be empty"
            return $validationResult
        }
    }
    
    # Check input length
    if ($Input.Length -gt $script:SecurityConfig.MaxInputLength) {
        $validationResult.SecurityIssues += "Input exceeds maximum length of $($script:SecurityConfig.MaxInputLength) characters"
        return $validationResult
    }
    
    # Check for malicious patterns
    foreach ($pattern in $script:SecurityConfig.BlockedPatterns) {
        if ($Input -match $pattern) {
            $validationResult.SecurityIssues += "Input contains potentially malicious pattern: $pattern"
            return $validationResult
        }
    }
    
    # Type-specific validation
    switch ($InputType) {
        'SubscriptionId' {
            if ($Input -notmatch '^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$') {
                $validationResult.SecurityIssues += "Invalid subscription ID format"
                return $validationResult
            }
        }
        
        'Email' {
            if ($Input -notmatch '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') {
                $validationResult.SecurityIssues += "Invalid email format"
                return $validationResult
            }
            
            # Additional email security checks
            if ($Input.Length -gt 254) {
                $validationResult.SecurityIssues += "Email address too long"
                return $validationResult
            }
        }
        
        'Path' {
            # Sanitize file paths
            $sanitizedPath = $Input -replace '[<>:"|?*]', '_'
            
            # Check for path traversal attempts
            if ($Input -match '\.\.[/\\]') {
                $validationResult.SecurityIssues += "Path traversal attempt detected"
                return $validationResult
            }
            
            # Check file extension if it's a file path
            if ($Input -match '\.[a-zA-Z0-9]+$') {
                $extension = [System.IO.Path]::GetExtension($Input).ToLower()
                if ($extension -notin $script:SecurityConfig.AllowedFileExtensions) {
                    $validationResult.SecurityIssues += "File extension '$extension' not allowed"
                    return $validationResult
                }
            }
            
            $validationResult.SanitizedInput = $sanitizedPath
        }
        
        'ControlFamily' {
            # Validate control family format (e.g., AC-*, SC-7, IR-*)
            if ($Input -notmatch '^[A-Z]{2,3}(-[0-9]+|\-\*|\*)$') {
                $validationResult.SecurityIssues += "Invalid control family format. Expected format: XX-* or XX-N"
                return $validationResult
            }
        }
        
        'ResourceId' {
            # Validate Azure resource ID format
            if ($Input -notmatch '^/subscriptions/[a-fA-F0-9-]{36}/') {
                $validationResult.SecurityIssues += "Invalid Azure resource ID format"
                return $validationResult
            }
            
            # Check for suspicious characters in resource ID
            if ($Input -match '[<>&"\'`]') {
                $validationResult.SecurityIssues += "Resource ID contains suspicious characters"
                return $validationResult
            }
        }
        
        'General' {
            # General sanitization for text input
            $sanitizedInput = $Input -replace '[<>&"\'`]', ''
            $validationResult.SanitizedInput = $sanitizedInput
            
            if ($sanitizedInput -ne $Input) {
                $validationResult.Warnings += "Input was sanitized to remove potentially dangerous characters"
            }
        }
    }
    
    # Final security check - ensure no PowerShell injection
    if ($Input -match '\$\(|\`|\||\;|\&\&|\|\|') {
        $validationResult.SecurityIssues += "Input contains PowerShell injection patterns"
        return $validationResult
    }
    
    $validationResult.IsValid = $true
    return $validationResult
}

function Test-EnvironmentSecurity {
    <#
    .SYNOPSIS
        Validates the execution environment for security
    .DESCRIPTION
        Checks the PowerShell execution environment for security issues
    #>
    
    $securityChecks = @{
        IsCloudShell = $false
        ExecutionPolicy = $null
        ModuleIntegrity = $true
        EnvironmentIssues = @()
        SecurityWarnings = @()
        Recommendations = @()
    }
    
    try {
        # Check if running in Azure Cloud Shell
        if ($env:AZUREPS_HOST_ENVIRONMENT -eq "cloud-shell") {
            $securityChecks.IsCloudShell = $true
            $securityChecks.Recommendations += "Running in Azure Cloud Shell (recommended for security)"
        }
        else {
            $securityChecks.SecurityWarnings += "Not running in Azure Cloud Shell - ensure environment is secure"
        }
        
        # Check PowerShell execution policy
        $executionPolicy = Get-ExecutionPolicy
        $securityChecks.ExecutionPolicy = $executionPolicy
        
        if ($executionPolicy -in @('Unrestricted', 'Bypass')) {
            $securityChecks.SecurityWarnings += "PowerShell execution policy is too permissive: $executionPolicy"
            $securityChecks.Recommendations += "Consider using RemoteSigned or Restricted execution policy"
        }
        
        # Check for PowerShell version
        $psVersion = $PSVersionTable.PSVersion
        if ($psVersion.Major -lt 7) {
            $securityChecks.SecurityWarnings += "PowerShell version $psVersion may have security vulnerabilities"
            $securityChecks.Recommendations += "Upgrade to PowerShell 7+ for latest security features"
        }
        
        # Check for module integrity (simplified)
        $azModules = Get-Module -ListAvailable -Name Az.*
        if ($azModules.Count -eq 0) {
            $securityChecks.EnvironmentIssues += "Azure PowerShell modules not found"
            $securityChecks.ModuleIntegrity = $false
        }
        
        # Check for suspicious environment variables
        $suspiciousVars = @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY')
        foreach ($var in $suspiciousVars) {
            if (Get-ChildItem env: | Where-Object Name -eq $var) {
                $securityChecks.SecurityWarnings += "Proxy environment variable detected: $var"
                $securityChecks.Recommendations += "Verify proxy settings are legitimate"
            }
        }
        
        # Check current user context
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        if ($currentUser.IsSystem) {
            $securityChecks.SecurityWarnings += "Running as SYSTEM account"
        }
        
        # Check for transcript logging
        if (-not (Get-Command Start-Transcript -ErrorAction SilentlyContinue)) {
            $securityChecks.SecurityWarnings += "PowerShell transcript logging not available"
        }
        
    }
    catch {
        $securityChecks.EnvironmentIssues += "Failed to complete environment security check: $($_.Exception.Message)"
    }
    
    return $securityChecks
}

function Protect-SensitiveData {
    <#
    .SYNOPSIS
        Sanitizes output to prevent sensitive data exposure
    .DESCRIPTION
        Removes or masks sensitive information from audit outputs
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [object]$Data,
        
        [string[]]$SensitivePatterns = @(
            '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email addresses
            '\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',              # Credit card numbers
            '\b\d{3}-\d{2}-\d{4}\b',                                # SSN
            '\b[A-Fa-f0-9]{32}\b',                                  # MD5 hashes
            '\b[A-Fa-f0-9]{40}\b',                                  # SHA1 hashes
            '\b[A-Za-z0-9+/]{20,}={0,2}\b'                          # Base64 encoded strings
        )
    )
    
    # Convert data to JSON for processing
    $jsonData = $Data | ConvertTo-Json -Depth 10 -Compress
    
    # Apply sanitization patterns
    foreach ($pattern in $SensitivePatterns) {
        $jsonData = $jsonData -replace $pattern, '[REDACTED]'
    }
    
    # Mask Azure subscription IDs (except the one being audited)
    $jsonData = $jsonData -replace '\b[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}\b', '[SUBSCRIPTION-ID]'
    
    # Convert back to object
    try {
        return $jsonData | ConvertFrom-Json
    }
    catch {
        # If conversion fails, return original data with warning
        Write-Warning "Failed to sanitize data - returning original"
        return $Data
    }
}

function Test-OutputSecurity {
    <#
    .SYNOPSIS
        Validates output files and directories for security
    .DESCRIPTION
        Ensures output locations are safe and don't overwrite critical files
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [switch]$CreateIfNotExists
    )
    
    $outputValidation = @{
        IsValid = $false
        SecurityIssues = @()
        Warnings = @()
        SanitizedPath = $OutputPath
    }
    
    try {
        # Validate the output path
        $pathValidation = Test-InputSecurity -Input $OutputPath -InputType 'Path'
        
        if (-not $pathValidation.IsValid) {
            $outputValidation.SecurityIssues += $pathValidation.SecurityIssues
            return $outputValidation
        }
        
        $outputValidation.SanitizedPath = $pathValidation.SanitizedInput
        
        # Resolve the full path
        $fullPath = Resolve-Path $outputValidation.SanitizedPath -ErrorAction SilentlyContinue
        if (-not $fullPath) {
            if ($CreateIfNotExists) {
                # Try to create the directory
                $parentDir = Split-Path $outputValidation.SanitizedPath -Parent
                if ($parentDir -and -not (Test-Path $parentDir)) {
                    New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
                }
            }
            else {
                $outputValidation.SecurityIssues += "Output path does not exist: $OutputPath"
                return $outputValidation
            }
        }
        
        # Check for dangerous locations
        $dangerousPaths = @(
            "$env:SYSTEMROOT",
            "$env:PROGRAMFILES",
            "$env:PROGRAMFILES(X86)",
            "$env:WINDIR"
        )
        
        foreach ($dangerousPath in $dangerousPaths) {
            if ($dangerousPath -and $outputValidation.SanitizedPath.StartsWith($dangerousPath, [StringComparison]::OrdinalIgnoreCase)) {
                $outputValidation.SecurityIssues += "Cannot write to system directory: $dangerousPath"
                return $outputValidation
            }
        }
        
        # Check for existing critical files
        $criticalFiles = @('audit.ps1', 'password.txt', 'config.json', 'secrets.json')
        $fileName = Split-Path $outputValidation.SanitizedPath -Leaf
        
        if ($fileName -in $criticalFiles) {
            $outputValidation.Warnings += "Output filename matches critical file: $fileName"
        }
        
        # Check permissions
        if (Test-Path $outputValidation.SanitizedPath) {
            try {
                # Test write access
                $testFile = Join-Path (Split-Path $outputValidation.SanitizedPath -Parent) "test_$(Get-Random).tmp"
                "test" | Out-File $testFile -ErrorAction Stop
                Remove-Item $testFile -ErrorAction SilentlyContinue
            }
            catch {
                $outputValidation.SecurityIssues += "No write permission to output location"
                return $outputValidation
            }
        }
        
        $outputValidation.IsValid = $true
        
    }
    catch {
        $outputValidation.SecurityIssues += "Output validation failed: $($_.Exception.Message)"
    }
    
    return $outputValidation
}

function Enable-SecurityAuditing {
    <#
    .SYNOPSIS
        Enables security auditing for the current session
    .DESCRIPTION
        Sets up security logging and monitoring for the audit process
    #>
    
    param(
        [string]$AuditLogPath = "./logs/security-audit.log",
        [switch]$EnableTranscript
    )
    
    try {
        # Create security audit log directory
        $logDir = Split-Path $AuditLogPath -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        
        # Start security logging
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $securityEvent = @{
            Timestamp = $timestamp
            Event = "SecurityAuditingEnabled"
            User = $env:USERNAME ?? $env:USER ?? "Unknown"
            Environment = $env:AZUREPS_HOST_ENVIRONMENT ?? "Unknown"
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        }
        
        $securityEvent | ConvertTo-Json -Compress | Add-Content $AuditLogPath
        
        # Enable PowerShell transcript if requested
        if ($EnableTranscript) {
            $transcriptPath = Join-Path $logDir "transcript-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
            Start-Transcript -Path $transcriptPath -Force
            Write-Host "Security transcript enabled: $transcriptPath" -ForegroundColor Green
        }
        
        Write-AuditLog -Message "Security auditing enabled" -Level "Info"
        return $true
        
    }
    catch {
        Write-Warning "Failed to enable security auditing: $($_.Exception.Message)"
        return $false
    }
}

function Disable-SecurityAuditing {
    <#
    .SYNOPSIS
        Disables security auditing and cleans up
    #>
    
    try {
        # Stop transcript if running
        try {
            Stop-Transcript
        }
        catch {
            # Transcript wasn't running
        }
        
        Write-AuditLog -Message "Security auditing disabled" -Level "Info"
        
    }
    catch {
        Write-Warning "Failed to disable security auditing: $($_.Exception.Message)"
    }
}

# Export functions
Export-ModuleMember -Function @(
    'Test-InputSecurity',
    'Test-EnvironmentSecurity',
    'Protect-SensitiveData',
    'Test-OutputSecurity',
    'Enable-SecurityAuditing',
    'Disable-SecurityAuditing'
)