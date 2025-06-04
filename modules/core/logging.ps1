# Logging Module
# Provides logging functionality for audit operations

$script:LogPath = $null
$script:LogLevel = "Info"

function Initialize-AuditLog {
    <#
    .SYNOPSIS
        Initializes the audit logging system
    .DESCRIPTION
        Sets up logging configuration and creates log file
    #>
    
    param(
        [string]$Path = "./logs",
        [ValidateSet("Debug", "Info", "Warning", "Error")]
        [string]$Level = "Info"
    )
    
    $script:LogLevel = $Level
    
    # Create logs directory if it doesn't exist
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    
    # Create log filename with timestamp
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $logFile = "AuditLog_${timestamp}.log"
    $script:LogPath = Join-Path $Path $logFile
    
    # Write initial log entry
    Write-AuditLog -Message "Azure Security Audit Log Initialized" -Level "Info"
    Write-AuditLog -Message "Log Level: $Level" -Level "Info"
}

function Write-AuditLog {
    <#
    .SYNOPSIS
        Writes a message to the audit log
    .DESCRIPTION
        Logs messages with timestamp and severity level
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [ValidateSet("Debug", "Info", "Warning", "Error")]
        [string]$Level = "Info",
        
        [string]$ControlId = "",
        
        [hashtable]$Context = @{}
    )
    
    # Check if logging is initialized
    if (-not $script:LogPath) {
        Initialize-AuditLog
    }
    
    # Check log level
    $levels = @{
        "Debug" = 0
        "Info" = 1
        "Warning" = 2
        "Error" = 3
    }
    
    if ($levels[$Level] -lt $levels[$script:LogLevel]) {
        return
    }
    
    # Create log entry
    $logEntry = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Level = $Level
        Message = $Message
        ControlId = $ControlId
        Context = $Context
        User = $env:USER ?? "Unknown"
        CloudShell = $env:AZUREPS_HOST_ENVIRONMENT ?? "Unknown"
    }
    
    # Format log message
    $logMessage = "$($logEntry.Timestamp) [$($logEntry.Level)]"
    if ($ControlId) {
        $logMessage += " [$ControlId]"
    }
    $logMessage += " - $Message"
    
    # Add context if provided
    if ($Context.Count -gt 0) {
        $contextJson = $Context | ConvertTo-Json -Compress
        $logMessage += " | Context: $contextJson"
    }
    
    # Write to log file
    try {
        $logMessage | Out-File -FilePath $script:LogPath -Append -Encoding UTF8
    }
    catch {
        Write-Warning "Failed to write to log file: $_"
    }
    
    # Also write to verbose stream for debugging
    Write-Verbose $logMessage
}

function Get-AuditLogPath {
    <#
    .SYNOPSIS
        Returns the current audit log file path
    #>
    
    return $script:LogPath
}

function Write-ControlCheckStart {
    <#
    .SYNOPSIS
        Logs the start of a control check
    #>
    
    param(
        [string]$ControlId,
        [string]$ControlName
    )
    
    Write-AuditLog -Message "Starting control check: $ControlName" -Level "Info" -ControlId $ControlId
}

function Write-ControlCheckResult {
    <#
    .SYNOPSIS
        Logs the result of a control check
    #>
    
    param(
        [string]$ControlId,
        [string]$Status,
        [string[]]$Findings
    )
    
    $context = @{
        Status = $Status
        FindingsCount = $Findings.Count
    }
    
    $level = switch ($Status) {
        "Pass" { "Info" }
        "Fail" { "Warning" }
        "Error" { "Error" }
        default { "Info" }
    }
    
    Write-AuditLog -Message "Control check completed with status: $Status" -Level $level -ControlId $ControlId -Context $context
}

function Write-AuditSummary {
    <#
    .SYNOPSIS
        Writes audit summary to log
    #>
    
    param(
        [hashtable]$Summary
    )
    
    Write-AuditLog -Message "Audit completed" -Level "Info" -Context $Summary
    Write-AuditLog -Message "Log file location: $script:LogPath" -Level "Info"
}

# Export functions
Export-ModuleMember -Function @(
    'Initialize-AuditLog',
    'Write-AuditLog',
    'Get-AuditLogPath',
    'Write-ControlCheckStart',
    'Write-ControlCheckResult',
    'Write-AuditSummary'
)