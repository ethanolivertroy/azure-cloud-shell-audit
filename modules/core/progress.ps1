# Progress Indicator Module
# Provides visual progress tracking for audit operations

$script:ProgressState = @{
    TotalSteps = 0
    CurrentStep = 0
    StartTime = $null
    CurrentOperation = ""
}

function Initialize-AuditProgress {
    <#
    .SYNOPSIS
        Initializes the progress tracking system
    #>
    
    param(
        [int]$TotalSteps
    )
    
    $script:ProgressState.TotalSteps = $TotalSteps
    $script:ProgressState.CurrentStep = 0
    $script:ProgressState.StartTime = Get-Date
    
    # Clear any existing progress
    Write-Progress -Activity "Azure Security Audit" -Completed -ErrorAction SilentlyContinue
}

function Update-AuditProgress {
    <#
    .SYNOPSIS
        Updates the progress bar with current operation status
    #>
    
    param(
        [string]$Operation,
        [string]$Status = "In Progress",
        [int]$Step = -1
    )
    
    if ($Step -ge 0) {
        $script:ProgressState.CurrentStep = $Step
    }
    else {
        $script:ProgressState.CurrentStep++
    }
    
    $script:ProgressState.CurrentOperation = $Operation
    
    # Calculate percentage
    $percentComplete = 0
    if ($script:ProgressState.TotalSteps -gt 0) {
        $percentComplete = [math]::Round(($script:ProgressState.CurrentStep / $script:ProgressState.TotalSteps) * 100, 0)
    }
    
    # Calculate elapsed time and ETA
    $elapsed = (Get-Date) - $script:ProgressState.StartTime
    $elapsedString = "{0:mm}:{0:ss}" -f $elapsed
    
    $eta = ""
    if ($script:ProgressState.CurrentStep -gt 0 -and $percentComplete -lt 100) {
        $avgSecondsPerStep = $elapsed.TotalSeconds / $script:ProgressState.CurrentStep
        $remainingSteps = $script:ProgressState.TotalSteps - $script:ProgressState.CurrentStep
        $remainingSeconds = $avgSecondsPerStep * $remainingSteps
        $etaTime = (Get-Date).AddSeconds($remainingSeconds)
        $eta = " | ETA: {0:HH:mm:ss}" -f $etaTime
    }
    
    # Update progress bar
    Write-Progress -Activity "Azure Security Audit" `
                   -Status "$Status - $Operation (Step $($script:ProgressState.CurrentStep) of $($script:ProgressState.TotalSteps))" `
                   -PercentComplete $percentComplete `
                   -CurrentOperation "Elapsed: $elapsedString$eta"
}

function Complete-AuditProgress {
    <#
    .SYNOPSIS
        Completes the progress tracking
    #>
    
    Write-Progress -Activity "Azure Security Audit" -Completed
    
    $elapsed = (Get-Date) - $script:ProgressState.StartTime
    $totalTime = "{0:mm}:{0:ss}" -f $elapsed
    
    Write-Host ""
    Write-Host "Audit completed in $totalTime" -ForegroundColor Green
}

function Show-ControlProgress {
    <#
    .SYNOPSIS
        Shows progress for individual control checks
    #>
    
    param(
        [string]$ControlId,
        [string]$ControlName,
        [int]$Current,
        [int]$Total
    )
    
    $subPercent = 0
    if ($Total -gt 0) {
        $subPercent = [math]::Round(($Current / $Total) * 100, 0)
    }
    
    Write-Progress -Activity "Checking $ControlId" `
                   -Status "$ControlName" `
                   -PercentComplete $subPercent `
                   -Id 2 `
                   -ParentId 0 `
                   -CurrentOperation "Sub-check $Current of $Total"
}

function Complete-ControlProgress {
    <#
    .SYNOPSIS
        Completes the control progress indicator
    #>
    
    Write-Progress -Activity "Control Check" -Id 2 -Completed -ErrorAction SilentlyContinue
}

function Show-Spinner {
    <#
    .SYNOPSIS
        Shows a spinner for operations without known progress
    #>
    
    param(
        [string]$Message = "Processing..."
    )
    
    $spinChars = '|', '/', '-', '\'
    $i = 0
    
    # This would need to be called in a loop or background job
    # For now, just show a simple message
    Write-Host "`r$Message $($spinChars[$i % 4])" -NoNewline
}

# Export functions
Export-ModuleMember -Function @(
    'Initialize-AuditProgress',
    'Update-AuditProgress',
    'Complete-AuditProgress',
    'Show-ControlProgress',
    'Complete-ControlProgress',
    'Show-Spinner'
)