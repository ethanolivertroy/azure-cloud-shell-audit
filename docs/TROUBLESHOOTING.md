# Troubleshooting Guide - Azure Cloud Shell Security Audit Tool

This guide helps resolve common issues when using the Azure Cloud Shell Security Audit Tool.

## Common Issues and Solutions

### Authentication and Authorization

#### Issue: "Not authenticated to Azure"
```powershell
Error: Not authenticated to Azure. Run Connect-AzAccount first.
```

**Solution:**
```powershell
# Connect to Azure
Connect-AzAccount

# Verify connection
Get-AzContext

# If using service principal
Connect-AzAccount -ServicePrincipal -Credential $credential -TenantId $tenantId
```

**Additional Steps:**
- Ensure you're in Azure Cloud Shell (recommended)
- Check internet connectivity if running locally
- Verify your Azure subscription is active

#### Issue: "Cannot access subscription"
```powershell
Error: Cannot access subscription: 12345678-1234-1234-1234-123456789012
```

**Solution:**
```powershell
# List available subscriptions
Get-AzSubscription

# Set correct subscription
Set-AzContext -SubscriptionId "your-subscription-id"

# Verify permissions
Get-AzRoleAssignment -SignInName (Get-AzContext).Account.Id
```

**Required Permissions:**
- Reader role (minimum)
- Security Reader role (recommended)
- Contributor role (for policy assignment features)

#### Issue: "Insufficient privileges for control assessment"
```powershell
Warning: Cannot verify role assignments - may have limited permissions
```

**Solution:**
1. **Check Current Roles:**
   ```powershell
   Get-AzRoleAssignment -SignInName (Get-AzContext).Account.Id
   ```

2. **Request Additional Permissions:**
   - Security Reader: For security-specific controls
   - Reader: For basic resource enumeration
   - Directory Reader (Azure AD): For user/group information

3. **Run Audit with Limited Scope:**
   ```powershell
   ./audit.ps1 -SubscriptionId "your-sub-id" -Controls "SC-*" -AssessmentType QuickScan
   ```

### Performance and Rate Limiting

#### Issue: "Rate limit exceeded"
```powershell
Warning: Rate limit reached. Waiting 42.3 seconds...
```

**Solution:**
1. **Use Configuration File:**
   ```json
   {
     "Performance": {
       "MaxCallsPerMinute": 200,
       "RetryDelayMs": 2000,
       "BatchSize": 25
     }
   }
   ```

2. **Run During Off-Peak Hours:**
   - Avoid peak business hours
   - Consider weekend execution for large environments

3. **Reduce Scope:**
   ```powershell
   # Focus on specific control families
   ./audit.ps1 -SubscriptionId "your-sub-id" -Controls "AC-*,SC-*"
   
   # Use QuickScan mode
   ./audit.ps1 -SubscriptionId "your-sub-id" -AssessmentType QuickScan
   ```

#### Issue: "Audit takes too long to complete"
```powershell
# Large environments timing out
```

**Solution:**
1. **Check Environment Size:**
   ```powershell
   # Count resources first
   (Get-AzResource).Count
   (Get-AzResourceGroup).Count
   ```

2. **Use Progressive Approach:**
   ```powershell
   # Start with critical controls
   ./audit.ps1 -SubscriptionId "your-sub-id" -Controls "AC-2,AC-3,SC-7,SI-2"
   
   # Then expand scope
   ./audit.ps1 -SubscriptionId "your-sub-id" -Controls "AC-*"
   ```

3. **Configure Timeout:**
   ```json
   {
     "Security": {
       "MaxExecutionTimeMinutes": 180
     }
   }
   ```

### Module and Dependency Issues

#### Issue: "Module not found: modules/core/auth.ps1"
```powershell
Warning: Module not found: /path/to/modules/core/auth.ps1
```

**Solution:**
1. **Verify File Structure:**
   ```powershell
   # Check if running from correct directory
   Get-Location
   
   # Verify module files exist
   Get-ChildItem -Recurse -Filter "*.ps1" | Select-Object Name, FullName
   ```

2. **Re-download Tool:**
   ```powershell
   # Clone fresh copy
   git clone https://github.com/your-org/azure-cloud-shell-audit.git
   cd azure-cloud-shell-audit
   ```

3. **Check File Permissions:**
   ```powershell
   # Ensure files are readable
   Get-Acl ./modules/core/auth.ps1
   ```

#### Issue: "Azure PowerShell modules not available"
```powershell
Error: Required module 'Az.Accounts' is not installed
```

**Solution in Azure Cloud Shell:**
```powershell
# Modules are pre-installed, verify they're loaded
Get-Module -ListAvailable Az.*

# If needed, import explicitly
Import-Module Az.Accounts, Az.Resources, Az.Security
```

**Solution in Local PowerShell:**
```powershell
# Install Azure PowerShell
Install-Module -Name Az -Force -AllowClobber

# Or update existing installation
Update-Module -Name Az
```

### Output and Reporting Issues

#### Issue: "Permission denied writing to output directory"
```powershell
Error: No write permission to output location
```

**Solution:**
```powershell
# Use different output directory
./audit.ps1 -SubscriptionId "your-sub-id" -OutputPath "./my-reports"

# Or use home directory
./audit.ps1 -SubscriptionId "your-sub-id" -OutputPath "~/audit-reports"

# Check current directory permissions
Test-Path -Path "." -PathType Container
```

#### Issue: "HTML report not generating properly"
```powershell
# Report file created but appears corrupted
```

**Solution:**
1. **Check Disk Space:**
   ```powershell
   Get-PSDrive
   ```

2. **Try Different Format:**
   ```powershell
   # Use JSON format instead
   ./audit.ps1 -SubscriptionId "your-sub-id" -OutputFormat JSON
   ```

3. **Check for Special Characters:**
   ```powershell
   # May be caused by special characters in resource names
   # Tool automatically sanitizes, but check logs for warnings
   ```

### Configuration Issues

#### Issue: "Invalid configuration file format"
```powershell
Error: Failed to load configuration: ConvertFrom-Json failed
```

**Solution:**
1. **Validate JSON:**
   ```powershell
   # Test JSON validity
   Get-Content ./audit-config.json | ConvertFrom-Json
   ```

2. **Create New Config:**
   ```powershell
   # Generate default configuration
   ./audit.ps1 -CreateDefaultConfig
   ```

3. **Common JSON Errors:**
   - Missing commas between properties
   - Trailing commas
   - Unescaped quotes in strings
   - Incorrect boolean values (use true/false, not True/False)

#### Issue: "Email notifications not working"
```json
{
  "Notifications": {
    "EmailSettings": {
      "Enabled": true,
      "SmtpServer": "smtp.company.com",
      "From": "audit@company.com",
      "To": ["security@company.com"]
    }
  }
}
```

**Solution:**
1. **Test SMTP Connectivity:**
   ```powershell
   Test-NetConnection -ComputerName smtp.company.com -Port 587
   ```

2. **Check Authentication:**
   - Ensure SMTP server allows connections from Azure Cloud Shell
   - Consider using app passwords for Office 365
   - Verify firewall rules

3. **Use Alternative Methods:**
   ```powershell
   # Use webhook instead
   ./audit.ps1 -SubscriptionId "your-sub-id" -EnableWebhookNotification
   ```

### Control-Specific Issues

#### Issue: "False positives in security assessments"
```powershell
# Control shows "Fail" but configuration is actually correct
```

**Solution:**
1. **Review Specific Finding:**
   ```powershell
   # Run specific control only
   ./audit.ps1 -SubscriptionId "your-sub-id" -Controls "AC-2" -OutputFormat JSON
   ```

2. **Check Resource Scope:**
   - Tool may be checking different resources than expected
   - Verify resource names and types in output

3. **Report Issue:**
   - Create GitHub issue with specific details
   - Include sanitized output showing the false positive

#### Issue: "Controls marked as 'Manual' when they should be automated"
```powershell
Status: "Manual" - requires Azure AD Premium and Graph API access
```

**Solution:**
1. **Check License Requirements:**
   - Some controls require Azure AD Premium P1/P2
   - Conditional Access policies need Premium licenses

2. **Verify Graph Permissions:**
   ```powershell
   # Test Graph access
   Get-AzADUser | Select-Object -First 1
   ```

3. **Accept Manual Review:**
   - Some controls inherently require manual verification
   - Use findings as checklist for manual review

## Advanced Troubleshooting

### Debug Mode

Enable detailed logging for troubleshooting:

```powershell
# Enable verbose output
./audit.ps1 -SubscriptionId "your-sub-id" -Verbose

# Enable debug logging
$DebugPreference = "Continue"
./audit.ps1 -SubscriptionId "your-sub-id"
```

### Connectivity Testing

Test Azure service connectivity:

```powershell
# Test basic Azure connectivity
Test-NetConnection -ComputerName management.azure.com -Port 443

# Test Graph API access
Test-NetConnection -ComputerName graph.microsoft.com -Port 443

# Check proxy settings (if applicable)
[System.Net.WebRequest]::DefaultWebProxy
```

### Memory and Resource Issues

For large environments:

```powershell
# Monitor memory usage
Get-Process -Name pwsh | Select-Object WorkingSet64

# Increase memory limit if needed (local PowerShell)
$env:POWERSHELL_TELEMETRY_OPTOUT = 1
```

### Log Analysis

Check audit logs for detailed error information:

```powershell
# View recent audit logs
Get-Content ./logs/AuditLog_*.log | Select-Object -Last 50

# Search for specific errors
Select-String -Path ./logs/*.log -Pattern "Error|Exception"
```

## Getting Help

### Self-Service Resources

1. **Check Documentation:**
   - README.md for basic usage
   - IMPLEMENTATION_PLAN.md for technical details
   - Examples directory for usage patterns

2. **Review Configuration:**
   ```powershell
   # Validate current configuration
   ./audit.ps1 -ValidateConfig -ConfigPath ./audit-config.json
   ```

3. **Test Environment:**
   ```powershell
   # Run connectivity tests
   ./audit.ps1 -TestConnectivity -SubscriptionId "your-sub-id"
   ```

### Community Support

1. **GitHub Issues:**
   - Search existing issues first
   - Provide detailed error messages
   - Include environment information

2. **Discussion Forums:**
   - Check project discussions
   - Community Q&A
   - Feature requests

### Enterprise Support

For enterprise deployments:
- Consider commercial support options
- Engage Azure support for platform issues
- Consult security professionals for complex compliance requirements

## Preventive Measures

### Pre-Audit Checklist

Before running audits:
- [ ] Verify Azure authentication
- [ ] Check subscription permissions
- [ ] Test output directory write access
- [ ] Validate configuration file (if used)
- [ ] Confirm available time for large environments

### Best Practices

1. **Start Small:** Begin with single control families
2. **Test First:** Use QuickScan mode for initial testing
3. **Monitor Resources:** Watch for rate limiting in large environments
4. **Regular Updates:** Keep the tool updated
5. **Backup Configs:** Save working configurations

### Monitoring

Set up monitoring for production use:
- Track audit execution times
- Monitor for authentication failures
- Alert on unexpected errors
- Review audit coverage regularly

---

If you continue to experience issues not covered in this guide, please create a detailed issue report including:
- Error messages (sanitized)
- Environment details
- Steps to reproduce
- Expected vs. actual behavior