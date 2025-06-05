# Azure Cloud Shell Security Audit Tool

A comprehensive security audit script designed to run directly in Azure Cloud Shell, checking for compliance with FedRAMP and NIST 800-53 standards while assessing impacts to the CIA (Confidentiality, Integrity, Availability) triad.

## Overview

This tool helps security engineers:
- Assess Azure environments against FedRAMP High baseline controls
- Map findings to NIST 800-53 Rev 5 controls
- Evaluate security risks using the CIA triad framework
- Generate actionable remediation guidance
- Produce compliance reports in multiple formats

<img src="graphic.webp" width="500">

## Quick Start

1. Open [Azure Cloud Shell](https://shell.azure.com) (PowerShell mode)
2. Clone this repository:
   ```powershell
   git clone https://github.com/your-org/azure-cloud-shell-audit.git
   cd azure-cloud-shell-audit
   ```
3. Run the audit:
   ```powershell
   ./audit.ps1 -SubscriptionId "your-subscription-id"
   ```

## Features

### Security Control Coverage
- **Access Control (AC)**: Account management, access enforcement, least privilege, information flow
- **Audit & Accountability (AU)**: Audit events, log retention, monitoring, protection of audit information
- **System & Communications Protection (SC)**: Encryption, network security, boundary protection, transmission integrity
- **System & Information Integrity (SI)**: Flaw remediation, malicious code protection, integrity monitoring, input validation
- **Identification & Authentication (IA)**: Multi-factor authentication, identity management
- **Incident Response (IR)**: Incident handling, monitoring, reporting, response planning
- **Configuration Management (CM)**: Baseline configuration, change control, component inventory
- **Risk Assessment (RA)**: Risk assessment process, vulnerability scanning, risk response
- **Media Protection (MP)**: Secure media transport and handling

### CIA Triad Assessment
Each finding includes impact ratings for:
- **Confidentiality**: Risk of unauthorized data disclosure
- **Integrity**: Risk of unauthorized data modification
- **Availability**: Risk of service disruption

### Compliance Mapping
- FedRAMP High baseline controls
- NIST 800-53 Rev 5 control families
- Azure-specific implementation guidance

## Usage Examples

### Basic Audit
```powershell
# Audit entire subscription
./audit.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012"
```

### Targeted Control Assessment
```powershell
# Audit only Access Control and Audit families
./audit.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" -Controls "AC-*,AU-*"
```

### CIA-Focused Assessment
```powershell
# Focus on high confidentiality impact controls
./audit.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" -AssessmentType CIA
```

### Custom Output Format
```powershell
# Generate JSON report for automation
./audit.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" -OutputFormat JSON
```

### Azure Policy Integration
```powershell
# Check current policy compliance
./audit.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" -EnablePolicyCompliance

# Enable continuous compliance monitoring
./audit.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" -EnableContinuousCompliance -NotificationEmail "security@company.com"
```

### Advanced Usage Examples
```powershell
# Comprehensive audit with all features
./audit.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" `
           -Controls "*" `
           -OutputFormat HTML `
           -EnablePolicyCompliance `
           -EnableContinuousCompliance `
           -NotificationEmail "security@company.com"

# Quick security scan focusing on high-risk areas
./audit.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" `
           -Controls "AC-*,SC-*,SI-*" `
           -AssessmentType QuickScan
```

## Output Formats

- **HTML**: Interactive dashboard with findings and remediation (default)
- **JSON**: Machine-readable format for automation
- **CSV**: For spreadsheet analysis
- **Markdown**: For documentation and wikis

## Prerequisites

- Azure Cloud Shell (recommended) or PowerShell 7.0+
- Azure PowerShell modules (pre-installed in Cloud Shell)
- Reader access to target Azure subscription
- No external dependencies

## Report Structure

### Executive Summary
- Overall compliance status
- Critical findings count
- CIA impact distribution

### Technical Details
- Control-by-control assessment
- Evidence collected
- Specific Azure resource findings

### Remediation Plan
- Prioritized action items
- Implementation guidance
- Azure service recommendations

## Security Considerations

- **Read-Only Operations**: Script performs no modifications
- **No Credential Storage**: Uses Azure Cloud Shell authentication
- **Secure Output**: Sensitive data sanitized in reports
- **Rate Limiting**: Implements API call throttling

## Extending the Tool

### Adding New Controls
1. Add control definition to `config/control-definitions.json`
2. Implement check function in appropriate module under `modules/controls/`
3. Update control mapping in `modules/compliance/`

### Custom Compliance Frameworks
The tool supports adding custom compliance mappings:
- ISO 27001
- SOC 2
- PCI DSS
- CIS Azure Foundations Benchmark

## Troubleshooting

### Common Issues

1. **Authentication Errors**
   ```powershell
   Connect-AzAccount
   Set-AzContext -SubscriptionId "your-subscription-id"
   ```

2. **Permission Errors**
   - Ensure you have at least Reader role
   - For full assessment, Security Reader role recommended

3. **Module Not Found**
   - Run in Azure Cloud Shell for best compatibility
   - Or install required modules:
     ```powershell
     Install-Module -Name Az -Force
     ```

## Contributing

See [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for development roadmap and contribution guidelines.

## License

[Your License Here]

## Support

For issues and feature requests, please use the GitHub issue tracker.