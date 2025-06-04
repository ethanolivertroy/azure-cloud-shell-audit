# Network Security Control Checks
# Implements FedRAMP and NIST 800-53 network security controls

function Test-NetworkControls {
    <#
    .SYNOPSIS
        Performs comprehensive network security checks
    .DESCRIPTION
        Evaluates Azure network configuration against FedRAMP and NIST 800-53 controls
    #>
    
    param(
        [string]$SubscriptionId
    )
    
    $networkResults = @()
    
    # SC-7: Boundary Protection
    $networkResults += Test-BoundaryProtection -SubscriptionId $SubscriptionId
    
    # SC-7(3): Access Points
    $networkResults += Test-NetworkAccessPoints -SubscriptionId $SubscriptionId
    
    # SC-7(4): External Telecommunications Services
    $networkResults += Test-NetworkSegmentation -SubscriptionId $SubscriptionId
    
    # SC-8: Transmission Confidentiality and Integrity
    $networkResults += Test-TransmissionProtection -SubscriptionId $SubscriptionId
    
    # AC-4: Information Flow Enforcement
    $networkResults += Test-InformationFlowEnforcement -SubscriptionId $SubscriptionId
    
    return $networkResults
}

function Test-BoundaryProtection {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "SC-7"
        ControlName = "Boundary Protection"
        FedRAMPLevel = "High"
        NISTFamily = "System and Communications Protection"
        Status = "Unknown"
        CIAImpact = @{
            Confidentiality = "High"
            Integrity = "High"
            Availability = "High"
        }
        Findings = @()
        Evidence = @()
        Remediation = @()
    }
    
    try {
        # Check Network Security Groups
        $nsgs = Get-AzNetworkSecurityGroup
        $publicNSGs = @()
        $riskyRules = @()
        
        foreach ($nsg in $nsgs) {
            # Check for overly permissive inbound rules
            foreach ($rule in $nsg.SecurityRules) {
                if ($rule.Direction -eq "Inbound" -and 
                    $rule.Access -eq "Allow" -and
                    ($rule.SourceAddressPrefix -eq "*" -or $rule.SourceAddressPrefix -eq "Internet")) {
                    
                    # Check if it's a risky port
                    $riskyPorts = @(22, 3389, 445, 135, 139, 1433, 3306, 5432, 27017, 6379)
                    $destPort = $rule.DestinationPortRange
                    
                    if ($destPort -eq "*" -or $destPort -in $riskyPorts) {
                        $riskyRules += @{
                            NSG = $nsg.Name
                            Rule = $rule.Name
                            Port = $destPort
                            Source = $rule.SourceAddressPrefix
                        }
                    }
                }
            }
            
            # Check if NSG is associated with public-facing resources
            if ($nsg.NetworkInterfaces.Count -gt 0 -or $nsg.Subnets.Count -gt 0) {
                foreach ($nic in $nsg.NetworkInterfaces) {
                    $nicResource = Get-AzNetworkInterface -ResourceId $nic.Id -ErrorAction SilentlyContinue
                    if ($nicResource.IpConfigurations | Where-Object { $_.PublicIpAddress }) {
                        $publicNSGs += $nsg.Name
                    }
                }
            }
        }
        
        # Check Azure Firewall deployment
        $firewalls = Get-AzFirewall -ErrorAction SilentlyContinue
        $hasFirewall = $firewalls.Count -gt 0
        
        # Check Application Gateways with WAF
        $appGateways = Get-AzApplicationGateway -ErrorAction SilentlyContinue
        $wafEnabled = $appGateways | Where-Object { $_.WebApplicationFirewallConfiguration -and $_.WebApplicationFirewallConfiguration.Enabled }
        
        # Evaluate findings
        if ($riskyRules.Count -eq 0) {
            $result.Findings += "No overly permissive NSG rules detected"
        }
        else {
            $result.Status = "Fail"
            foreach ($risky in $riskyRules) {
                $result.Findings += "NSG '$($risky.NSG)' has risky rule '$($risky.Rule)' allowing traffic from '$($risky.Source)' to port '$($risky.Port)'"
            }
            $result.Remediation += "Review and restrict NSG rules to specific source IPs and ports"
            $result.Remediation += "Implement least-privilege network access policies"
        }
        
        if ($hasFirewall) {
            $result.Findings += "Azure Firewall deployed: $($firewalls.Count) instance(s) found"
        }
        else {
            $result.Findings += "No Azure Firewall instances found"
            $result.Remediation += "Consider deploying Azure Firewall for centralized network security"
        }
        
        if ($wafEnabled.Count -gt 0) {
            $result.Findings += "Web Application Firewall enabled on $($wafEnabled.Count) Application Gateway(s)"
        }
        else {
            $result.Findings += "No Web Application Firewall protection detected"
            $result.Remediation += "Enable WAF on Application Gateways for web application protection"
        }
        
        if ($result.Status -ne "Fail") {
            $result.Status = "Pass"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess boundary protection: $_"
    }
    
    return $result
}

function Test-NetworkAccessPoints {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "SC-7(3)"
        ControlName = "Access Points"
        FedRAMPLevel = "High"
        NISTFamily = "System and Communications Protection"
        Status = "Unknown"
        CIAImpact = @{
            Confidentiality = "High"
            Integrity = "Medium"
            Availability = "High"
        }
        Findings = @()
        Evidence = @()
        Remediation = @()
    }
    
    try {
        # Check number of public IPs
        $publicIps = Get-AzPublicIpAddress
        $result.Findings += "Found $($publicIps.Count) public IP addresses"
        
        # Check for unused public IPs
        $unusedIps = $publicIps | Where-Object { -not $_.IpConfiguration }
        if ($unusedIps.Count -gt 0) {
            $result.Status = "Fail"
            $result.Findings += "Found $($unusedIps.Count) unassociated public IP addresses"
            $result.Remediation += "Remove unused public IP addresses to reduce attack surface"
            foreach ($ip in $unusedIps) {
                $result.Evidence += "Unused IP: $($ip.Name) in resource group $($ip.ResourceGroupName)"
            }
        }
        
        # Check VPN Gateways
        $vpnGateways = Get-AzVirtualNetworkGateway -ErrorAction SilentlyContinue | Where-Object { $_.GatewayType -eq "Vpn" }
        if ($vpnGateways.Count -gt 0) {
            $result.Findings += "Found $($vpnGateways.Count) VPN Gateway(s) for secure access"
            
            # Check VPN configuration
            foreach ($vpn in $vpnGateways) {
                if ($vpn.VpnType -ne "RouteBased") {
                    $result.Findings += "VPN Gateway '$($vpn.Name)' uses policy-based routing (less secure)"
                    $result.Remediation += "Consider migrating to route-based VPN for better security"
                }
            }
        }
        
        # Check Bastion hosts
        $bastions = Get-AzBastion -ErrorAction SilentlyContinue
        if ($bastions.Count -gt 0) {
            $result.Findings += "Azure Bastion deployed for secure RDP/SSH access: $($bastions.Count) instance(s)"
        }
        else {
            $result.Findings += "No Azure Bastion hosts found"
            $result.Remediation += "Deploy Azure Bastion for secure administrative access without exposing VMs to internet"
        }
        
        if ($result.Status -ne "Fail") {
            $result.Status = "Pass"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess network access points: $_"
    }
    
    return $result
}

function Test-NetworkSegmentation {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "SC-7(4)"
        ControlName = "Network Segmentation"
        FedRAMPLevel = "High"
        NISTFamily = "System and Communications Protection"
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
        # Check Virtual Networks
        $vnets = Get-AzVirtualNetwork
        $result.Findings += "Found $($vnets.Count) Virtual Network(s)"
        
        # Check for proper subnet segmentation
        $totalSubnets = 0
        $smallSubnets = 0
        
        foreach ($vnet in $vnets) {
            $totalSubnets += $vnet.Subnets.Count
            
            # Check for subnet delegation (indicates service segregation)
            $delegatedSubnets = $vnet.Subnets | Where-Object { $_.Delegations.Count -gt 0 }
            if ($delegatedSubnets.Count -gt 0) {
                $result.Findings += "VNet '$($vnet.Name)' has $($delegatedSubnets.Count) delegated subnet(s) for service isolation"
            }
            
            # Check subnet sizes (smaller = better segmentation)
            foreach ($subnet in $vnet.Subnets) {
                $subnetSize = ($subnet.AddressPrefix -split '/')[1]
                if ($subnetSize -ge 24) {  # /24 or smaller
                    $smallSubnets++
                }
            }
        }
        
        if ($totalSubnets -gt 0) {
            $segmentationRatio = [math]::Round(($smallSubnets / $totalSubnets) * 100, 2)
            $result.Findings += "$segmentationRatio% of subnets are properly sized (/24 or smaller)"
            
            if ($segmentationRatio -lt 50) {
                $result.Status = "Fail"
                $result.Remediation += "Implement micro-segmentation with smaller subnets"
                $result.Remediation += "Use dedicated subnets for different application tiers"
            }
        }
        
        # Check for VNet peering (network isolation)
        $peerings = @()
        foreach ($vnet in $vnets) {
            if ($vnet.VirtualNetworkPeerings.Count -gt 0) {
                $peerings += $vnet.VirtualNetworkPeerings
            }
        }
        
        if ($peerings.Count -gt 0) {
            $result.Findings += "Found $($peerings.Count) VNet peering connection(s)"
            
            # Check if peerings have proper access controls
            foreach ($peering in $peerings) {
                if ($peering.AllowGatewayTransit -or $peering.UseRemoteGateways) {
                    $result.Findings += "VNet peering allows gateway transit - ensure this is intended"
                }
            }
        }
        
        # Check for Private Endpoints
        $privateEndpoints = Get-AzPrivateEndpoint -ErrorAction SilentlyContinue
        if ($privateEndpoints.Count -gt 0) {
            $result.Findings += "Found $($privateEndpoints.Count) Private Endpoint(s) for service isolation"
        }
        else {
            $result.Findings += "No Private Endpoints found"
            $result.Remediation += "Use Private Endpoints to access Azure services privately"
        }
        
        if ($result.Status -ne "Fail") {
            $result.Status = "Pass"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess network segmentation: $_"
    }
    
    return $result
}

function Test-TransmissionProtection {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "SC-8"
        ControlName = "Transmission Confidentiality and Integrity"
        FedRAMPLevel = "High"
        NISTFamily = "System and Communications Protection"
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
        # Check Application Gateways for SSL/TLS
        $appGateways = Get-AzApplicationGateway -ErrorAction SilentlyContinue
        $sslIssues = 0
        
        foreach ($appGw in $appGateways) {
            # Check SSL policies
            if ($appGw.SslPolicy) {
                if ($appGw.SslPolicy.PolicyType -eq "Predefined" -and $appGw.SslPolicy.PolicyName -ne "AppGwSslPolicy20170401S") {
                    $sslIssues++
                    $result.Findings += "Application Gateway '$($appGw.Name)' uses outdated SSL policy"
                }
            }
            else {
                $sslIssues++
                $result.Findings += "Application Gateway '$($appGw.Name)' has no SSL policy configured"
            }
            
            # Check for HTTP listeners (non-HTTPS)
            $httpListeners = $appGw.HttpListeners | Where-Object { $_.Protocol -eq "Http" }
            if ($httpListeners.Count -gt 0) {
                $sslIssues++
                $result.Findings += "Application Gateway '$($appGw.Name)' has $($httpListeners.Count) non-HTTPS listener(s)"
            }
        }
        
        # Check Storage Accounts for encryption in transit
        $storageAccounts = Get-AzStorageAccount
        $unencryptedTransit = 0
        
        foreach ($storage in $storageAccounts) {
            if (-not $storage.EnableHttpsTrafficOnly) {
                $unencryptedTransit++
                $result.Evidence += "Storage account '$($storage.StorageAccountName)' allows non-HTTPS traffic"
            }
        }
        
        if ($unencryptedTransit -gt 0) {
            $result.Status = "Fail"
            $result.Findings += "Found $unencryptedTransit storage account(s) allowing unencrypted traffic"
            $result.Remediation += "Enable 'Secure transfer required' on all storage accounts"
        }
        else {
            $result.Findings += "All storage accounts require HTTPS traffic"
        }
        
        # Check VPN Gateway encryption
        $vpnGateways = Get-AzVirtualNetworkGateway -ErrorAction SilentlyContinue | Where-Object { $_.GatewayType -eq "Vpn" }
        foreach ($vpn in $vpnGateways) {
            # Check VPN connections
            $connections = Get-AzVirtualNetworkGatewayConnection -ResourceGroupName $vpn.ResourceGroupName -ErrorAction SilentlyContinue
            foreach ($conn in $connections) {
                if ($conn.IpsecPolicies.Count -eq 0) {
                    $result.Findings += "VPN connection '$($conn.Name)' uses default IPsec policy (weaker encryption)"
                    $result.Remediation += "Configure custom IPsec policies with strong encryption algorithms"
                }
            }
        }
        
        if ($sslIssues -gt 0) {
            $result.Status = "Fail"
            $result.Remediation += "Update SSL/TLS policies to use TLS 1.2 minimum"
            $result.Remediation += "Disable HTTP listeners and redirect to HTTPS"
        }
        
        if ($result.Status -ne "Fail") {
            $result.Status = "Pass"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess transmission protection: $_"
    }
    
    return $result
}

function Test-InformationFlowEnforcement {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "AC-4"
        ControlName = "Information Flow Enforcement"
        FedRAMPLevel = "High"
        NISTFamily = "Access Control"
        Status = "Unknown"
        CIAImpact = @{
            Confidentiality = "High"
            Integrity = "Medium"
            Availability = "Medium"
        }
        Findings = @()
        Evidence = @()
        Remediation = @()
    }
    
    try {
        # Check for Azure Firewall rules
        $firewalls = Get-AzFirewall -ErrorAction SilentlyContinue
        
        if ($firewalls.Count -gt 0) {
            foreach ($fw in $firewalls) {
                # Check for application rules
                $appRuleCount = 0
                $networkRuleCount = 0
                
                if ($fw.ApplicationRuleCollections) {
                    $appRuleCount = ($fw.ApplicationRuleCollections | ForEach-Object { $_.Rules.Count } | Measure-Object -Sum).Sum
                }
                
                if ($fw.NetworkRuleCollections) {
                    $networkRuleCount = ($fw.NetworkRuleCollections | ForEach-Object { $_.Rules.Count } | Measure-Object -Sum).Sum
                }
                
                $result.Findings += "Firewall '$($fw.Name)' has $appRuleCount application rules and $networkRuleCount network rules"
                
                # Check for threat intelligence
                if ($fw.ThreatIntelMode -eq "Alert" -or $fw.ThreatIntelMode -eq "Deny") {
                    $result.Findings += "Firewall '$($fw.Name)' has threat intelligence enabled (mode: $($fw.ThreatIntelMode))"
                }
                else {
                    $result.Findings += "Firewall '$($fw.Name)' does not have threat intelligence enabled"
                    $result.Remediation += "Enable threat intelligence-based filtering on Azure Firewall"
                }
            }
        }
        else {
            $result.Findings += "No Azure Firewall deployed for centralized flow control"
            $result.Remediation += "Deploy Azure Firewall to enforce information flow policies"
        }
        
        # Check NSG flow logs
        $nsgs = Get-AzNetworkSecurityGroup
        $flowLogsEnabled = 0
        
        foreach ($nsg in $nsgs) {
            # Check if flow logs are enabled (requires Network Watcher)
            $flowLogConfig = Get-AzNetworkWatcherFlowLogStatus -NetworkWatcherName "NetworkWatcher_$($nsg.Location)" `
                -ResourceGroupName "NetworkWatcherRG" -TargetResourceId $nsg.Id -ErrorAction SilentlyContinue
            
            if ($flowLogConfig -and $flowLogConfig.Enabled) {
                $flowLogsEnabled++
            }
        }
        
        if ($nsgs.Count -gt 0) {
            $flowLogPercentage = [math]::Round(($flowLogsEnabled / $nsgs.Count) * 100, 2)
            $result.Findings += "$flowLogPercentage% of NSGs have flow logs enabled"
            
            if ($flowLogPercentage -lt 100) {
                $result.Status = "Fail"
                $result.Remediation += "Enable NSG flow logs on all Network Security Groups"
                $result.Remediation += "Configure flow log retention based on compliance requirements"
            }
        }
        
        # Check for Service Endpoints
        $vnets = Get-AzVirtualNetwork
        $serviceEndpointCount = 0
        
        foreach ($vnet in $vnets) {
            foreach ($subnet in $vnet.Subnets) {
                if ($subnet.ServiceEndpoints.Count -gt 0) {
                    $serviceEndpointCount += $subnet.ServiceEndpoints.Count
                }
            }
        }
        
        if ($serviceEndpointCount -gt 0) {
            $result.Findings += "Found $serviceEndpointCount service endpoint(s) for direct service connectivity"
        }
        else {
            $result.Findings += "No service endpoints configured"
            $result.Remediation += "Configure service endpoints to restrict traffic flow to Azure services"
        }
        
        if ($result.Status -ne "Fail") {
            $result.Status = "Pass"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess information flow enforcement: $_"
    }
    
    return $result
}