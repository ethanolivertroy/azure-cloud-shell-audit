# Data Protection and Encryption Control Checks
# Implements FedRAMP and NIST 800-53 data protection controls

function Test-DataProtectionControls {
    <#
    .SYNOPSIS
        Performs comprehensive data protection and encryption checks
    .DESCRIPTION
        Evaluates Azure data protection configuration against FedRAMP and NIST 800-53 controls
    #>
    
    param(
        [string]$SubscriptionId
    )
    
    $dataResults = @()
    
    # SC-13: Cryptographic Protection
    $dataResults += Test-CryptographicProtection -SubscriptionId $SubscriptionId
    
    # SC-28: Protection of Information at Rest
    $dataResults += Test-DataAtRestEncryption -SubscriptionId $SubscriptionId
    
    # SC-12: Cryptographic Key Management
    $dataResults += Test-KeyManagement -SubscriptionId $SubscriptionId
    
    # MP-5: Media Transport
    $dataResults += Test-MediaProtection -SubscriptionId $SubscriptionId
    
    # AC-16: Security Attributes (Data Classification)
    $dataResults += Test-DataClassification -SubscriptionId $SubscriptionId
    
    return $dataResults
}

function Test-CryptographicProtection {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "SC-13"
        ControlName = "Cryptographic Protection"
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
        # Check TLS version enforcement across services
        $tlsIssues = 0
        
        # Check Storage Accounts
        $storageAccounts = Get-AzStorageAccount
        foreach ($storage in $storageAccounts) {
            if ($storage.MinimumTlsVersion -ne "TLS1_2") {
                $tlsIssues++
                $result.Evidence += "Storage account '$($storage.StorageAccountName)' allows TLS < 1.2"
            }
        }
        
        if ($tlsIssues -eq 0) {
            $result.Findings += "All storage accounts enforce TLS 1.2 minimum"
        }
        else {
            $result.Status = "Fail"
            $result.Findings += "Found $tlsIssues storage account(s) allowing weak TLS versions"
            $result.Remediation += "Set minimum TLS version to 1.2 for all storage accounts"
        }
        
        # Check SQL Databases
        $sqlServers = Get-AzSqlServer -ErrorAction SilentlyContinue
        foreach ($server in $sqlServers) {
            $tdeStatus = Get-AzSqlServerTransparentDataEncryptionProtector -ResourceGroupName $server.ResourceGroupName `
                -ServerName $server.ServerName -ErrorAction SilentlyContinue
            
            if ($tdeStatus) {
                if ($tdeStatus.Type -eq "AzureKeyVault") {
                    $result.Findings += "SQL Server '$($server.ServerName)' uses customer-managed keys for TDE"
                }
                else {
                    $result.Findings += "SQL Server '$($server.ServerName)' uses service-managed keys for TDE"
                }
            }
            
            # Check connection encryption
            if ($server.MinimalTlsVersion -ne "1.2") {
                $tlsIssues++
                $result.Evidence += "SQL Server '$($server.ServerName)' allows TLS < 1.2"
            }
        }
        
        # Check App Services
        $webApps = Get-AzWebApp -ErrorAction SilentlyContinue
        foreach ($app in $webApps) {
            $config = Get-AzWebApp -ResourceGroupName $app.ResourceGroup -Name $app.Name
            if ($config.SiteConfig.MinTlsVersion -ne "1.2") {
                $tlsIssues++
                $result.Evidence += "Web App '$($app.Name)' allows TLS < 1.2"
            }
            
            # Check HTTPS only
            if (-not $config.HttpsOnly) {
                $result.Findings += "Web App '$($app.Name)' does not enforce HTTPS"
                $result.Remediation += "Enable 'HTTPS Only' for Web App '$($app.Name)'"
            }
        }
        
        if ($result.Status -ne "Fail" -and $tlsIssues -eq 0) {
            $result.Status = "Pass"
            $result.Findings += "Cryptographic protection properly configured across services"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess cryptographic protection: $_"
    }
    
    return $result
}

function Test-DataAtRestEncryption {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "SC-28"
        ControlName = "Protection of Information at Rest"
        FedRAMPLevel = "High"
        NISTFamily = "System and Communications Protection"
        Status = "Unknown"
        CIAImpact = @{
            Confidentiality = "High"
            Integrity = "Medium"
            Availability = "Low"
        }
        Findings = @()
        Evidence = @()
        Remediation = @()
    }
    
    try {
        $encryptionIssues = 0
        
        # Check VM disk encryption
        $vms = Get-AzVM
        $encryptedDisks = 0
        $totalDisks = 0
        
        foreach ($vm in $vms) {
            $diskEncryption = Get-AzVMDiskEncryptionStatus -ResourceGroupName $vm.ResourceGroupName `
                -VMName $vm.Name -ErrorAction SilentlyContinue
            
            $totalDisks++
            if ($diskEncryption) {
                if ($diskEncryption.OsVolumeEncrypted -eq "Encrypted") {
                    $encryptedDisks++
                }
                else {
                    $result.Evidence += "VM '$($vm.Name)' OS disk is not encrypted"
                    $encryptionIssues++
                }
                
                # Check data disks
                if ($diskEncryption.DataVolumesEncrypted -ne "Encrypted" -and $vm.StorageProfile.DataDisks.Count -gt 0) {
                    $result.Evidence += "VM '$($vm.Name)' has unencrypted data disks"
                    $encryptionIssues++
                }
            }
        }
        
        if ($totalDisks -gt 0) {
            $encryptionRate = [math]::Round(($encryptedDisks / $totalDisks) * 100, 2)
            $result.Findings += "$encryptionRate% of VM OS disks are encrypted"
            
            if ($encryptionRate -lt 100) {
                $result.Status = "Fail"
                $result.Remediation += "Enable Azure Disk Encryption on all virtual machines"
            }
        }
        
        # Check Storage Account encryption
        $storageAccounts = Get-AzStorageAccount
        $customerManagedKeys = 0
        
        foreach ($storage in $storageAccounts) {
            # Check encryption settings
            if ($storage.Encryption.KeySource -eq "Microsoft.Keyvault") {
                $customerManagedKeys++
                $result.Findings += "Storage '$($storage.StorageAccountName)' uses customer-managed keys"
            }
            
            # Check if infrastructure encryption is enabled (double encryption)
            if ($storage.Encryption.RequireInfrastructureEncryption) {
                $result.Findings += "Storage '$($storage.StorageAccountName)' has infrastructure encryption enabled"
            }
        }
        
        if ($storageAccounts.Count -gt 0) {
            $cmkPercentage = [math]::Round(($customerManagedKeys / $storageAccounts.Count) * 100, 2)
            $result.Findings += "$cmkPercentage% of storage accounts use customer-managed keys"
            
            if ($cmkPercentage -lt 50) {
                $result.Remediation += "Consider using customer-managed keys for sensitive data storage"
            }
        }
        
        # Check SQL Database encryption
        $sqlServers = Get-AzSqlServer -ErrorAction SilentlyContinue
        foreach ($server in $sqlServers) {
            $databases = Get-AzSqlDatabase -ServerName $server.ServerName `
                -ResourceGroupName $server.ResourceGroupName -ErrorAction SilentlyContinue
            
            foreach ($db in $databases | Where-Object { $_.DatabaseName -ne "master" }) {
                $tde = Get-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName $server.ResourceGroupName `
                    -ServerName $server.ServerName -DatabaseName $db.DatabaseName -ErrorAction SilentlyContinue
                
                if ($tde -and $tde.State -ne "Enabled") {
                    $encryptionIssues++
                    $result.Evidence += "SQL Database '$($db.DatabaseName)' does not have TDE enabled"
                }
            }
        }
        
        # Check Cosmos DB encryption
        $cosmosAccounts = Get-AzCosmosDBAccount -ErrorAction SilentlyContinue
        foreach ($cosmos in $cosmosAccounts) {
            if (-not $cosmos.EnableAutomaticFailover) {
                $result.Findings += "Cosmos DB '$($cosmos.Name)' does not have automatic failover (affects availability)"
            }
        }
        
        if ($encryptionIssues -eq 0 -and $result.Status -ne "Fail") {
            $result.Status = "Pass"
            $result.Findings += "Data at rest encryption is properly configured"
        }
        else {
            $result.Status = "Fail"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess data at rest encryption: $_"
    }
    
    return $result
}

function Test-KeyManagement {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "SC-12"
        ControlName = "Cryptographic Key Management"
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
        # Check Key Vaults
        $keyVaults = Get-AzKeyVault
        $result.Findings += "Found $($keyVaults.Count) Key Vault(s)"
        
        $keyManagementIssues = 0
        
        foreach ($kv in $keyVaults) {
            # Get detailed Key Vault info
            $kvDetails = Get-AzKeyVault -VaultName $kv.VaultName -ResourceGroupName $kv.ResourceGroupName
            
            # Check soft delete
            if (-not $kvDetails.EnableSoftDelete) {
                $keyManagementIssues++
                $result.Evidence += "Key Vault '$($kv.VaultName)' does not have soft delete enabled"
            }
            
            # Check purge protection
            if (-not $kvDetails.EnablePurgeProtection) {
                $keyManagementIssues++
                $result.Evidence += "Key Vault '$($kv.VaultName)' does not have purge protection enabled"
            }
            
            # Check for HSM backing
            if ($kvDetails.Sku.Name -eq "Premium") {
                $result.Findings += "Key Vault '$($kv.VaultName)' uses HSM-backed keys (Premium SKU)"
            }
            
            # Check access policies
            $accessPolicies = $kvDetails.AccessPolicies
            if ($accessPolicies.Count -gt 10) {
                $result.Findings += "Key Vault '$($kv.VaultName)' has $($accessPolicies.Count) access policies - review for least privilege"
                $result.Remediation += "Review and minimize access policies for Key Vault '$($kv.VaultName)'"
            }
            
            # Check for key rotation (simplified check)
            $keys = Get-AzKeyVaultKey -VaultName $kv.VaultName -ErrorAction SilentlyContinue
            foreach ($key in $keys) {
                if ($key.Expires) {
                    $daysUntilExpiry = ($key.Expires - (Get-Date)).Days
                    if ($daysUntilExpiry -lt 30 -and $daysUntilExpiry -gt 0) {
                        $result.Findings += "Key '$($key.Name)' in vault '$($kv.VaultName)' expires in $daysUntilExpiry days"
                    }
                }
            }
            
            # Check network restrictions
            if ($kvDetails.NetworkAcls.DefaultAction -ne "Deny") {
                $keyManagementIssues++
                $result.Evidence += "Key Vault '$($kv.VaultName)' allows public network access by default"
                $result.Remediation += "Configure network ACLs to restrict Key Vault access"
            }
        }
        
        if ($keyVaults.Count -eq 0) {
            $result.Status = "Fail"
            $result.Findings += "No Key Vaults found - centralized key management not implemented"
            $result.Remediation += "Deploy Azure Key Vault for centralized cryptographic key management"
        }
        elseif ($keyManagementIssues -eq 0) {
            $result.Status = "Pass"
            $result.Findings += "Key management controls are properly configured"
        }
        else {
            $result.Status = "Fail"
            $result.Remediation += "Enable soft delete and purge protection on all Key Vaults"
            $result.Remediation += "Use HSM-backed keys for high-value cryptographic operations"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess key management: $_"
    }
    
    return $result
}

function Test-MediaProtection {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "MP-5"
        ControlName = "Media Transport"
        FedRAMPLevel = "High"
        NISTFamily = "Media Protection"
        Status = "Unknown"
        CIAImpact = @{
            Confidentiality = "High"
            Integrity = "Medium"
            Availability = "Low"
        }
        Findings = @()
        Evidence = @()
        Remediation = @()
    }
    
    try {
        # Check for secure file transfer options
        $storageAccounts = Get-AzStorageAccount
        $secureTransferIssues = 0
        
        foreach ($storage in $storageAccounts) {
            # Check secure transfer requirement
            if (-not $storage.EnableHttpsTrafficOnly) {
                $secureTransferIssues++
                $result.Evidence += "Storage '$($storage.StorageAccountName)' allows insecure transfer"
            }
            
            # Check for private endpoints
            $privateEndpoints = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $storage.Id -ErrorAction SilentlyContinue
            if ($privateEndpoints) {
                $result.Findings += "Storage '$($storage.StorageAccountName)' has private endpoint connections"
            }
        }
        
        # Check for Azure File Sync
        $fileSyncs = Get-AzStorageSyncService -ErrorAction SilentlyContinue
        if ($fileSyncs) {
            $result.Findings += "Azure File Sync configured for secure hybrid file sharing"
        }
        
        # Check managed disks export settings
        $disks = Get-AzDisk
        $exportableDisks = 0
        
        foreach ($disk in $disks) {
            if ($disk.DiskState -eq "Unattached" -and $disk.NetworkAccessPolicy -ne "DenyAll") {
                $exportableDisks++
            }
        }
        
        if ($exportableDisks -gt 0) {
            $result.Findings += "Found $exportableDisks unattached disk(s) that could be exported"
            $result.Remediation += "Set network access policy to 'DenyAll' for unattached disks"
        }
        
        # Check Import/Export service usage
        # Note: This would require checking activity logs in a real implementation
        $result.Findings += "Manual review required: Check Azure Import/Export jobs for secure media handling"
        
        if ($secureTransferIssues -eq 0) {
            $result.Status = "Pass"
            $result.Findings += "Media transport controls are properly configured"
        }
        else {
            $result.Status = "Fail"
            $result.Remediation += "Enable secure transfer on all storage accounts"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess media protection: $_"
    }
    
    return $result
}

function Test-DataClassification {
    param([string]$SubscriptionId)
    
    $result = @{
        ControlId = "AC-16"
        ControlName = "Security Attributes (Data Classification)"
        FedRAMPLevel = "High"
        NISTFamily = "Access Control"
        Status = "Unknown"
        CIAImpact = @{
            Confidentiality = "High"
            Integrity = "Low"
            Availability = "Low"
        }
        Findings = @()
        Evidence = @()
        Remediation = @()
    }
    
    try {
        # Check for resource tags indicating classification
        $allResources = Get-AzResource
        $taggedResources = 0
        $classificationTags = @("Classification", "DataClassification", "Sensitivity", "SecurityLevel")
        
        foreach ($resource in $allResources) {
            if ($resource.Tags) {
                foreach ($tag in $classificationTags) {
                    if ($resource.Tags.ContainsKey($tag)) {
                        $taggedResources++
                        break
                    }
                }
            }
        }
        
        if ($allResources.Count -gt 0) {
            $taggedPercentage = [math]::Round(($taggedResources / $allResources.Count) * 100, 2)
            $result.Findings += "$taggedPercentage% of resources have classification tags"
            
            if ($taggedPercentage -lt 80) {
                $result.Status = "Fail"
                $result.Remediation += "Implement consistent data classification tagging across all resources"
                $result.Remediation += "Use tags like 'Classification', 'Sensitivity' with values: Public, Internal, Confidential, Restricted"
            }
            else {
                $result.Status = "Pass"
            }
        }
        
        # Check SQL Database classification
        $sqlServers = Get-AzSqlServer -ErrorAction SilentlyContinue
        foreach ($server in $sqlServers) {
            $databases = Get-AzSqlDatabase -ServerName $server.ServerName `
                -ResourceGroupName $server.ResourceGroupName -ErrorAction SilentlyContinue
            
            foreach ($db in $databases | Where-Object { $_.DatabaseName -ne "master" }) {
                # Note: Actual data classification check would require SQL connection
                $result.Findings += "SQL Database '$($db.DatabaseName)' - data classification status requires manual review"
            }
        }
        
        # Check for Azure Information Protection
        $result.Findings += "Azure Information Protection status requires Azure AD Premium license verification"
        $result.Remediation += "Consider implementing Azure Information Protection for document classification"
        
        # Check storage account blob inventory
        foreach ($storage in Get-AzStorageAccount) {
            $inventoryPolicies = Get-AzStorageBlobInventoryPolicy -StorageAccount $storage -ErrorAction SilentlyContinue
            if ($inventoryPolicies) {
                $result.Findings += "Storage '$($storage.StorageAccountName)' has blob inventory policies for data governance"
            }
        }
        
        if ($result.Status -ne "Fail") {
            $result.Status = "Partial"
            $result.Findings += "Data classification requires manual review and organizational policies"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Findings += "Failed to assess data classification: $_"
    }
    
    return $result
}