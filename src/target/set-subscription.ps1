$vaultName = ""
$subscriptionId = (Get-AzContext).Subscription.Id
Set-Location -Path $subscriptionId

# Recreate custom roles if any
Write-Host "checking custom roles" -ForegroundColor yellow
$roleDefinitions = Get-Content customroles.json | ConvertFrom-Json
$roleDefinitions | ForEach-Object -Process {
	Write-Host "checking role definition "$_.roleName
	$definition = New-Object Microsoft.Azure.Commands.Resources.Models.Authorization.PSRoleDefinition
	$definition.AssignableScopes = $_.assignableScopes
	$definition.Actions = $_.permissions.actions
	$definition.NotActions = $_.permissions.notActions
	$definition.DataActions = $_.permissions.dataActions
	$definition.NotDataActions = $_.permissions.notDataActions
	$definition.Name = $_.roleName
	$definition.Description = $_.description
    if(!(Get-AzRoleDefinition | Where-Object {$_.Name -eq $definition.Name})){
	    New-AzRoleDefinition -Role $definition
    } else {
        Write-Host "Custom role already exist" $definition.Name
    }
}

if(!(Get-AzResourceGroup | Where-Object {$_.ResourceGroupName -eq "autocreate_rg"})){
	New-AzResourceGroup -Name "autocreate_rg" -Location "westeurope" -Tag @{state="DONOTDELETE"}
}
if(!($vault = Get-AzKeyVault | Where-Object {$_.ResourceGroupName -eq "autocreate_rg"})){
	$rand = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 20| foreach-object {[char]$_})
	$vaultName = "kv" + $rand
	$vault = New-AzKeyVault -VaultName $vaultName -ResourceGroupName "autocreate_rg" -location "westeurope" -Sku 'Standard'
}
$vaultName = $vault.VaultName

Write-Host "Assigning access policy to current user"
$currentUserId = az ad signed-in-user show --query objectId -o tsv
Set-AzKeyVaultAccessPolicy -VaultName $vaultName -ObjectId $currentUserId -PermissionsToKeys Get,List,Update,Create,Import,Delete,Recover,Backup,Restore -PermissionsToCertificates Get, List, Update, Create, Import, Delete, Recover, Backup, Restore, ManageContacts,ManageIssuers, GetIssuers, ListIssuers, SetIssuers, DeleteIssuers -PermissionsToSecrets Get,List,Set,Delete,Recover,Backup,Restore -Passthru
Start-Sleep -seconds 10

#To run for each automation account
Write-Host "Recreate service principal and runAs account for Azure automation"
$automationAccounts = Get-AzAutomationAccount
ForEach ($automationAccount in $automationAccounts) {
        Write-Host "Configuring automation account $($automationAccount.automationAccountName)"
        $automationApplication = Get-AzADApplication | Where-Object {$_.DisplayName -Like "$($automationAccount.AutomationAccountName)_*"}

        if($automationApplication){
                Write-Host "Configuring the 'run as account' for automation account '$($automationAccount.AutomationAccountName)'"
                Write-Host "Creating certificate"
                $CertificateSubjectName = "CN=EU,OU=EU,O=org,L=Brussels,S=Belgium,C=BE"
                $AzureKeyVaultCertificatePolicy = New-AzKeyVaultCertificatePolicy -SubjectName $CertificateSubjectName -IssuerName "Self" -KeyType "RSA" -KeyUsage "DigitalSignature" -ValidityInMonths 12 -RenewAtNumberOfDaysBeforeExpiry 20 -KeyNotExportable:$False -ReuseKeyOnRenewal:$False
                $AzureKeyVaultCertificate = Add-AzKeyVaultCertificate -VaultName $vaultName -Name $automationAccount.AutomationAccountName -CertificatePolicy $AzureKeyVaultCertificatePolicy

                do {
                        Write-Host "Waiting for long-running task to complete ..."
                        start-sleep -Seconds 5
                } until ((Get-AzKeyVaultCertificateOperation -Name $automationAccount.AutomationAccountName -vaultName $vaultName).Status -eq "completed")

                Write-Host "Exporting certificate"
                $PfxPassword = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 48| foreach-object {[char]$_})
                $secretPassword = ConvertTo-SecureString -String $PfxPassword -Force -AsPlainText
                Set-AzKeyvaultSecret -VaultName $vaultName -Name "$($automationAccount.AutomationAccountName)-secret" -SecretValue $secretPassword | Out-Null
                $PfxFilePath = join-path -Path (get-location).path -ChildPath "cert.pfx"
                $AzKeyVaultCertificatObject = Get-AzKeyVaultCertificate -VaultName $vaultName -Name $($automationAccount.AutomationAccountName)
                $secret = Get-AzKeyVaultSecret -VaultName $vaultName -Name $AzKeyVaultCertificatObject.Name
                $secretValueText = '';
                $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret.SecretValue)
                try {
                        $secretValueText = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
                } finally {
                        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
                }

                $AzKeyVaultCertificatSecretBytes = [System.Convert]::FromBase64String($SecretValueText)
                $certCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
                $certCollection.Import($AzKeyVaultCertificatSecretBytes,$null,[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
                $protectedCertificateBytes = $certCollection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $PfxPassword)
                [System.IO.File]::WriteAllBytes($PfxFilePath, $protectedCertificateBytes)

                Write-Host "Link Azure AD application and automation account with certificate"
                $AzKeyVaultCertificatStringValue = [System.Convert]::ToBase64String($certCollection.GetRawCertData())
                #New-AzADAppCredential -ApplicationId $automationApplication.ApplicationId -CertValue $AzKeyVaultCertificatStringValue -StartDate $certCollection.NotBefore -EndDate $certCollection.NotAfter
                #$automationAppCredential = Get-AzADAppCredential -ApplicationId $automationApplication.ApplicationId
                $automationAppCredential = New-AzADAppCredential -ApplicationId $automationApplication.ApplicationId -CertValue $AzKeyVaultCertificatStringValue -StartDate $certCollection.NotBefore -EndDate $certCollection.NotAfter -CustomKeyIdentifier "RunAsAccount"
                #$AzADServicePrincipal = New-AzADServicePrincipal -ApplicationId $automationApplication.ApplicationId -SkipAssignment
                $automationADServicePrincipal = Get-AzADServicePrincipal -ApplicationId $automationApplication.ApplicationId
                Set-AzAutomationCertificate -ResourceGroupName $automationAccount.ResourceGroupName -AutomationAccountName $automationAccount.AutomationAccountName -Path $PfxFilePath -Name $automationAccount.AutomationAccountName -Password $secretPassword -Exportable:$Exportable

                $ConnectionFieldData = @{
                        "ApplicationId" = $automationApplication.ApplicationId
                        "TenantId" = (Get-AzContext).Tenant.ID
                        "CertificateThumbprint" = $certCollection.Thumbprint
                        "SubscriptionId" = (Get-AzContext).Subscription.ID
                }

                New-AzAutomationConnection -ResourceGroupName $automationAccount.ResourceGroupName -AutomationAccountName $automationAccount.AutomationAccountName -Name "AzureRunAsConnection" -ConnectionTypeName "AzureServicePrincipal" -ConnectionFieldValues $ConnectionFieldData
        } else {
                Write-Host "No 'Run as account' linked to the automation account '$($automationAccount.AutomationAccountName)'. Skipping creation of the run as account"
        }
}

# Recreate role assignments
Write-Host "checking role assignment" -ForegroundColor yellow
$roleAssignments = Get-Content roleassignments.json | ConvertFrom-Json
$roleAssignments | ForEach-Object -Process {
    try{
	    Write-Host "assign role $($_.RoleDefinitionName) to $($_.principalType) $($_.principalName)"
        $principalName = $_.principalName
        $roleDefinition = $_.RoleDefinitionName
        $scope = $_.scope
        $objectId = ""
	    switch($_.principalType){
		    "User" {
			    $objectId = (Get-AzADUser | Where-Object {$_.Mail -match $principalName.split('_')[0].split('@')[0] -And $_.Mail -like "*$DNSSuffix*"}).Id
		    }
		    "Group" {
                if(!(Get-AzADGroup -DisplayName $principalName)){
                    New-AzADGroup -DisplayName $principalName | Out-Null
                }
                $objectId = (Get-AzADGroup -DisplayName $principalName).Id
		    }
		    "ServicePrincipal" { 
                $mapping = Get-Content -Path ../mappingOldAppNewSP.json | ConvertFrom-Json
                $objectId = ($mapping | Where-Object {$_.oldAppId -eq $roleAssignment.principalName})[0].newServicePrincipal
		    }
		    default {
			    Write-Host "Role assignment cannot be assigned, unknown principal type: $_.principalType"
		    }
	    }
        if ($scope.split('/')[3] -eq 'managementGroups') {
            Write-Host "scope is invalid (management group)"
        }
        elseif (Get-AzRoleAssignment | Where-Object {$_.Scope -eq $scope -And $_.RoleDefinitionName -eq $roleDefinition -And $_.ObjectId -eq $objectId}) {
            Write-Host "role already assigned"
        }
        elseif ( $roleDefinition -eq 'User Access Administrator' ) {
            Write-Host "Role User Access Administrator cannot be assigned"
        }
        elseif ( $_.principalType -eq 'ServicePrincipal' ) {
            Write-Host "service principal is not supported yet"
        }
        else {
            New-AzRoleAssignment -ObjectId $objectId -RoleDefinitionName $roleDefinition -Scope $scope
            Write-Host "role $($_.RoleDefinitionName) assigned to $($_.principalType) $($_.principalName)"
        }
    } catch {
        Write-Host "User cannot be assigned. Check if user is in the directory"
    }
}

# Update keyvaults
Write-Host "checking keyvaults" -ForegroundColor yellow
$userList = Get-Content ../userList.json | ConvertFrom-Json
Get-ChildItem -Filter kv-*.json | ForEach-Object {
	$content = Get-Content $_.FullName | ConvertFrom-Json
	$vault = Get-AzResource -ResourceId $content.Id -ExpandProperties
	Write-Host "configuring keyvault" $vault.name
	$vault.Properties.TenantId = (Get-AzContext).Tenant.TenantId
    Write-Host "tenantid is: $((Get-AzContext).Tenant.TenantId)"
    Write-Host "vault tenantid is: $($vault.Properties.TenantId)"
	$vault.Properties.AccessPolicies = @()
	$vaultName = $vault.name
    Set-AzResource -ResourceId $vault.Id -Properties $vault.Properties -Force

    Write-Host "Recreating vault access policies"
    $content.properties.accessPolicies | ForEach-Object -Process {
        $permissions = $_.permissions
        $objectId = $_.objectId
        $user = $userList | Where-Object {$_.objectId -eq $objectId}
        if($user) {
            Write-Host "Recreating access policy for user $($user.userPrincipalName)"
            $newUserId = (Get-AzADUser | Where-Object {$_.Mail -match $user.userPrincipalName.split('_')[0].split('@')[0] -And $_.Mail -like "*$DNSSuffix*"}).Id
            $newUserId
            if($newUserId){
                Set-AzKeyVaultAccessPolicy -ObjectId $newUserId -VaultName $vaultName -PermissionsToKeys $permissions.keys -PermissionsToSecrets $permissions.secrets -PermissionsToCertificates $permissions.certificates -PassThru
            } else {
                Write-Host "corresponding user cannot be found in the current tenant"
            }
        } else {
            Write-Host "User cannot be found in userList"
        }
    }
}

# Update SQL server
Write-Host "sql server" -ForegroundColor yellow
$sql = Get-Content sql.json | ConvertFrom-Json
$sql | ForEach-Object -Process {
	Write-Host "reconfigure server" $_.id.split('/')[8]
	$login = $_.login
    try {
	    $objectId = (Get-AzADUser | Where-Object {$_.Mail -match $login.split('_')[0].split('@')[0] -And $_.Mail -like "*$DNSSuffix*"}).Id
	    if($objectId){
            Write-Host "Assigning sql server admin to $objectId"
            Set-AzSqlServerActiveDirectoryAdministrator -objectId $objectId -ResourceGroupName $_.resourceGroup -ServerName ($_.id.split('/')[8]) -DisplayName "DBAs"
        } else {
            Write-Host "Corresponding user cannot be found in the current tenant"
        }
    } catch {
        Write-Host "Cannot find any corresponding object id for user" $login
    }
}
Set-Location -Path ..