$vaultName = ""

Write-Host "Creating new vault for automation accounts certificates"
$rand = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 20| foreach-object {[char]$_})
$vaultName = "kv" + $rand
$resourceGroup = New-AzResourceGroup -Name "autocreate_rg" -Location "westeurope" -Tag @{state="DONOTDELETE"}
New-AzKeyVault -VaultName $vaultName -ResourceGroupName "autocreate_rg" -location "westeurope" -Sku 'Standard'
Write-Host "Created vault "$vaultName

Write-Host "Assigning access policy to current user"
$currentUserId = az ad signed-in-user show --query objectId -o tsv
Set-AzKeyVaultAccessPolicy -VaultName $vaultName -ObjectId $currentUserId -PermissionsToKeys Get,List,Update,Create,Import,Delete,Recover,Backup,Restore -PermissionsToCertificates Get, List, Update, Create, Import, Delete, Recover, Backup, Restore, ManageContacts,ManageIssuers, GetIssuers, ListIssuers, SetIssuers, DeleteIssuers -PermissionsToSecrets Get,List,Set,Delete,Recover,Backup,Restore -Passthru
Start-Sleep -seconds 10
#$vaultName

#To run for each automation account
Write-Host "Recreate service principal and runAs account for Azure automation"
if(Test-Path ./automationAccounts.json) {
	$content = Get-Content automationAccounts.json | ConvertFrom-Json
	$content | ForEach-Object -Process {
	    Write-Host "Configuring automation account "$_.name
	    $automationAccountName = $_.name
	    $automationAccountResourceGroup = $_.resourceGroup
	    $automationAccount = Get-AzAutomationAccount | Where-Object {$_.automationAccountName -eq $automationAccountName}
	    $RunAsAccount = "RunAsAccount-$($automationAccount.SubscriptionId)-$($automationAccount.AutomationAccountName)"

	    Write-Host "RunAsAccount is $RunAsAccount"
	    Write-Host "Creating certificate"
	    $AzureKeyVaultCertificatePolicy = New-AzKeyVaultCertificatePolicy -SubjectName $CertificateSubjectName -IssuerName "Self" -KeyType "RSA" -KeyUsage "DigitalSignature" -ValidityInMonths 12 -RenewAtNumberOfDaysBeforeExpiry 20 -KeyNotExportable:$False -ReuseKeyOnRenewal:$False
	    $AzureKeyVaultCertificate = Add-AzKeyVaultCertificate -VaultName $vaultName -Name $RunAsAccount -CertificatePolicy $AzureKeyVaultCertificatePolicy

	    do {
	    start-sleep -Seconds 20
	    } until ((Get-AzKeyVaultCertificateOperation -Name $RunAsAccount -vaultName $vaultName).Status -eq "completed")

	    Write-Host "Exporting certificate"
	    $PfxPassword = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 48| foreach-object {[char]$_})
	    $secretPassword = ConvertTo-SecureString -String $PfxPassword -Force -AsPlainText
	    Set-AzKeyvaultSecret -VaultName $vaultName -Name "$RunAsAccount-secret" -SecretValue $secretPassword
	    $PfxFilePath = join-path -Path (get-location).path -ChildPath "cert.pfx"
	    $AzKeyVaultCertificatObject = Get-AzKeyVaultCertificate -VaultName $vaultName -Name $RunAsAccount
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

	    Write-Host "creating Azure AD application"
	    # Redirect URI must be unique in the tenant
	    # What to do if multiple customers defined http://localhost
	    # DisplayName must be taken from migration file
	    if(!($AzADApplicationRegistration = Get-AzADApplication | Where-Object {$_.DisplayName -eq $RunAsAccount -And $_.identifierUris -eq "https://$RunAsAccount"})){
		$AzADApplicationRegistration = New-AzADApplication -DisplayName $RunAsAccount -HomePage "http://$RunAsAccount" -IdentifierUris "https://$RunAsAccount"
	    } else {
		$rand = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 5| foreach-object {[char]$_})
		$RunAsAccount = $RunAsAccount + $rand
		$AzADApplicationRegistration = New-AzADApplication -DisplayName "$RunAsAccount" -HomePage "http://$RunAsAccount" -IdentifierUris "https://$RunAsAccount"
	    }

	    Write-Host "Link Azure AD application and automation account with certificate"
	    $AzKeyVaultCertificatStringValue = [System.Convert]::ToBase64String($certCollection.GetRawCertData())
	    New-AzADAppCredential -ApplicationId $AzADApplicationRegistration.ApplicationId -CertValue $AzKeyVaultCertificatStringValue -StartDate $certCollection.NotBefore -EndDate $certCollection.NotAfter
	    $AzADServicePrincipal = New-AzADServicePrincipal -ApplicationId $AzADApplicationRegistration.ApplicationId -SkipAssignment
	    # TODO: Get $automationAccount from the file
	    New-AzAutomationCertificate -ResourceGroupName $automationAccountResourceGroup -AutomationAccountName $automationAccountName -Path $PfxFilePath -Name $RunAsAccount -Password $secretPassword -Exportable:$Exportable

	    $ConnectionFieldData = @{
	    "ApplicationId" = $AzADApplicationRegistration.ApplicationId
	    "TenantId" = (Get-AzContext).Tenant.ID
	    "CertificateThumbprint" = $certCollection.Thumbprint
	    "SubscriptionId" = (Get-AzContext).Subscription.ID
	    }

	    $AzAutomationConnection = New-AzAutomationConnection -ResourceGroupName $automationAccountResourceGroup -AutomationAccountName $automationAccountName -Name $RunAsAccount -ConnectionTypeName "AzureServicePrincipal" -ConnectionFieldValues $ConnectionFieldData
	    Start-Sleep -seconds 15
	    $servicePrincipal = Get-AzADServicePrincipal | where-Object {$_.DisplayName -eq $RunAsAccount}

	    #TODO remove assignment
	    Write-Host "Assigning default contributor right to automation account's service principal"
	    New-AzRoleAssignment -objectId $servicePrincipal.Id -RoleDefinitionName "Contributor"
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
			    $objectId = (Get-AzADUser | Where {$_.Mail -match $principalName.split('_')[0].split('@')[0] -And $_.Mail -like "*$DNSSuffix*"}).Id
		    }
		    "Group" {
                if(!($group = Get-AzADGroup -DisplayName $principalName)){
                    $group = New-AzADGroup -DisplayName $principalName
                }
                $objectId = (Get-AzADGroup -DisplayName $principalName).Id
		    }
		    "ServicePrincipal" {
			    #New-AzRoleAssignment -ObjectId $_.PrincipalId -RoleDefinitionName $roleDefinition -Scope $scope	
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
$userList = Get-Content userList.json | ConvertFrom-Json
Get-ChildItem -Filter kv-*.json | ForEach-Object {
	$content = Get-Content $_.FullName | ConvertFrom-Json
	$vault = Get-AzResource -ResourceId $content.Id -ExpandProperties
	Write-Host "configuring keyvault" $vault.name
	$vault.Properties.TenantId = $context.Tenant.TenantId
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
            $newUserId = (Get-AzADUser | Where {$_.Mail -match $user.userPrincipalName.split('_')[0].split('@')[0] -And $_.Mail -like "*$DNSSuffix*"}).Id
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
	    $objectId = (Get-AzADUser | Where {$_.Mail -match $login.split('_')[0].split('@')[0] -And $_.Mail -like "*$DNSSuffix*"}).Id
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
