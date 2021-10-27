#az login might be required via device auth code flow for admin consent (added warning message to start of the script)...

Param(
	[Parameter(Mandatory = $true)][string]$name
)

Write-Warning -Message "Ensure you have run 'Connect-AzureAD' cmdlet before running this script" -WarningAction Inquire
write-warning -Message "In order to grant admin consent on any recreated Azure AD apps, you need to run 'az login' and do Modern Auth - Device code Authtentication (https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code)." -WarningAction Inquire
Write-Warning -Message "This scripts creates new Azure RunAs connection which name may vary from usual name. Automation Accounts runbooks must be updated accordingly to use the new Azure RunAs connection name."

$context = Set-AzContext -subscriptionName $name
if(!($context)){
	Write-Host "Provided subscription is invalid"
	return
}
Write-Host "Installation of the modules needed for this script"
Install-Module -Name 'Az.ManagedServiceIdentity'
$CertificateSubjectName = "CN=EU,OU=EU,O=org,L=Brussels,S=Belgium,C=BE"
$DNSSuffix = "ec.europa.eu"
#$centralKeyVault = "" # To be created

Write-Host "extracting source files"
New-Item -Path . -Name aadmigration -ItemType "directory"
if(!(Get-ChildItem -Name "aadmigration.tar.gz")){
	Write-Host "archive not found"
	return
}
tar -xvzf aadmigration.tar.gz
cd aadmigration

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

#Check users if the old tenant and try to reinvite in the new tenant if they were invited from EC
$userList = Get-Content userList.json | ConvertFrom-Json
ForEach($user in $userList){
    if($user.mail -Like ("*@*ec.europa.eu")){
        Write-Host "Checking user $($user.mail)"
        if(Get-AzADUser -Mail $user.mail){
            Write-Host "User already added in the consolidated tenant"
        } else {
            New-AzureADMSInvitation -InvitedUserEmailAddress $user.mail -SendInvitationMessage $True -InviteRedirectUrl "http://myapps.microsoft.com"
        }
    } else {
        Write-Host "user email not supported"
    }
}

#Recreate Azure AD applications
$tenantId = (Get-azcontext).Tenant.id
$TenantName = Get-AzTenant | where{$_.id -eq $tenantId}
$AzAdApps = Get-Content AADapplications.json | ConvertFrom-Json
$newAppsIds = @{}

ForEach($AzADApp in $AzAdApps){
    if(($AzADApp.DisplayName -notlike "*RunAsAccount*") -And ($AzADApp.DisplayName -notlike "*lzslzAutomation*") -And ($AzAdApp.DisplayName -ne "OptionalClaimsApp") -And ($AzADApp.DisplayName -notlike "*aad-extension-app*") -And ($AzADApp.DisplayName -notlike "*Learn On Demand*") -And ($AzADApp.DisplayName -notlike "*Tenant Schema Extension App*") -And ($AzADApp.DisplayName -notlike "*Cost-Monitor-Account*")){
        Write-host "Recreating Azure AD appliction "$AzAdApp.DisplayName

        #Recreating Azure AD apps based from backed up Json file
        $NewApp = New-AzureADApplication -DisplayName $AzAdApp.DisplayName
        $NewSPN = New-AzureADServicePrincipal -AppId $NewApp.AppId

        
        #Add Application owner
        $OldOId=$AzADApp.ObjectId
	Write-host $OldOId
	$BackupFile = Get-childitem -Path . | where{$_.name -like "*application*$oldOid*"} 
	$BackupAppOwner = Get-Content $BackupFile | ConvertFrom-Json
	If(($BackupAppOwner -eq $null)){
		Write-Host "Azure Ad app $AzADApp.DisplayName has no owner assigned."
	}Else{
		ForEach($owner in $BackupAppOwner){
			 if($owner.userPrincipalName -eq $null){
				Write-Host "Azure Ad app $AzADApp.DisplayName has no owner assigned."
			 }else{
				Write-Host "Owner of the application is" $owner.userPrincipalName
				$ownerObjectId = (Get-AzADUser | Where {$_.Mail -match $owner.userPrincipalName.split('_')[0].split('@')[0] -And $_.Mail -like "*$DNSSuffix*"}).Id
				if($ownerObjectId -eq $null){
				   Write-host "Not able to find the owner in the directory." -ForegroundColor Yellow
				}Else{
					$currentOwner=Get-AzureADApplicationOwner -objectId $newapp.ObjectId
					if($currentOwner.ObjectId -ne $ownerObjectId){
					   Add-AzureADApplicationOwner -ObjectId $newapp.ObjectId -RefObjectId $ownerObjectId 
					   Write-host "Added $ownerObjectId as owner of the Azure AD app." -ForegroundColor Green 
					}else{
						Write-host "Correct owner is already assigned to AzADApp" -ForegroundColor Green 
					}
				}
			  }
		}
	}
	
        #Add ReplyUrls
        $ReplyURLs = $AzADApp.ReplyUrls

        if(!($replyUrls -eq $null)){
            Set-AzureADApplication -ObjectId $NewApp.ObjectId -ReplyUrls $ReplyUrls
            Write-host "Added Reply Urls" $ReplyURLs -ForegroundColor Green
        }Else{
            Write-host "No Reply urls to add to the azure ad application"
        }

        #Add Azure AD application roles
        $approles = @()

        try{
            Foreach($approle in $AzADApp.appRoles){
                $Id = [Guid]::NewGuid().ToString()
                [switch] $Disabled

                #Create new AppRole Object
                $newAppRole = [Microsoft.Open.AzureAD.Model.AppRole]::new()
                $newAppRole.AllowedMemberTypes = New-Object System.Collections.Generic.List[string]
                If($approle.AllowedMemberTypes -eq "User"){
                        $newAppRole.AllowedMemberTypes = ("User")
                    } Elseif ($approle.AllowedMemberTypes -eq "Application") {
                        $newAppRole.AllowedMemberTypes = ("Application")
                    } Else {
                        $newAppRole.AllowedMemberTypes = ("User","Application")
                    }
                $newAppRole.DisplayName = $appRole.Displayname
                $newAppRole.Description = $appRole.Description
                $newAppRole.Value = $appRole.Value
                $newAppRole.Id = $Id
                $newAppRole.IsEnabled = (-not $Disabled)
                $appRoles += $newAppRole
                }
        
                Set-AzureADApplication -objectId $NewApp.ObjectId -appRoles $appRoles
                Write-Host "AppRoles have been added" -ForegroundColor Green

        } catch {
            Write-host "Following error was encountered: " $error[0].Exception.ErrorContent.Message.value -ForegroundColor Red
        }

        #Add azure AD API permissions
        $RRAaccs = $AzADApp.RequiredResourceAccess
        $Req = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
   
            Try{
                ForEach($RRAs in $RRAaccs){
                    $RRAra = $RRAs.ResourceAccess
                    $req.ResourceAppId = @()
                    $req.ResourceAppId += $RRAs.ResourceAppId

                    if($RRAs.ResourceAppId -eq "00000003-0000-0000-c000-000000000000"){                                 
                        ForEach($RRA in $RRAra){
                            $Acc = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList $RRA.Id, $RRA.Type                   
                            $req.ResourceAccess += $acc
                            }
                        Set-AzureADApplication -ObjectId $NewApp.ObjectId -RequiredResourceAccess $req
                     } Else {
                       $MissingApiRights = Get-AzADServicePrincipal -ApplicationId $RRAs.ResourceAppId
                       Write-Host "Resource Access is not for Microsoft Graph API. Requested Resource Access is for " $MissingApiRights.DisplayName -ForegroundColor Yellow
                    }
                    }            
                } catch{
                    Write-host "Following error was encountered: " $error[0].Exception.ErrorContent.Message.value -ForegroundColor Red
                } 

        #Add secret to Azure AD application
        $creds = $AzAdApp | Select passwordcredentials, keycredentials

        if(!($creds.PasswordCredentials.count -eq $null)){
            Write-host "Recreating Secret..." -ForegroundColor Green
            $startDate = Get-Date
            $endDate = $startDate.AddYears(2)
            $aadAppsecret01 = New-AzureADApplicationPasswordCredential -ObjectId $NewApp.ObjectId -CustomKeyIdentifier "Secret01" -StartDate $startDate -EndDate $endDate
            Write-Host "The new secret is valid for 2 years. The secret value is: " $aadAppsecret01.value -ForegroundColor Green
        }Elseif(!($creds.KeyCredentials.count -eq $null)){
            Write-Host "Certificate used for application. Please recreate and reattach certificate." -ForegroundColor Yellow
        }Else{
            Write-Host "No credentials found on the application."
        }

        #Recreate Token Configuration
        $claims = $AzADApp.OptionalClaims
        If(!(($claims.AccessToken -eq $null) -and ($claims.IdToken -eq $null) -and ($claims.SamlToken -eq $null))){
		$tmp = New-Object -TypeName Microsoft.Open.AzureAD.Model.OptionalClaims
		$tmp.AccessToken = $claims.AccessToken
		$tmp.IdToken = $claims.IdToken
		$tmp.SamlToken = $claims.SamlToken
		Set-AzureADapplication -ObjectId $newApp.objectid -OptionalClaims $tmp
            	Write-host "Recreated Token configuration" -ForegroundColor Green
        }Else{
            Write-host "No token configuration to be recreated."
        }

        #Check for implicit flow
        $implicit = $AzADApp.Oauth2AllowImplicitFlow

        if($implicit -eq $false){
            Set-AzureADApplication -ObjectId $NewApp.ObjectId -Oauth2AllowImplicitFlow $false    
        }Else {
            Set-AzureADApplication -ObjectId $newApp.ObjectId -Oauth2AllowImplicitFlow $true
        }
        Write-host "Verified Implicit flow status..."

        #Public clients
	If(!($AzAdApp.identifierUris -eq $null)){
		$public = $AzADApp.PublicClient

		If(($public -eq $null) -or ($public -eq $false)){
		    Set-AzureADApplication -ObjectId $newapp.ObjectId -PublicClient $false
		}Else{
		    Set-azureadapplication -ObjectId $NewApp.ObjectId -publicclient $true
		}
		Write-Host "Public client state has been set."
	} else {
		Write-Host "Skip public clients because app identifier uris is empty"
	}

        #Implicit ID Token
        #$StateIdToken = az ad app list --app-id $AzADApp.appId | ConvertFrom-Json     
        $idToken = $AzADapp.oauth2allowidtokenimplicitflow
        $OID = $newApp.ObjectId

        If($idtoken -eq $false){
        #azure CLI command, no PSH counterpart
            az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/applications/$OID" --headers 'Content-Type=application/json' --body '{"web":{"implicitGrantSettings":{"enableIdTokenIssuance":false}}}'
            Write-Host "Blocked Implicit flow ID token" -ForegroundColor Green
        }Else{
        #acure CLI command, no PSH counterpart
            az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/applications/$OID" --headers 'Content-Type=application/json' --body '{"web":{"implicitGrantSettings":{"enableIdTokenIssuance":true}}}'
            Write-Host "Allowed Implicit flow ID token" -ForegroundColor Yellow
        }

        #Exposed API's
        Try{
            If(!($AzAdApp.identifierUris -eq $null)){
		Set-azureadapplication -ObjectId $NewApp.ObjectId -IdentifierUris "api://$($NewApp.AppId)"
		Write-Host "Added the identifier Uri: api://$($NewApp.AppId)" -ForegroundColor Green
	    } else {
			Write-Host "No identifier URI specified" -ForegroundColor Green
	    }
        }Catch{
            Write-host "Following error was encountered: " $error[0].Exception.ErrorContent.Message.value -ForegroundColor Red
        }

        $EmptyScopes = New-Object System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.OAuth2Permission]

        $CurrentScope = $NewApp.Oauth2Permissions

        if($CurrentScope -eq $null){
            Write-Host "No Exposed API found for the app."
        }Else{
            $Value = $CurrentScope | Select -ExpandProperty Value
            ($CurrentScope | where{$_.Value -eq $value}).IsEnabled = $false

            Set-AzureADApplication -ObjectId $newApp.ObjectId -Oauth2Permissions $CurrentScope
            Start-Sleep -seconds 5
            Set-AzureADApplication -ObjectId $newApp.ObjectId -Oauth2Permissions $EmptyScopes
        }

        Try{
		$NewPermissions=New-Object Collections.Generic.List[Microsoft.Open.AzureAD.Model.OAuth2Permission]
		Foreach($Permission in $AzAdApp.Oauth2Permissions){
			$Id = [Guid]::NewGuid().ToString()
			
			#Create new oAuth2Permission Object
			$NewPermission = [Microsoft.Open.AzureAD.Model.OAuth2Permission]::new()
			$NewPermission.AdminConsentDescription = $Permission.AdminConsentDescription
			$NewPermission.AdminConsentDisplayName = $Permission.AdminConsentDisplayName
			$NewPermission.Id = $Id
			$NewPermission.Type = $permission.Type
			$NewPermission.UserConsentDescription = $Permission.UserConsentDescription
			$NewPermission.UserConsentDisplayName = $Permission.UserConsentDisplayName
			$NewPermission.Value = $Permission.value
			$NewPermissions.add($NewPermission)
		}
		Set-azureadapplication -ObjectId $NewApp.ObjectId -Oauth2Permissions $NewPermissions
		Write-Host "Added API to Azure AD application" -ForegroundColor Green
	}Catch{
		Write-host "Following error was encountered: " $error[0].Exception.ErrorContent.Message.value -ForegroundColor Red
	}

	#Adding logoutUrl
	if($AzADApp.logoutUrl -ne $null){
		Set-AzureAdApplication -ObjectId $newApp.ObjectId -logoutUrl $AzADApp.logoutUrl
		Write-Host "Setting logoutUrl" -ForegroundColor Green
	}

        Start-sleep -seconds 20
	
        #AZ Cli call test for admin consent
		$AppId = $NewApp.AppId
		
        Try{
            az ad app permission admin-consent --id $AppId
            Write-Host "Admin Consent Granted to Azure AD application" -Foregroundcolor Black -BackgroundColor Green -NoNewLine
	    Write-Host " " 
        }catch{
            Write-host "Admin consent failed due to $err"
        }

        #Write-Host "Admin Consent Granted to Azure AD application" -BackgroundColor Green -Foregroundcolor Black
	$newAppsIds.add($AzADApp.appId,$newApp)
    }
}

ForEach($AzADApp in $AzAdApps){
	if(($AzADApp.DisplayName -notlike "*RunAsAccount*") -And ($AzADApp.DisplayName -notlike "*lzslzAutomation*") -And ($AzAdApp.DisplayName -ne "OptionalClaimsApp") -And ($AzADApp.DisplayName -notlike "*aad-extension-app*") -And ($AzADApp.DisplayName -notlike "*Learn On Demand*") -And ($AzADApp.DisplayName -notlike "*Tenant Schema Extension App*") -And ($AzADApp.DisplayName -notlike "*Cost-Monitor-Account*")){

		Write-host "Recreating Azure AD PreAuthorizedApplication oAuth2 permissions"$AzAdApp.DisplayName

		#REST API call for PreAuthorizedApplication oAuth2 permissions

		$oldAzAdManifest = Get-Content "appmanifest-$($AzAdApp.ObjectId).json" | ConvertFrom-Json

		if($oldAzAdManifest.api.preAuthorizedApplications.count -gt 0){
			$requestBody="{\""api\"": {\""preAuthorizedApplications\"": ["
			ForEach($preAuthApp in $oldAzAdManifest.api.preAuthorizedApplications){
				$oldPreAuthAppId=$preAuthApp.appId
				if($newAppsIds.ContainsKey($oldPreAuthAppId)){
					$newPreAuthAppId = $newAppsIds.$oldPreAuthAppId.appId
				}else{
					$newPreAuthAppId = $oldPreAuthAppId
				}
				$newAzureAdAppOAuth2Perm=get-azureadapplication -objectId $newAppsIds.($AzADApp.appId).ObjectId | select -ExpandProperty Oauth2Permissions
				
				$newAzureAdAppOAuth2PermIds=""
				ForEach($perm in $newAzureAdAppOAuth2Perm){
					ForEach($permissionId in $preAuthApp.DelegatedPermissionIds){
						$OldAdminConsentDescription=($oldAzAdManifest.api.oauth2permissionScopes | where-object {$_.Id -eq $permissionId}).AdminConsentDescription
						if($perm.AdminConsentDescription -eq $OldAdminConsentDescription){
							$id=$perm.Id
							if($perm  -eq $newAzureAdAppOAuth2Perm[-1]){
								$newAzureAdAppOAuth2PermIds+="\""$id\"""
							}else{
								$newAzureAdAppOAuth2PermIds+="\""$id\"","
							}
							
						}
					}
				}
				if($preAuthApp  -eq $oldAzAdManifest.api.preAuthorizedApplications[-1]){
					$requestBody+="{\""appId\"": \""$newPreAuthAppId\"",\""delegatedPermissionIds\"": [$newAzureAdAppOAuth2PermIds]}"
				}else{
					$requestBody+="{\""appId\"": \""$newPreAuthAppId\"",\""delegatedPermissionIds\"": [$newAzureAdAppOAuth2PermIds]},"
				}
			}
			$requestBody+="]}}"
			az rest --method PATCH --url "https://graph.microsoft.com/v1.0/applications/$($newAppsIds.($AzADApp.appId).ObjectId)" --body $requestBody
		}			
	}
}

#Recreate User assigned identities
Write-Host "checking user assigned identities" -ForegroundColor yellow
$userAssignedIdentities = Get-Content useridentity.json | ConvertFrom-Json
$userAssignedIdentities | ForEach-Object -Process {
	Write-Host "checking user assigned identity $_.name"
	New-AzUserAssignedIdentity -ResourceGroupName $_.resourceGroup -Name $_.name
}

# Recreate Groups
$content = Get-Content groupList.json | ConvertFrom-Json
$content | ForEach-Object -Process {
    Write-Host "Checking "$_.displayName
    if($_.onPremisesDomainName -eq $null){
        if(!(Get-AzADGroup -DisplayName $_.displayName)){
            Write-Host "Recreating the group" $_.displayName
            New-AzADGroup -DisplayName $_.displayName -MailNickName $_.displayName | Out-Null
        }
    }  Else {
        Write-host $_.displayName "is a group synced from On-Premises."
    }        
}

# Add group members
Write-Host "Recreating group membership" -ForeGroundColor yellow
$groupList = Get-Content groupList.json | ConvertFrom-Json
Get-ChildItem -Filter groupMember-*.json | ForEach-Object {
	$content = Get-Content $_.FullName | ConvertFrom-Json
    $groupObjectId = $_.name.Substring(12, 36)
    $oldGroup = $groupList | where-Object {$_.ObjectId -eq $groupObjectId}
    Write-Host "Checking members for group " $oldGroup.displayName
    $group = Get-AzADGroup -DisplayName $oldGroup.displayName
    $content | ForEach-Object -Process {
        $principalName = $_.userPrincipalName
        Write-Host "Checking membership for "$principalName
        $objectId = (Get-AzADUser | Where {$_.Mail -match $principalName.split('_')[0].split('@')[0] -And $_.Mail -like "*$DNSSuffix*"}).Id
        if(!($objectId)){
            Write-Host "User cannot be found and assigned group membership" $principalName
        } else {
            if(!(Get-AzureADGroupMember -objectId $group.Id | where-Object {$_.ObjectId -eq $objectId})){
                Add-AzureADGroupMember -RefObjectId $objectId -ObjectId $group.Id
                Write-Host "Added $objectId to group $($group.Id)"
            } else {
                Write-Host "User is already member of the group"
            }
        }
    }
}

# Add group owners
Write-Host "Recreating group ownership" -ForeGroundColor yellow
$groupList = Get-Content groupList.json | ConvertFrom-Json
Get-ChildItem -Filter groupOwner-*.json | ForEach-Object {
	$content = Get-Content $_.FullName | ConvertFrom-Json
    $groupObjectId = $_.name.Substring(11, 36)
    $oldGroup = $groupList | where-Object {$_.ObjectId -eq $groupObjectId}
    Write-Host "Checking owners for group " $oldGroup.displayName
    $group = Get-AzADGroup -DisplayName $oldGroup.displayName
    $content | ForEach-Object -Process {
        $principalName = $_.userPrincipalName
        Write-Host "Checking ownership for "$principalName
        $objectId = (Get-AzADUser | Where {$_.Mail -match $principalName.split('_')[0].split('@')[0] -And $_.Mail -like "*$DNSSuffix*"}).Id
        if(!($objectId)){
            Write-Host "User cannot be found and assigned ownership of the group" $principalName
        } else {
            if(!(Get-AzureADGroupOwner -objectId $group.Id | where-Object {$_.objectId -eq $objectId})){
                Add-AzureADGroupOwner -RefObjectId $objectId -ObjectId $group.Id
                Write-Host "Added $objectId to group $($group.Id) as owner"
            } else {
                Write-Host "User is already owner of the group"
            }
        }
    }
}

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

cd ../
