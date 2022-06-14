#az login might be required via device auth code flow for admin consent (added warning message to start of the script)...

#Check users if the old tenant and try to reinvite in the new tenant if they were invited from EC
$userList = Get-Content userList.json | ConvertFrom-Json
ForEach($user in $userList){
    if($user.mail -Like ("*@*$DNSSuffix")){
        Write-Host "Checking user $($user.mail)"
        try{
		if(Get-AzADUser -Mail $user.mail){
           		Write-Host "User already added in the consolidated tenant"
       		} else {
			Write-Host "Inviting user $($user.mail) to the consolidated tenant"
            		az rest --method POST --uri "https://graph.microsoft.com/v1.0/invitations" --body "{\""invitedUserEmailAddress\"": \""$($user.mail)\"", \""inviteRedirectUrl\"": \""http://myapps.microsoft.com\""}" --headers '{\"Content-Type\":\"application/json\"}'
        	}
	} catch {
            Write-host "Following error was encountered: " $error[0].Exception.ErrorContent.Message.value -ForegroundColor Red
        }
    } else {
        Write-Host "user email not supported"
    }
}

#Recreate Azure AD applications
$tenantId = (Get-azcontext).Tenant.id
$AzAdApps = Get-Content AADapplications.json | ConvertFrom-Json
$newAppsIds = @{}
$mappingTable = @()

ForEach($AzADApp in $AzAdApps){
    if(($AzADApp.DisplayName -notlike "*RunAsAccount*") -And ($AzADApp.DisplayName -notlike "*lzslzAutomation*") -And ($AzAdApp.DisplayName -ne "OptionalClaimsApp") -And ($AzADApp.DisplayName -notlike "*aad-extensions-app*") -And ($AzADApp.DisplayName -notlike "*Learn On Demand*") -And ($AzADApp.DisplayName -notlike "*Tenant Schema Extension App*") -And ($AzADApp.DisplayName -notlike "*Cost-Monitor-Account*")){
        Write-host "Recreating Azure AD application "$AzAdApp.DisplayName

        #Recreating Azure AD apps based from backed up Json file
        $NewApp = New-AzureADApplication -DisplayName $AzAdApp.DisplayName
        $NewSPN = New-AzureADServicePrincipal -AppId $NewApp.AppId
        
        $mapping = New-Object -TypeName psobject
        $mapping | Add-Member -MemberType NoteProperty -Name "oldAppId" -Value $AzAdApp.appId
        $mapping | Add-Member -MemberType NoteProperty -Name "newAppId" -Value $NewApp.appId

        $mappingTable += $mapping

        #Add Application owner
        $OldOId=$AzADApp.id
	Write-host $OldOId
	$BackupFile = Get-childitem -Path . | where-Object {$_.name -like "*application*$oldOid*"} 
	$BackupAppOwner = Get-Content $BackupFile | ConvertFrom-Json
	If(($null -eq $BackupAppOwner)){
		Write-Host "Azure Ad app"$AzADApp.DisplayName"has no owner assigned."
	}Else{
		ForEach($owner in $BackupAppOwner){
			 if($null -eq $owner.userPrincipalName){
				Write-Host "Azure Ad app"$AzADApp.DisplayName"has no owner assigned."
			 }else{
				Write-Host "Owner of the application is" $owner.userPrincipalName
				$ownerObjectId = ./userId.ps1 $owner.userPrincipalName.split('_')[0].split('@')[0] $DNSSuffix $subdomainDNSSuffix
				#(Get-AzADUser | Where-Object {$_.Mail -match $owner.userPrincipalName.split('_')[0].split('@')[0] -And $_.Mail -like "*$DNSSuffix*"}).Id
				if($null -eq $ownerObjectId){
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

        if(!($null -eq $replyUrls)){
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

        if($creds.PasswordCredentials.count -gt 0){
            Write-host "Recreating Secret..." -ForegroundColor Green
            $startDate = Get-Date
            $endDate = $startDate.AddYears(2)
            $aadAppsecret01 = New-AzureADApplicationPasswordCredential -ObjectId $NewApp.ObjectId -CustomKeyIdentifier "Secret01" -StartDate $startDate -EndDate $endDate
            Write-Host "The new secret is valid for 2 years. The secret value is: " $aadAppsecret01.value -ForegroundColor Green
        }Elseif($creds.KeyCredentials.count -gt 0){
            Write-Host "Certificate used for application. Please recreate and reattach certificate." -ForegroundColor Yellow
        }Else{
            Write-Host "No credentials found on the application."
        }

        #Recreate Token Configuration
        $claims = $AzADApp.OptionalClaims
        If(!(($null -eq $claims.AccessToken) -and ($null -eq $claims.IdToken) -and ($null -eq $claims.SamlToken))){
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
	If(!(0 -eq $AzAdApp.identifierUris.Length)){
		$public = $AzADApp.PublicClient

		If(($null -eq $public) -or ($public -eq $false)){
		    Set-AzureADApplication -ObjectId $newapp.ObjectId -PublicClient $false
		}Else{
		    Set-azureadapplication -ObjectId $NewApp.ObjectId -publicclient $true
		}
		Write-Host "Public client state has been set."
	} else {
		Write-Host "Skip public clients because app identifier uris is empty"
	}

        #Exposed API's
        Try{
            If(!($null -eq $AzAdApp.identifierUris)){
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

        if($null -eq $CurrentScope){
            Write-Host "No Exposed API found for the app."
        }Else{
            $Value = $CurrentScope | Select -ExpandProperty Value
            ($CurrentScope | Where-Object {$_.Value -eq $value}).IsEnabled = $false

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
	if($null -eq $AzADApp.logoutUrl){
		Set-AzureAdApplication -ObjectId $newApp.ObjectId -logoutUrl $AzADApp.logoutUrl
		Write-Host "Setting logoutUrl" -ForegroundColor Green
	}

        Start-sleep -seconds 20
	
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

$mappingTable | ConvertTo-Json > mappingTable.json

ForEach($AzADApp in $AzAdApps){
	if(($AzADApp.DisplayName -notlike "*RunAsAccount*") -And ($AzADApp.DisplayName -notlike "*lzslzAutomation*") -And ($AzAdApp.DisplayName -ne "OptionalClaimsApp") -And ($AzADApp.DisplayName -notlike "*aad-extension-app*") -And ($AzADApp.DisplayName -notlike "*Learn On Demand*") -And ($AzADApp.DisplayName -notlike "*Tenant Schema Extension App*") -And ($AzADApp.DisplayName -notlike "*Cost-Monitor-Account*")){

		Write-host "Recreating Azure AD PreAuthorizedApplication oAuth2 permissions"$AzAdApp.DisplayName

		#REST API call for PreAuthorizedApplication oAuth2 permissions

		$oldAzAdManifest = Get-Content "appmanifest-$($AzAdApp.Id).json" | ConvertFrom-Json

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

#Recreating user assigned applications
ForEach($oldUser in $userList){
	$user = Get-AzADUser | ?{$_.displayName -eq $oldUser.displayName}
	if (!($user -eq $null)){
		$b = Get-content "AppRoleAssignment_$($oldUser.displayName).json" | ConvertFrom-json
		$list = $b.value.resourceDisplayName

		ForEach($AssApp in $list){
   			if(!($AssApp -eq "MicrosoftAzureActiveAuthn")){
        			Write-Host "Starting with " $assapp
        			Write-Host "user: " $user.Id
        			# Get the service principal for the app you want to assign the user to
        			$servicePrincipal = Get-AzAdServicePrincipal | Where{$_.displayName -eq $AssApp}
        			Write-Host "SPN: " $servicePrincipal.Id

        			# Create the user app role assignment
        			$newApp = Get-AzureADApplication | ?{$_.displayName -eq $AssApp}
				Write-Host "App: " $newApp.displayname

            			If($newApp.approles.count -eq "0"){  
                			New-AzureADUserAppRoleAssignment -ObjectId $user.Id -PrincipalId $user.Id -ResourceId $servicePrincipal.Id -Id ([Guid]::Empty)
           			}Else{
                			$arcId = ($b.value | where{$_.resourceDisplayName -eq $AssApp}).approleId		
					$oldApplicationObjectId = ($AzAdApps | where{$_.displayName -eq $AssApp}).ObjectId
					$oldAppRoles = (Get-Content "appmanifest-$($oldApplicationObjectId).json" | ConvertFrom-Json).appRoles
					forEach($role in $oldAppRoles){
						if($role.id -eq $arcId){
							$newRoleId = ($newApp.appRoles | where{$_.displayName -eq $role.displayName}).Id
							New-AzureADUserAppRoleAssignment -ObjectId $user.Id -PrincipalId $user.Id -ResourceId $servicePrincipal.Id -Id $newRoleId
						}
					}
        			}
    			}
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
    $oldGroup = $groupList | where-Object {$_.id -eq $groupObjectId}
    Write-Host "Checking members for group " $oldGroup.displayName
    $group = Get-AzADGroup -DisplayName $oldGroup.displayName
    $content | ForEach-Object -Process {
        $principalName = $_.userPrincipalName
        Write-Host "Checking membership for "$principalName
        $objectId = ./userId.ps1 $principalName.split('_')[0].split('@')[0] $DNSSuffix $subdomainDNSSuffix
	#(Get-AzADUser | Where-Object {$_.Mail -match $principalName.split('_')[0].split('@')[0] -And $_.Mail -like "*$DNSSuffix*"}).Id
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
    $oldGroup = $groupList | where-Object {$_.id -eq $groupObjectId}
    Write-Host "Checking owners for group " $oldGroup.displayName
    $group = Get-AzADGroup -DisplayName $oldGroup.displayName
    $content | ForEach-Object -Process {
        $principalName = $_.userPrincipalName
        Write-Host "Checking ownership for "$principalName
        $objectId = ./userId.ps1 $principalName.split('_')[0].split('@')[0] $DNSSuffix $subdomainDNSSuffix
	#(Get-AzADUser | Where-Object {$_.Mail -match $principalName.split('_')[0].split('@')[0] -And $_.Mail -like "*$DNSSuffix*"}).Id
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
