Write-Warning -Message "Ensure you have run 'Connect-AzureAD' cmdlet before running this script" -WarningAction Inquire
write-warning -Message "In order to grant admin consent on any recreated Azure AD apps, you need to run 'az login' and do Modern Auth - Device code Authtentication (https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code)." -WarningAction Inquire
Write-Warning -Message "This scripts creates new Azure RunAs connection which name may vary from usual name. Automation Accounts runbooks must be updated accordingly to use the new Azure RunAs connection name."

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
Set-Location -Path aadmigration

Invoke-WebRequest -URI https://raw.githubusercontent.com/digitc1/aadconsolidation/main/src/target/get-userId.ps1 -OutFile get-userId.ps1

Invoke-WebRequest -URI https://raw.githubusercontent.com/digitc1/aadconsolidation/main/src/target/set-tenant.ps1 -OutFile tenant.ps1
./tenant.ps1
Remove-Item tenant.ps1

Invoke-WebRequest -URI https://raw.githubusercontent.com/digitc1/aadconsolidation/main/src/target/set-subscription.ps1 -OutFile subscription.ps1
$subscriptionList = Get-ChildItem -Directory
ForEach ($subscription in $subscriptionList){
	Set-AzContext -SubscriptionId $subscription.Name
	./subscription.ps1
}
Remove-Item subscription.ps1

Remove-Item get-userId.ps1
Set-Location ../
