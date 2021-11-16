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

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/digitc1/aadconsolidation/main/src/target/set-tenant.ps1" -OutFile $HOME/aad.ps1
./aad.ps1
Remove-Item -Path $HOME/aad.ps1

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/digitc1/aadconsolidation/main/src/target/set-subscription.ps1" -OutFile $HOME/set-subscription.ps1
./set-subscription.ps1
Remove-Item -Path $HOME/set-subscription.ps1
