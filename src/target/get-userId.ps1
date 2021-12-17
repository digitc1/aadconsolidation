Param(
	[Parameter(Mandatory = $true)][string]$principalName, 
	[Parameter(Mandatory = $true)][string]$DNSSuffix, 
	[Parameter(Mandatory = $true)][string]$subdomainDNSSuffix
)

$userId=(Get-AzADUser | Where-Object {$_.Mail -match $principalName.split('_')[0].split('@')[0] -And $_.Mail -match "$subdomainDNSSuffix"}).Id

if($userId -eq $null){
	return (Get-AzADUser | Where-Object {$_.Mail -match $principalName.split('_')[0].split('@')[0] -And $_.Mail -like "*$DNSSuffix*"}).Id
}else{
	return $userId
}
