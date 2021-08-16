#chmod +x on the sh script when running in azure cli
#!/bin/bash

# Switch to the correct subscription
if az account set --subscription "$1" ; then
	echo "Subscription successfully loaded"
else
	echo "Error using subscriptionId, halting execution" && exit 1
fi

mkdir aadmigration
cd aadmigration

# Install the az resource graph extension, so querying of resource managed by ARM is possible
az extension add --name resource-graph

# Get an extract of the Azure AD
az ad user list > userList.json
az ad group list > groupList.json
groups=$(az ad group list --query [].objectId --output tsv)
for i in $groups
do
	az ad group member list -g $i > "groupMember-$i.json"
	az ad group owner list -g $i > "groupOwner-$i.json"
done

#Get Azure AD applications
az ad app list > AADapplications.json

#Get Azure AD app ObjectId Reference
az ad app list --query '[].{objectId:objectId, displayName:displayName}' --output tsv > aadappref.json

# Get azure ad application owners
apps=$(az ad app list --query [].objectId --output tsv)
for i in $apps
do
	az ad app owner list --id $i > "application-$i.json"
	az rest --method GET --uri "https://graph.microsoft.com/v1.0/applications/$i" > "appmanifest-$i.json"
done

# Save all role assignments, including inherited role assignments and export the output to json
az role assignment list --all --include-inherited --output json > roleassignments.json

# Save all custom roles to an external json file, to be recreated in the destination tenant
az role definition list --custom-role-only true --output json > customroles.json

# List system assigned identities and user assigned identity
az ad sp list --all --filter "servicePrincipalType eq 'ManagedIdentity'" > managedidentities.json
az ad sp list --all --filter "servicePrincipalType eq 'Application'" > applicationIdentities.json

# List user assigned managed identities only
az identity list > useridentity.json

# Save all keyvaults configuration to json files to reproduce access to key and secret in the new directory
keyvaults=$(az keyvault list --query [].name --output tsv)
for i in $keyvaults;
do
        az keyvault show --name $i > "kv-$i.json"
done

# List Azure SQL databases with AAD authentication to reproduce in the new directory
az sql server ad-admin list --ids $(az graph query -q "resources | where type == 'microsoft.sql/servers' | project id" -o tsv |  cut -f1) > sql.json

# List other resources with known Azure AD dependencies
subscription=$(az account show --query id | sed -e 's/^"//' -e 's/"$//')
az graph query -q "resources | where type != 'microsoft.azureactivedirectory/b2cdirectories' | where identity <> '' or properties.tenantId <> '' or properties.encryptionSettingsCollection.enabled == true | project name, type, kind, identity, tenantId, properties.tenantId" --subscriptions $subscription --output json > aaddependencies.json

# Clear data export settings from AAD tenant
uri="https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01"
az rest --method GET --uri $uri > dataexport.json
ids=$(az rest --method GET --uri $uri --query value[].id --output tsv)
for id in $ids ; do az rest --method DELETE --uri "https://management.azure.com/$id?api-version=2017-04-01"; done

cd ../
tar -cvzf aadmigration.tar.gz aadmigration

echo "Script completed"
