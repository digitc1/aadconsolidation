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

# Get all Azure AD conditional access policies
az rest --method GET --uri "https://graph.microsoft.com/v1.0/identity/conditionalaccess/policies" > AzADCAP.json

# Get all Azure AD application proxy applications
az ad sp list --query "[?contains(tags,'WindowsAzureActiveDirectoryOnPremApp')]" --all > azadappproxyapps.json

#Save all Azure AD role assignments
ids=$(az rest --method GET --uri "https://graph.microsoft.com/v1.0/directoryroles" --query value[].roleTemplateId --output tsv)
for id in $ids; 
do
	az rest --method GET --uri "https://graph.microsoft.com/v1.0/directoryroles/roleTemplateId=$id/members" > "azADRole-$id.json"
done

# Get All Administrative Units
az rest --method GET --uri "https://graph.microsoft.com/v1.0/directory/administrativeunits" > AzAdAU.json

# Get All members of the Administrative units (users and groups)
AUs=$(az rest --method GET --uri "https://graph.microsoft.com/v1.0/directory/administrativeunits" --query value[].id --output tsv)
for i in $AUs;
do
az rest --method GET --uri "https://graph.microsoft.com/v1.0/directory/administrativeunits/$i/members" > "AU-$i-members.json"
done

# Get External Collaboration settings - Backup only
az rest --method GET --uri "https://graph.microsoft.com/beta/legacy/policies" | jq '.value[] | select(.definition[] | contains ("InvitationsAllowedAndBlockedDomainsPolicy"))' > InvitationsAllowedAndBlockedDomainsPolicy.json

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

# Save all information related to PIM
pim=$(az ad sp create-for-rbac -o tsv)
az ad app permission add --id $(echo $pim | cut -d' ' -f1) --api 00000003-0000-0000-c000-000000000000 --api-permissions 62ade113-f8e0-4bf9-a6ba-5acb31db32fd=Scope
az ad app permission add --id $(echo $pim | cut -d' ' -f1) --api 00000003-0000-0000-c000-000000000000 --api-permissions eb0788c2-6d4e-4658-8c9e-c0fb8053f03d=Scope
az ad app permission add --id $(echo $pim | cut -d' ' -f1) --api 00000003-0000-0000-c000-000000000000 --api-permissions d01b97e9-cbc0-49fe-810a-750afd5527a3=Scope
az ad app permission add --id $(echo $pim | cut -d' ' -f1) --api 00000003-0000-0000-c000-000000000000 --api-permissions 741c54c3-0c1e-44a1-818b-3f97ab4e8c83=Scope
az ad app permission add --id $(echo $pim | cut -d' ' -f1) --api 00000003-0000-0000-c000-000000000000 --api-permissions 48fec646-b2ba-4019-8681-8eb31435aded=Scope
az ad app permission add --id $(echo $pim | cut -d' ' -f1) --api 00000003-0000-0000-c000-000000000000 --api-permissions 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8=Role
az ad app permission add --id $(echo $pim | cut -d' ' -f1) --api 00000003-0000-0000-c000-000000000000 --api-permissions 483bed4a-2ad3-4361-a73b-c83ccdbdc53c=Role
az ad app permission add --id $(echo $pim | cut -d' ' -f1) --api 00000003-0000-0000-c000-000000000000 --api-permissions c7fbd983-d9aa-4fa7-84b8-17382c103bc4=Role
az ad app permission admin-consent --id $(echo $pim | cut -d' ' -f1)
az login --service-principal -u $(echo $pim | cut -d' ' -f1) -p $(echo $pim | cut -d' ' -f4) -t $(echo $pim | cut -d' ' -f5)

az rest --method GET --uri "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilitySchedules" > pim.json

cd ../
tar -cvzf aadmigration.tar.gz aadmigration

echo "Script completed"
