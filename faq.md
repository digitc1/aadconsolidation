# Frequently Asked Questions

## Migration scope

- [Which accounts will be migrated?](#which-account-will-be-migrated)
- [Will Azure DevOps Organization be migrated?](#will-azure-devops-organization-be-migrated)
- [Is there any impact for M365 users?](#is-there-any-impact-for-m365-users)
- [Will Azure AD applications be migrated?](#will-azure-ad-applications-be-migrated)
- [Is there any impact for the developers?](#is-there-any-impact-for-the-developers)

## User Management

- [Will all users be migrated?](#will-all-users-be-migrated)
- [Will all groups be migrated?](#will-all-groups-be-migrated)
- [Will users have the same rights in Azure?](#will-users-have-the-same-rights-in-azure)
- [Will non-EC users have the same rights in Azure?](#will-non-ec-users-have-the-same-rights-in-azure)

## Azure resources

- [Will Azure resources be modified?](#will-azure-resources-be-modified)

## Application

- [Is there any impact for my application?](#is-there-any-impact-for-my-application)
- [Is there any impact for my application's users?](#is-there-any-impact-for-my-applications-users)

### Which accounts will be migrated?

This migration project concerns all the accounts created by DIGIT with hotmail account (acp4euXXX@hotmail.com and acpcloudXXX@hotmail.com). Additional accounts linked to Azure AD owned by the customer will not be impacted by this migration project.

### Will Azure DevOps Organization be migrated?

This question is currently under investigation with Microsoft.

### Is there any impact for M365 users?

No. The scope of this migration project is only the subscription and will not have any impact on the existing M365 users.

### Will Azure AD application be migrated?

All information related to Azure AD application will be gathered by the script and an application will be recreated in the new account with the exact same information and rights. However, some information do not support migration and must be updated manually. This includes:

* Azure AD application's secret (password)

### Is there any impact for the developers?

Yes. During the entire migration process, the developers will not be able to login to the Azure portal anymore. The access to virtual machines (ssh, rdp) will remain during the entire process. The downtime can last for up to half a day.

### Will all users be migrated?

There are 3 possibilities that can arise:
1. The user has a @ec.europa.eu account. In this case, the user will be migrated.
1. The user connects with a local user account (@acp4euXXXhotmail.onmicrosoft.com). In this case, the user will be migrated if a corresponding @ec.europa.eu user can be found in the destination tenant. Otherwise, the user will not be migrated automatically and some additional manual steps will be required to complete the transition.
1. The user connects with an external provider account (@company.com other than europa.eu). In this case, the user will not be migrated automatically and some additional manual steps will be required to complete the transition.

### Will all groups be migrated?

Yes. All groups in the source tenant will be recreated and reconfigured in the exact same way, including name, group owner, group member (only if the user can be migrated) and Role Based Access Control.

### Will users have the same rights in Azure?

All EC users will be migrated to the new tenant and will be granted the same access on the subscription. Some administration rights may be removed during the migration process (e.g. global administration of the account).
All non-EC users in the source account (local account) will be converted to EC users whenever possible, if a corresponding EC user can be found in the consolidated account. Other users can be added manually with their EC account.

### Will non-EC users have the same rights in Azure?

External users can be added as guest or member and be granted access to the Azure portal. Some conditional access may be required to be able to connect (for instance, being part of the whitelisted providers).

### Will Azure resources be modified?

No, the Azure resources will be migrated as they are.

### Is there any impact for my application?

Mostly No. If you're running an IaaS or PaaS application, this one will remain active for the entire duration of the migration. However, some specific part of the application may not be accessible:

* If the application uses a managed identity or Azure AD application, this one will not work until recreated
* If the application uses external connectors (Microsoft Teams, Office365, ...), those may need some reconfiguration.

### Is there any impact for the application's users?

No. If the application doesn't use any assets that require recreation/reconfiguration, there won't be any impact for the end-users.
