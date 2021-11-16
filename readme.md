# Azure AD Consolidation

## Introduction
The purpose of this project is to migrate all the subscriptions owned by the European Commission to a single tenant in order to facilitate the management and governance of the accounts.

## Code Repository
The code repository contains 2 files:
* source.sh
* target.ps1

The first one, source.sh, is a cli script intended to be run on the source account which will create an archive containing all the information to be transfered. This archive can then be downloaded and uploaded to the destination account.

The second one, target.ps1, is a PowerShell script intended to be run on the target account which will recreate all the Azure assets existing in the source account based on the information provided by the shared archive.


## Procedure

### Source account
In the source account, open a new shell session and ensure the Azure Shell is using cli.

![This is a alt text.](/images/open-cli.png "Picture showing how to open Azure CLI.")

If the Azure Shell uses PowerShell by default, click on the switch button to switch to Azure CLI.

![This is a alt text.](/images/switch-cli.png "Picture showing how to switch to Azure CLI.")

In Azure CLI, run the following code:

```
curl https://raw.githubusercontent.com/digitc1/aadconsolidation/main/src/source.sh --output script.sh
chmod +x script.sh
az login
./script.sh [SUBSCRIPTION_NAME}
rm script.sh
```

Once the script completed, click on the download button and enter the name "aadmigration.tar.gz" to download the archive containing all the information related to your account. This archive must be kept carefully as it will be the only way to recover all the information related to the old account (RBAC, applications, ...).

![This is a alt text.](/images/download.png "Picture showing how to download files.")

![This is a alt text.](/images/download2.png "Picture showing how to download files.")

![This is a alt text.](/images/download3.png "Picture showing how to download files.")

### Target account
In the target account, open a new shell session and ensure the Azure Shell is using PowerShell.

![This is a alt text.](/images/open-cli.png "Picture showing how to open Azure Shell.")

If the Azure Shell uses CLI by default, click on the switch button to switch to Azure PowerShell.

![This is a alt text.](/images/switch-shell.png "Picture showing how to switch to Azure Shell.")

Upload the archive created by running the script on the source account

In Azure Shell, run the following code:

```
Invoke-WebRequest -URI https://raw.githubusercontent.com/digitc1/aadconsolidation/main/src/target.ps1 -OutFile script.ps1
Connect-AzureAD
az login
./script.ps1 --name <subscription>
rm script.ps1
```

## Frequently Asked Questions
Check our [Frequently Asked Questions](https://github.com/digitc1/aadconsolidation/blob/main/faq.md) for additional information.

## Contribute
These scripts have been created by European Commission (DIGIT) and Microsoft and are intended to be used by the European Commission only.

To contribute to the code, contact DIGIT CLOUD VIRTUAL TASK FORCE functional mailbox.
