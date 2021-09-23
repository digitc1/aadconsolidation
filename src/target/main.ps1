Invoke-WebRequest -Uri "https://raw.githubusercontent.com/digitc1/aadconsolidation/main/src/target.ps1" -OutFile $HOME/aad.ps1
./aad.ps1
Remove-Item -Path $HOME/aad.ps1

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/digitc1/aadconsolidation/main/src/target/set-subscription.ps1" -OutFile $HOME/set-subscription.ps1
./set-subscription.ps1
Remove-Item -Path $HOME/set-subscription.ps1
