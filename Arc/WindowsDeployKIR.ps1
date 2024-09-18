# Define the URL of the MSI
$msiUrl = "https://download.microsoft.com/download/03c7aacb-1f7b-443d-95e8-6d7d301ac831/Windows%2010%201809%20and%20Windows%20Server%202019%20KB5041578%20240816_21501%20Known%20Issue%20Rollback.msi"
 
# Define the local path to save the MSI file
$msiPath = "$env:TEMP\KB5041578_Known_Issue_Rollback.msi"
 
# Download the MSI file
Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath
 
# Install the MSI
Start-Process msiexec.exe -ArgumentList "/i", "`"$msiPath`"", "/quiet", "/norestart" -Wait

Start-Sleep 20

# CD to location where LGPO is installed
cd "C:\Users\Administrator\Downloads\LGPO\LGPO_30\"

# Enable the KIR Policy
.\LGPO.exe /r "C:\Users\Administrator\Downloads\lgpo.txt.txt" /w "C:\Windows\System32\GroupPolicy\Machine\registry.pol" /v

# Add New Registry Key for KIR Policy
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides" -Force

# Add New Registry Value for KIR Policy
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides" -Name "2290715789" -PropertyType "DWORD" -Value "1" -Force
 
# Reboot the machine
Restart-Computer -Force