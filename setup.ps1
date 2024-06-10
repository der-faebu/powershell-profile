#If the file does not exist, create it.
if (!(Test-Path -Path $PROFILE -PathType Leaf)) {
    try {
        # Detect Version of Powershell & Create Profile directories if they do not exist.
        if ($PSVersionTable.PSEdition -eq "Core" ) { 
            if (!(Test-Path -Path ($env:userprofile + "\Documents\Powershell"))) {
                New-Item -Path ($env:userprofile + "\Documents\Powershell") -ItemType "directory"
            }
        }
        elseif ($PSVersionTable.PSEdition -eq "Desktop") {
            if (!(Test-Path -Path ($env:userprofile + "\Documents\WindowsPowerShell"))) {
                New-Item -Path ($env:userprofile + "\Documents\WindowsPowerShell") -ItemType "directory"
            }
        }

        Invoke-RestMethod https://github.com/der-faebu/powershell-profile/raw/main/Microsoft.PowerShell_profile.ps1 -OutFile $PROFILE
        Write-Host "The profile @ [$PROFILE] has been created."
        Write-host "if you want to add any persistent components, please do so at
        [$HOME\Documents\PowerShell\Profile.ps1] as there is an updater in the installed profile 
        which uses the hash to update the profile and will lead to loss of changes"
    }
    catch {
        throw $_.Exception.Message
    }
}
# If the file already exists, show the message and do nothing.
else {
    Get-Item -Path $PROFILE | Move-Item -Destination oldprofile.ps1 -Force
    Invoke-RestMethod https://github.com/der-faebu/powershell-profile/raw/main/Microsoft.PowerShell_profile.ps1 -OutFile $PROFILE
    Write-Host "The profile @ [$PROFILE] has been created and old profile removed."
    write-host "Please back up any persistent components of your old profile to [$HOME\Documents\PowerShell\Profile.ps1]
         as there is an updater in the installed profile which uses the hash to update the profile 
         and will lead to loss of changes"
}

# Choco install
#
try {
    Write-Host  "Testing for choco..." -ForegroundColor Cyan
    choco --version
    Write-Host "Chocolatey is already installed." -ForegroundColor Green
}
catch {
    Write-Host "Chocolatey is not installed yet. Installing..." -ForegroundColor Red
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}

# OMP Install
choco install -y oh-my-posh zoxide

# Install github cli
choco install -y gh

# Font Install
# Get all installed font families
Write-Host  "Handling fonts..." -ForegroundColor Cyan

[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
$fontFamilies = (New-Object System.Drawing.Text.InstalledFontCollection).Families

# Check if CaskaydiaCove NF is installed
if ($fontFamilies -notcontains "MesloLGM Nerd Font") {
    choco install -y nerd-fonts-meslo 
    # Download and install CaskaydiaCove NF
    # $webClient = New-Object System.Net.WebClient
    # $webClient.DownloadFile("https://github.com/ryanoasis/nerd-fonts/releases/download/v3.0.2/CascadiaCode.zip", ".\CascadiaCode.zip")
    # 
    # Expand-Archive -Path ".\CascadiaCode.zip" -DestinationPath ".\CascadiaCode" -Force
    # $destination = (New-Object -ComObject Shell.Application).Namespace(0x14)
    # Get-ChildItem -Path ".\CascadiaCode" -Recurse -Filter "*.ttf" | ForEach-Object {
    #     If (-not(Test-Path "C:\Windows\Fonts\$($_.Name)")) {        
    #         # Install font
    #         $destination.CopyHere($_.FullName, 0x10)
    #     }
    # }

    # Clean up
  #  Remove-Item -Path ".\CascadiaCode" -Recurse -Force
  #  Remove-Item -Path ".\CascadiaCode.zip" -Force
}


# Terminal Icons Install
#
Write-Host  "Installing Terminal-Icons module..." -ForegroundColor Cyan
if ($PSVersionTable.PSEdition -eq "Core" ) { 
    Install-Module -Name Terminal-Icons -Repository PSGallery -Force
}
Write-Host  "Importing `$Profile..." -ForegroundColor Cyan
& $profile
