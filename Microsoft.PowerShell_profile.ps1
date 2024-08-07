### PowerShell template profile 
### Version 1.03 - Tim Sneath <tim@sneath.org>
### From https://gist.github.com/timsneath/19867b12eee7fd5af2ba
###
### This file should be stored in $PROFILE.CurrentUserAllHosts
### If $PROFILE.CurrentUserAllHosts doesn't exist, you can make one with the following:
###    PS> New-Item $PROFILE.CurrentUserAllHosts -ItemType File -Force
### This will create the file and the containing subdirectory if it doesn't already 
###
### As a reminder, to enable unsigned script execution of local scripts on client Windows, 
### you need to run this line (or similar) from an elevated PowerShell prompt:
###   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
### This is the default policy on Windows Server 2012 R2 and above for server Windows. For 
### more information about execution policies, run Get-Help about_Execution_Policies.
function Test-InternetConnection {
    try {
        $null = Test-Connection -ComputerName github.com -Count 1 -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}
function Update-PSProfileFromGitHub {
    if (-not (Test-InternetConnection)) {
        Write-Warning "No internet connection available. Cannot update PS Profile..."
        return
    }
    $temp = [System.IO.Path]::GetTempPath()
    try {
        if (-not (Test-Path $PROFILE)) {
            New-Item $PROFILE -ItemType File
        }
        Write-Host  "Checking for profile updates on GitHub.." -ForegroundColor Cyan
        $url = "https://raw.githubusercontent.com/der-faebu/powershell-profile/main/Microsoft.PowerShell_profile.ps1"
        Invoke-RestMethod $url -OutFile "$temp/Microsoft.PowerShell_profile.ps1" -ErrorAction Stop
        $oldhash = Get-FileHash $PROFILE -ErrorAction Stop
        Write-Host "Old hash: $($oldhash.Hash)." -ForegroundColor Cyan
        $newhash = Get-FileHash "$temp/Microsoft.PowerShell_profile.ps1"
        Write-Host "New hash: $($newhash.Hash)" -ForegroundColor Cyan
        $retries = 0
        if ($newhash.Hash -eq $oldhash.Hash) {
            Write-Host "Profile is up to date" -ForegroundColor Green
        }
        else {
            Write-Host "Spotted some differences. Fetching newest version from GitHub..." -ForegroundColor Yellow
            while ($retries -le 3) {
                Copy-Item "$temp/Microsoft.PowerShell_profile.ps1" -Destination $PROFILE -Force
                . $PROFILE
                $retries++
                Write-Host "Profile has been updated." -ForegroundColor Green
                return
            }
            Write-Error "Could not update Profile after 3 retries."
        }
    }
    catch {
        Write-Error "unable to check for `$profile updates"
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    Remove-Variable @("newhash", "oldhash", "url") -ErrorAction SilentlyContinue
    Remove-Item  "$temp/Microsoft.PowerShell_profile.ps1" -ErrorAction SilentlyContinue
}
function Set-WindowsTerminalProfile {
    $windowsProfileSettingsPath = "$($env:USERPROFILE)\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
    if (-not (Test-Path $windowsProfileSettingsPath)) {
       
    }
}
# Import Terminal Icons
if ($PSVersionTable.PSEdition -eq "Core" ) {
    Import-Module -Name Terminal-Icons -ErrorAction Stop
}

function isAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) 
}

# If so and the current host is a command line, then change to red color 
# as warning to user that they are operating in an elevated context
# Useful shortcuts for traversing directories
function wsl { wsl.exe ~ }
function cd... { Set-Location ..\.. }
function cd.... { Set-Location ..\..\.. }

# Compute file hashes - useful for checking successful downloads 
function md5 { Get-FileHash -Algorithm MD5 $args }
function sha1 { Get-FileHash -Algorithm SHA1 $args }
function sha256 { Get-FileHash -Algorithm SHA256 $args }

# Quick shortcut to start notepad
function n++ { notepad++ $args }
function n { notepad $args }

# Drive shortcuts
function HKLM: { Set-Location HKLM: }
function HKCU: { Set-Location HKCU: }
function Env: { Set-Location Env: }
function home: { Set-Location $env:HOMEPATH }
function ex ($argList) {
    if (-not $argList) {
        $argList = $pwd
    }
    & explorer.exe $args
}

function desk { Set-Location "$HOME\Desktop" }
function desktop { Set-Location "$HOME\Desktop" }
function home { Set-Location $HOME } 
function tmp { Set-Location "c:\tmp" } 
function dl { Set-Location "$HOME\Downloads" }
# Creates drive shortcut for Work Folders, if current user account is using it
if (Test-Path "$env:USERPROFILE\Work Folders") {
    New-PSDrive -Name Work -PSProvider FileSystem -Root "$env:USERPROFILE\Work Folders" -Description "Work Folders"
    function Work: { Set-Location Work: }
}

# Set up command prompt and window title. Use UNIX-style convention for identifying 
# whether user is elevated (root) or not. Window title shows current version of PowerShell
# and appends [ADMIN] if appropriate for easy taskbar identification
function prompt { 
    if (isAdmin) {
        "[" + (Get-Location) + "] # " 
    }
    else {
        "[" + (Get-Location) + "] $ "
    }
}

$Host.UI.RawUI.WindowTitle = "PowerShell {0}" -f $PSVersionTable.PSVersion.ToString()
if (isAdmin) {
    $Host.UI.RawUI.WindowTitle += " [ADMIN]"
}

# Does the the rough equivalent of dir /s /b. For example, dirs *.png is dir /s /b *.png
function dirs {
    if ($args.Count -gt 0) {
        Get-ChildItem -Recurse -Include "$args" | Foreach-Object FullName
    }
    else {
        Get-ChildItem -Recurse | Foreach-Object FullName
    }
}

# Simple function to start a new elevated process. If arguments are supplied then 
# a single command is started with admin rights; if not then a new admin instance
# of PowerShell is started.
function admin {
    if ($args.Count -gt 0) {   
        $argList = "& '" + $args + "'"
        Start-Process "pwsh.exe" -Verb RunAs -ArgumentList $argList
    }
    else {
        Start-Process "pwsh.exe" -Verb RunAs
    }
}

# Set UNIX-like aliases for the admin command, so sudo <command> will run the command
# with elevated rights. 
Set-Alias -Name su -Value admin
Set-Alias -Name sudo -Value admin

# Make it easy to edit this profile once it's installed
function Edit-Profile {
    if ($host.Name -match "ise") {
        $psISE.CurrentPowerShellTab.Files.Add($profile.CurrentUserAllHosts)
    }
    else {
        notepad $profile.CurrentUserAllHosts
    }
}

Function Test-CommandExists {
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try { if (Get-Command $command) { RETURN $true } }
    Catch { Write-Host "$command does not exist"; RETURN $false }
    Finally { $ErrorActionPreference = $oldPreference }
} 
#
# Aliases
$vimExe = ((Get-Childitem -Recurse -Path "C:\tools\vim\") | Where-Object Name -eq 'vim.exe').FullName 
Set-Alias -Name vim -Value $vimExe.ToString()

function ll { Get-ChildItem -Path $pwd -File }
function repos { Set-Location c:\repos }

# git functions

function git-nuke {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BranchName
    )
    $branch = git branch --list $BranchName
    if ($null -ne $branch) {
        Write-Warning "Branch '$BranchName' will be nuked locally and from origin. Are you sure? (y/n)"
        $answer = Read-Host
        if ($answer -eq 'y') {
            git branch -D $BranchName
            git push origin --delete $BranchName
        }
    }
}

function gcom {
    git add .
    git commit -m "$args"
}

function lazyg {
    git add .
    git commit -m "$args"
    git push
}

function netcpl {
    control.exe /name Microsoft.NetworkAndSharingCenter
}

function Get-PublicIP {
    (Invoke-WebRequest "http://ifconfig.me/ip" ).Content
}
function Test-ADCredential {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Credential')]
        [ValidateNotNull()]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $true, ParameterSetName = 'UserPass')]
        [ValidateNotNullOrEmpty()]
        [string]$UserName,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'UserPass')]
        [ValidateNotNullOrEmpty()]
        [securestring]$Password
    )

    if ($PSCmdlet.ParameterSetName -eq 'Credential') {
        $UserName = $Credential.UserName
        $Password = $Credential.Password
    }

    if ($UserName -match '([a-zA-Z0-9]+)@([a-zA-Z0-9]+)\.([a-zA-Z]+)') {
        $UserName = $Matches[1]
    }

    if ($UserName -match '([a-zA-Z0-9]+)\\([a-zA-Z0-9]+)') {
        $UserName = $matches[2]
    }
    Write-Host "Username: '$UserName'."

    if ($PSCmdlet.ParameterSetName -eq 'Credential') {
        $UserName = $Credential.UserName
        $Password = $Credential.Password
    }
    
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('domain')
    $DS.ValidateCredentials($UserName, (ConvertFrom-SecureString -SecureString $Password -AsPlainText))

}

function Connect-VPN {
    try {

        if (-not(Test-Path $env:USERPROFILE\.vpncreds)) {
            Write-Warning "Could not find '.vpncreds' in user profile."
            $creds = Get-Credential -Message "Please enter your VPN credentials" -UserName $env:USERNAME
            $creds | Export-Clixml -Path $env:USERPROFILE\.vpncreds
        }        
       $creds = Import-Clixml -Path $env:USERPROFILE\.vpncreds
        $vpnConnection = Get-VpnConnection | Where-Object ServerAddress -eq 'sslvpn.root.ch'
        
        if ($null -eq $vpnConnection) {
            Write-Error "Could not find VPN connection."
        }

        if ($vpnConnection.ConnectionStatus -eq 'Disconnected') {
            Write-Information "Trying to connect VPN..."
            & rasdial.exe $($vpnConnection.Name) $creds.UserName $creds.GetNetworkCredential().Password
        }
    
        #    $routeIPConfiguration = Get-NetIPConfiguration | Where-Object {$_.IPv4Address.IPAddress -like "10.125.0.*"}
        #    $homeNetworkAccessible = $null -ne $routeIPConfiguration

        #    if($homeNetworkAccessible){
        #        $cmd = "New-NetRoute -DestinationPrefix 10.125.0.0/24 -NextHop 10.125.0.129 -InterfaceIndex $($routeIPConfiguration.InterfaceIndex); Read-host"
        #        $cmd | out-file $env:userprofile\.vpnroute
        #        Start-Process "pwsh.exe" -Verb RunAs -WorkingDirectory $env:USERPROFILE -ArgumentList $env:USERPROFILE\.vpnroute -Wait
        #    }
        #    Write-Host "VPN already connected." -ForegroundColor Yellow
    }
    catch {
        Write-Error $_.Exception.Message
    }
} 

function Reset-WindowsUpdateCache {
    if (-not (isAdmin)) {
        Write-Host "This function must be run as an administrator." -ForegroundColor Red
        return
    }
    Stop-Service -Name wuauserv, cryptSvc, bits, msiserver -Force

    Rename-Item -Path 'C:\Windows\SoftwareDistribution' -NewName 'SoftwareDistribution.old' -Force
    Rename-Item -Path 'C:\Windows\System32\catroot2' -NewName 'Catroot2.old' -Force

    Start-Service -Name wuauserv, cryptSvc, bits, msiserver

    Remove-Item -Path 'C:\Windows\SoftwareDistribution.old' -Recurse -Force
    Remove-Item -Path 'C:\Windows\System32\catroot2.old' -Recurse -Force

    Write-Output "Windows Update service has been reset and cache cleared."
}

Set-Alias -Name vpnup -Value Connect-VPN

function Disconnect-VPN {
    & rasdial.exe /disconnect
}

Set-Alias -Name vpndown -Value Disconnect-VPN

function Get-VPNStatus {
    Write-Output (Get-VpnConnection | Where-Object ServerAddress -eq 'sslvpn.root.ch' | Select-Object -ExpandProperty ConnectionStatus)
}

Set-Alias -Name getvpn -Value Get-VPNStatus

function uptime {
    #Windows Powershell only
    If ($PSVersionTable.PSVersion.Major -eq 5 ) {
        Get-WmiObject win32_operatingsystem |
        Select-Object @{EXPRESSION = { $_.ConverttoDateTime($_.lastbootuptime) } } | Format-Table -HideTableHeaders
    }
    Else {
        net statistics workstation | Select-String "since" | foreach-object { $_.ToString().Replace('Statistics since ', '') }
    }
}

## Github Copilot
function ghc {
    gh copilot $args
}

function Import-PSProfile {
    & $profile
}

Set-Alias -Name Reload-PSProfile -Value Import-PSProfile 
function Find-File($name) {
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        $place_path = $_.directory
        Write-Output "${place_path}\${_}"
    }
}

function unzip ($file) {
    Write-Output("Extracting", $file, "to", $pwd)
    $fullFile = Get-ChildItem -Path $pwd -Filter .\cove.zip | ForEach-Object { $_.FullName }
    Expand-Archive -Path $fullFile -DestinationPath $pwd
}

function ix ($file) {
    curl.exe -F "f:1=@$file" ix.io
}

function grep($regex, $dir) {
    if ( $dir ) {
        Get-ChildItem $dir | select-string $regex
        return
    }
    $input | select-string $regex
}

function touch($file) {
    "" | Out-File $file -Encoding utf8
}

function df {
    get-volume
}

function sed($file, $find, $replace) {
    (Get-Content $file).replace("$find", $replace) | Set-Content $file
}

function which($name) {
    Get-Command $name | Select-Object -ExpandProperty Definition
}

function export($name, $value) {
    set-item -force -path "env:$name" -value $value;
}

function pkill($name) {
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process
}

function pgrep($name) {
    GASCIIet-Process $name
}

# Import the Chocolatey Profile that contains the necessary code to enable
# tab-completions to function for `choco`.
# Be aware that if you are missing these lines from your profile, tab completion
# for `choco` will not function.
# See https://ch0.co/tab-completion for details.
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
    Import-Module "$ChocolateyProfile"
}

Invoke-Expression (& { (zoxide init powershell | Out-String) })


## Final Line to set prompt
oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\tokyo.omp.json" | Invoke-Expression
