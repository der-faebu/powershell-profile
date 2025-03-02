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
    [CmdletBinding(
        DefaultParameterSetName = 'ServerName'
    )]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'NoDNS')]
        [switch]$NoDNS,

        [Parameter(Mandatory = $false, ParameterSetName = 'ServerName')]
        [string]$ServerName = "raw.githubusercontent.com"
    )

    Write-Debug "Parameter set name: $($PSCmdlet.ParameterSetName)"

    if (-not $NoDNS) {
        try {
            Write-Verbose "Trying to resolve DNS name '$ServerName'..."
            Resolve-DnsName -Name $ServerName -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Error "Could not resolve DNS name '$ServerName'."
            return $false
        }
    }
    else {
        Write-Verbose "Skipping DNS resolution."
        Write-Verbose "Setting ServerName to 1.1.1.1 ."
        $ServerName = "1.1.1.1"
    }

    try {
        Write-Verbose "Testing connection to '$ServerName' on port 443..."
        Test-Connection -ComputerName $ServerName -TcpPort 443 -Count 1 -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        Write-Debug "$($_.Exception.Message)"
        return $false
    }
}
function Update-RemoteFile {
    [CmdletBinding(DefaultParameterSetName = "Url")]
    param (
        [Parameter(Mandatory, ParameterSetName = "Url", Position = 0)]
        [ValidateNotNullOrWhiteSpace()]
        [string]$RemoteUrl,

        [Parameter(Mandatory, ParameterSetName = "File", Position = 0)]
        [ValidateNotNullOrWhiteSpace()]
        [string]$RemoteFile,

        [Parameter(Mandatory, Position = 1)]
        [ValidateNotNullOrWhiteSpace()]
        [string]$LocalFile
    )

    Begin {
        if (-not (Test-Path $LocalFile)) {
            Write-Host "Local file does not exist. Creating: $LocalFile"
            New-Item -Path $LocalFile -ItemType File -Force | Out-Null
        }

        $tempFile = New-TemporaryFile
    }

    Process {
        try {
            if ($PSCmdlet.ParameterSetName -eq "Url") {
                Invoke-WebRequest -Uri $RemoteUrl -OutFile $tempFile.FullName -ErrorAction Stop
            }
            elseif ($PSCmdlet.ParameterSetName -eq "File") {
                if (-not (Test-Path $RemoteFile)) {
                    Write-Error "Remote file does not exist: $RemoteFile"
                    return
                }
                Copy-Item -Path $RemoteFile -Destination $tempFile.FullName -Force
            }

            $localHash = (Get-FileHash -Path $LocalFile -Algorithm SHA256).Hash
            $remoteHash = (Get-FileHash -Path $tempFile.FullName -Algorithm SHA256).Hash

            if ($localHash -eq $remoteHash) {
                Write-Output "No changes detected. File is up to date."
                return
            }

            $backupFile = "$LocalFile.backup"
            Copy-Item -Path $LocalFile -Destination $backupFile -Force
            Write-Output "Backup created: $backupFile"

            Move-Item -Path $tempFile.FullName -Destination $LocalFile -Force
            Write-Output "File updated: $LocalFile"
        }
        catch {
            Write-Error "Failed to update '$LocalFile'"
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    End {
        if (Test-Path $tempFile.FullName) {
            Remove-Item -Path $tempFile.FullName -Force -ErrorAction SilentlyContinue
        }
    }
}

Update-RemoteFile -RemoteURL "https://raw.githubusercontent.com/der-faebu/powershell-profile/main/Microsoft.PowerShell_profile.ps1" -LocalFile $PROFILE 

# Import Terminal Icons
if ($PSVersionTable.PSEdition -eq "Core" ) {
    Import-Module -Name Terminal-Icons -ErrorAction Stop
}

function IsAdmin {
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

function ConvertFrom-Base64 {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]
        $Base64Value
    )
    process {
        $stringValue = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(($Base64Value)))
        Write-Output $stringValue
    }
}
function ConvertTo-Base64 {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]
        $StringValue
    )
    process {
        $base64Value = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($StringValue))
        Write-Output $base64Value
    }
}

# Function for showing used arguments during Chocolatey install
function Unprotect-ChocoArguments {
    <#
    .SYNOPSIS 
    Uncovers the arguments used during installation of a chocolatey package.
    
    .OUTPUTS 
    System.String
    
    .PARAMETER ChocoPackage 
    The name of the Chocolatey package.

    .NOTES
    Error codes:
    5: Chocolatey not installed
    1: Choco package not found
    2: .Arguments file not found
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$ChocoPackage
    )

    if (-not $env:ChocolateyInstall) {
        Write-Error 'Chocolatey does not seem to be installed on this system.' -ErrorId 5
    }

    $intrinsicPackageInfo = choco list -e -r $ChocoPackage
    $cName = $intrinsicPackageInfo.split('|')[0]
    $cVers = $intrinsicPackageInfo.Split('|')[1]

    if (-not (choco list -e -r $ChocoPackage)) {
        Write-Error "Package '$ChocoPackage' is not installed on the system." -ErrorId 1
    }

    $hiddenChocofolder = "$($env:ChocolateyInstall)\.chocolatey"
    $packageFolder = "$hiddenChocofolder\$cName.$cVers"
    
    # This should never happen but just in case...
    if (@($packageFolder).Length -gt 1) {
        Throw "Multiple packages were found. Please choose between these candiates: $($packageFolder | ForEach-Object {$_.Name -join ",`r`n"})"
    }
    $argsFile = Get-ChildItem -Path $packageFolder -File | Where-Object Name -eq '.arguments'
    Write-Host $argsFile
    if (-not (Test-Path $argsFile)) {
        Write-Error "No .arguments file found for package '$ChocoPackage'." -ErrorId 2
    }

    $entropyBytes = [System.Text.Encoding]::UTF8.GetBytes("Chocolatey")
    $encryptedBytes = [System.Convert]::FromBase64String([System.IO.File]::ReadAllText($argsFile.FullName))
    $decryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedBytes, $entropyBytes, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)

    $decryptedArgs = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
    Write-Output $decryptedArgs
}

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

function Connect-RootVPN {
    $vpnCredName = 'rootVPNCreds'

    if (-not (Get-Module -FullyQualifiedName CredentialManager -ListAvailable )) {
        try {
            Install-Module CredentialManager -Scope CurrentUser -Force -ErrorAction Stop
        }
        catch {
            Write-Error "Error installing or CredentialManager module. Please install it manually."
        }
    }

    try {
        Import-Module CredentialManager -ErrorAction stop
    }

    catch {
        Throw "Error importing 'CredentialManager' module: '$($_.Exception.Message)'."
    }

    $vpnCred = Get-StoredCredential -Target $vpnCredName

    if ($null -eq $vpnCred) {
        Write-Warning "Could not find a vpn crential in Windows Credential Manager."
        $creds = Get-Credential -Message "Please enter your VPN credentials" -UserName $env:USERNAME
        try {
            & cmdkey.exe /generic:$($vpnCredName) /user:$($creds.UserName) /pass:$($creds.GetNetworkCredential().Password)
        }
        catch {
            Write-Error "Could not save credential to Windows Credential store."
        }
    }

    $vpnConnection = Get-VpnConnection | Where-Object ServerAddress -eq 'sslvpn.root.ch'
        
    if ($null -eq $vpnConnection) {
        Write-Error "Could not find VPN connection."
    }

    if ($vpnConnection.ConnectionStatus -eq 'Disconnected') {
        Write-Information "Trying to connect VPN..."
        & rasdial.exe $($vpnConnection.Name) $vpnCred.UserName $($vpnCred.GetNetworkCredential().Password)
    }
    
    Write-Host "VPN already connected." -ForegroundColor Yellow
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

Set-Alias -Name vpnup -Value Connect-RootVPN

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

function Update-TerminalConfig {
    $terminalSettingsPath = @{
        Unpackaged = "$($env:LOCALAPPDATA)\Microsoft\Windows Terminal\settings.json"
        Stable     = "$($env:LOCALAPPDATA)\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
        Preview    = "$($env:LOCALAPPDATA)\Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState\settings.json"
    }
    
    foreach ($path in $terminalSettingsPath.GetEnumerator().Name) {
        if (Test-Path $terminalSettingsPath[$path]) {
            Copy-Item -Path $path -Destination "$path_.bak"
            Update-RemoteFile -RemoteURL "https://raw.githubusercontent.com/der-faebu/powershell-profile/refs/heads/main/terminal.settings.json" -LocalFile $path
        }
    }
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
