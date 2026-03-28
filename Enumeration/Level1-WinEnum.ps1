<#
.SYNOPSIS
Windows Enumeration for Privilege Escalation (Level 1)

.DESCRIPTION
Powershell Script for Enumeration/Scanning possible permissions flaws or vulnerabilities in improper system configurations.

.NOTES
- I have a lot of admiration and respect for the work of https://github.com/peass-ng 
(from whom I learned to put this script together). 

- Sources such as: https://book.hacktricks.wiki/ have been of great use and learning.

- I intend to continue my studies and add/improve the processes I have written in this script.
#>

function Write-ColorHost {
    param (
        [string] $Text,
        [string] $Color
    )
    Write-Host -ForegroundColor $Color $Text -NoNewline
}

function Get-RemoteSessionInfo {
    Write-ColorHost "Remote Sessions: " "Magenta"
    
    try {
        qwinsta 2>$null
    }
    catch {
        try {
            $sessions = Get-CimInstance -ClassName Win32_LogonSession -Filter "LogonType=10" -ErrorAction SilentlyContinue
            
            if ($sessions) {
                $sessions | ForEach-Object {
                    Write-Host "Session ID: $($_.LogonId)"
                    Write-Host "User: $($_.Name)"
                    Write-Host "Logon Time: $($_.StartTime)"
                    Write-Host "---"
                }
            }
            else {
                Write-ColorHost "No RDP sessions detected" "Yellow"
            }
        }
        catch {
            Write-ColorHost "[!] Could not retrieve remote session info: $_" "Red"
        }
    }
}

function Get-LoggedOnUserInfo {
    Write-ColorHost "`nCurrent Logged on Users: `n`n" "Magenta"
    
    $commandExists = $null -ne (Get-Command quser -ErrorAction SilentlyContinue)
    
    if ($commandExists) {
        quser 2>$null
    }
    else {    
        try {
            $loggedOnUsers = @()
            
            $explorerProcesses = Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue
            
            if ($explorerProcesses) {
                foreach ($process in $explorerProcesses) {
                    $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner -ErrorAction SilentlyContinue
                    
                    if ($owner) {
                        $loggedOnUsers += [PSCustomObject]@{
                            User = "$($owner.Domain)\$($owner.User)"
                            Session = "Interactive"
                            Id = $process.ProcessId
                        }
                    }
                }
                
                if ($loggedOnUsers.Count -gt 0) {
                    $loggedOnUsers | Sort-Object User -Unique | ForEach-Object {
                        Write-Host "User: $($_.User)"
                        Write-Host "Session Type: $($_.Session)"
                        Write-Host "---"
                    }
                }
                else {
                    Write-ColorHost "No interactive sessions detected" "Yellow"
                }
            }
            else {
                Write-ColorHost "No interactive sessions detected" "Yellow"
            }
        }
        catch {
            Write-ColorHost "[!] Could not retrieve logged-on user info: $_" "Red"
        }
    }
}

# -> THIS FUNCTION IS NOT MINE, THAT'S WHY IT'S SO GOOD!!!
# -> COLLECTS DETAILED INFORMATION ABOUT THE INSTALLED ANTIVIRUS PRODUCTS
# I Forgot the name of the original author, but I want to give him credit for this function, it's really well done.
# If he contacts me, I will update the credits here, but for now, thank you very much for sharing this...
function Get-AntiVirusProductInfo {
    [CmdletBinding()]
    param (
        [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('name')]
        $computername=$env:computername
    )

    $AntiVirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ComputerName $computername

    $ret = @()
    foreach($AntiVirusProduct in $AntiVirusProducts){

        switch ($AntiVirusProduct.productState) {
            "262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
            "262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
            "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
            "266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
            "393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
            "393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
            "393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
            "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
            "397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
            "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
            default {$defstatus = "Unknown" ;$rtstatus = "Unknown"}
        }

        $ht = @{}
        $ht.Computername = $computername
        $ht.Name = $AntiVirusProduct.displayName
        $ht.'Product GUID' = $AntiVirusProduct.instanceGuid
        $ht.'Product Executable' = $AntiVirusProduct.pathToSignedProductExe
        $ht.'Reporting Exe' = $AntiVirusProduct.pathToSignedReportingExe
        $ht.'Definition Status' = $defstatus
        $ht.'Real-time Protection Status' = $rtstatus

        $ret += New-Object -TypeName PSObject -Property $ht 
    }
    
    Return $ret
}

function Get-SystemHotFixes {
    $OS_HotFixes = Get-HotFix -Description "Update" | Select-Object HotFixId, InstalledOn
    return $OS_HotFixes | Format-Table -Property HotFixId, InstalledOn -AutoSize
}

function Get-RegistryKeyValue {
    param (
        [string] $keyPath,
        [string] $keyName
    )

    if (-not (Test-Path $keyPath)) {
        Write-ColorHost "Registry path not found: $keyPath" "Red"
        return
    }

    try {
        $item = Get-ItemProperty -Path $keyPath -ErrorAction Stop
        if ($null -eq $item.$keyName) {
            Write-ColorHost "Key '$keyName' not found at path: $keyPath" "Red"
            return
        }

        if ($keyName -eq "CACHEDLOGONSCOUNT") {
            Write-Output "$($item.$keyName)"
            return
        }

        switch ($item.$keyName) {
            0 { Write-ColorHost "[0] Disabled" "Yellow" }
            1 { Write-ColorHost "[1] Enabled/Found!!" "Green" }
            default { Write-ColorHost "Unexpected key value: $($item.$keyName)" "Yellow" }
        }
    }
    catch {
        Write-ColorHost "[X] Error reading registry value: $_" "Red"
    }
}

function Test-LSAProtection {
    try {
        $lsaProtection = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\LSA).RunAsPPL
    
        switch ($lsaProtection) {
            2 { Write-Host "Enabled without UEFI Lock" }
            1 { Write-Host "Enabled with UEFI Lock" }
            0 { Write-ColorHost "Protection is Disabled!!" "Green" }
            Default { Write-ColorHost "The system was unable to find the specified registry value" "Red"}
        }
    } 
    catch {
        return "Unexpected registry value: $lsaProtection"
    }
}

function Test-UACStatus {
    try {
        $uacEnabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction Stop).EnableLUA
        
        if ($uacEnabled -eq 1) {
            Write-Host "EnableLua is set to 1. UAC Features are active!"
        }
        else {
            Write-ColorHost "EnableLUA is not active!!" "Green"
        }
    }
    catch {
        Write-ColorHost "[X] Could not read EnableLUA setting." "Red"
    }
}

function Test-CredentialGuardAndLAPS {
    [CmdletBinding()]
    param ()

    try {
        $lsaCfg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -ErrorAction Stop
        switch ($lsaCfg.LsaCfgFlags) {
            2 { Write-Host "Value: 2 - Credential Guard Enabled (without UEFI Lock)" }
            1 { Write-Host "Value: 1 - Credential Guard Enabled (with UEFI Lock)" }
            0 { Write-ColorHost "Value: 0 - Credential Guard Disabled!" "Green" }
            Default { Write-ColorHost "LsaCfgFlags: Unknown value - $($lsaCfg.LsaCfgFlags)`n" "Red" }
        }
    } 
    catch {
        Write-Warning "Could not access LSA registry key (LsaCfgFlags)."
    }

    Write-ColorHost "`nLAPS (Local Admin Password Solution) Check: " "Yellow"
    $lapsPaths = @(
        "C:\Program Files\LAPS\CSE\Admpwd.dll",
        "C:\Program Files (x86)\LAPS\CSE\Admpwd.dll"
    )
    $lapsFound = $false

    foreach ($path in $lapsPaths) {
        if (Test-Path $path) {
            Write-ColorHost "LAPS DLL found: $path" "Green"
            $lapsFound = $true
        }
    }

    if (-not $lapsFound) {
        Write-ColorHost "LAPS DLL not found on this machine." "Red"
    }

    try {
        $lapsPolicy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd" -ErrorAction Stop
        
        if ($lapsPolicy.AdmPwdEnabled -eq 1) {
            Write-ColorHost "LAPS GPO is enabled via registry." "Green"
        } 
        else {
            Write-ColorHost "LAPS GPO found but not enabled." "Yellow"
        }
    } 
    catch {
        Write-ColorHost "LAPS GPO registry key not found." "Red"
    }
}

function Get-InstalledApplicationsList {
    [CmdletBinding()]
    param ()

    $apps = @()

    $registryPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $registryPaths) {
        try {
            $entries = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -and $_.DisplayName -ne "" } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

            $apps += $entries
        } 
        catch {
            Write-Warning "Could not read from registry path: $path"
        }
    }

    if ($apps.Count -eq 0) {
        Write-ColorHost "No applications found." "Red"
    } 
    else {
        $apps | Sort-Object DisplayName | Format-Table -AutoSize `
            @{Name='Application'; Expression={$_.DisplayName}},
            @{Name='Version'; Expression={$_.DisplayVersion}},
            @{Name='Publisher'; Expression={$_.Publisher}},
            @{Name='Install Date'; Expression={ 
                if ($_.InstallDate -match '^\d{8}$') {
                    [datetime]::ParseExact($_.InstallDate, 'yyyyMMdd', $null).ToShortDateString()
                } 
                else {
                    $null
                }
            }}
    }
}

function Get-CommandHistory {
    Write-ColorHost "`nHKCU recent commands: " "Blue"

    if ($runMRUKey) {
        $properties = $runMRUKey.Property | Where-Object { $_ -ne "MRUList" }
        $entries = @()
    
        foreach ($prop in $properties) {
            $value = $runMRUKey.GetValue($prop)
        
            if ($value) {
                Write-Output "`n"
                $entries += "$prop : $value"
            }
        }
    
        if ($entries.Count -gt 0) {
            $entries | ForEach-Object { Write-Host $_ }
        } 
        else {
            Write-ColorHost "[!] Empty!" "DarkYellow"
        }
    } 
    else {
        Write-ColorHost "[X] Could not retrieve RunMRU registry key." "Red"
    }

    Write-ColorHost "`n`nPowerShell History (PSReadLine):`n" "Blue"
    $psHistoryPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    
    if (Test-Path $psHistoryPath) {
        Get-Content $psHistoryPath -Tail 20 | ForEach-Object { Write-Host $_ }
    } 
    else {
        Write-ColorHost "No PowerShell history file found." "Red"
    }

    Write-ColorHost "`nRecently Opened Files (RecentDocs) (Might be interesting):`n" "Blue"
    $recentDocsKey = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -ErrorAction SilentlyContinue
   
    if ($recentDocsKey) {
        foreach ($subKey in $recentDocsKey) {
            $key = Get-ItemProperty -Path $subKey.PSPath -ErrorAction SilentlyContinue
            $key.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' } | ForEach-Object {
                $val = $_.Value -as [byte[]]
   
                if ($val) {
                    try {
                        $str = [System.Text.Encoding]::Unicode.GetString($val) -replace '\x00', ''
                        Write-Host $str
                    } 
                    catch {}
                }
            }
        }
    }
    else {
        Write-ColorHost "RecentDocs registry key not found." "Red"
    }

    Write-ColorHost "`nExecutables from Prefetch Folder (Might be interesting):`n" "Blue"
    $prefetchPath = "$env:SystemRoot\Prefetch"
    
    if (Test-Path $prefetchPath) {
        try {
            Get-ChildItem $prefetchPath -Filter *.pf -ErrorAction Stop | Select-Object -First 20 | ForEach-Object {
                Write-Host $_.Name
            }
        } 
        catch {
            Write-ColorHost "[X] Could not access Prefetch folder. Administrator privileges might be required.`n" "Red"
        }
    } 
    else {
        Write-ColorHost "Prefetch folder not accessible or disabled." "Red"
    }
}

function Get-ClipboardData {
    try {
        if (-not [System.Reflection.Assembly]::LoadWithPartialName("PresentationCore")) {
            Write-Host "Error loading the PresentationCore library."
            return
        }

        $clipboardContent = [Windows.Clipboard]::GetText()

        if ($clipboardContent) {
            Write-Host $clipboardContent
        } 
        else {
            Write-Host "The clipboard is empty."
        }
    } 
    catch {
        Write-Host "An error occurred while accessing the clipboard: $_"
    }   
}

function Get-SMBShareInfo {
    if (-not (Get-Command -Name Get-SmbShare -ErrorAction SilentlyContinue)) {
        Write-ColorHost "SMB is not available or not enabled on this system. `n" "Red"
        return
    }

    $userGroups = whoami.exe /groups /fo csv |
        Select-Object -Skip 2 |
        ConvertFrom-Csv -Header 'GroupName' |
        Select-Object -ExpandProperty GroupName

    $shares = Get-SmbShare | Get-SmbShareAccess

    if (-not $shares) {
        Write-ColorHost "No available SMB shares found on this system. `n" "Red"
        return
    }

    $foundMatch = $false

    foreach ($share in $shares) {
        foreach ($group in $userGroups) {
            $isSameGroup = ($share.AccountName -like $group)
            $hasPermission = $share.AccessRight -in @('Full', 'Change')
            $isAllowed = $share.AccessControlType -eq 'Allow'

            if ($isSameGroup -and $hasPermission -and $isAllowed) {
                Write-Output "`n"
                Write-ColorHost "$($share.AccountName) has $($share.AccessRight) access to share '$($share.Name)'" "Green"
                $foundMatch = $true
            }
        }
    }

    if (-not $foundMatch) {
        Write-ColorHost "No SMB share permissions matched your current user groups. `n" "Red"
    }
}

function Test-FileSystemPermissions {
    param(
        [Parameter(Mandatory=$true)][string]$Target
    )

    if (-not (Test-Path $Target)) {
        Write-ColorHost "Path not found: $Target`n" "Red"
        return
    }

    try {
        $acl = Get-Acl -Path $Target
    } 
    catch {
        Write-ColorHost "Failed to read ACL for $Target`n" "Red"
        return
    }

    $user = "$env:COMPUTERNAME\$env:USERNAME"
    $groups = (whoami /groups /fo csv | Select-Object -Skip 2 | ConvertFrom-Csv -Header "GroupName") | Select-Object -ExpandProperty GroupName
    $identities = @($user) + $groups

    $found = $false

    foreach ($entry in $acl.Access) {
        foreach ($id in $identities) {
            if ($entry.IdentityReference -like "*$id") {
                $perm = $entry.FileSystemRights
                if ($perm -match "FullControl|Modify|Write") {
                    $found = $true
        
                    Write-ColorHost "`n`n[!] Potential misconfigured access" "Green"
                    Write-ColorHost "`n -> " "Yellow" 
                    Write-ColorHost "Identity '$($entry.IdentityReference)' has '$perm' on '$Target'" "White"
                }
            }
        }
    }

    if (-not $found) {
        Write-ColorHost "`nNo concerning permissions found for $Target`n" "Red"
    }
}

function Get-ScheduledTasksStatus {
    $tasksPath = "C:\Windows\System32\Tasks"

    if ((Test-Path $tasksPath) -and (Get-ChildItem $tasksPath -ErrorAction SilentlyContinue)) {
        Write-ColorHost "Access confirmed!! Proceed from here:`n" "Green"
        Write-ColorHost "-> $tasksPath`n`n" "Blue"

        Get-ChildItem $tasksPath | ForEach-Object {
            Write-Host " - $($_.FullName)`n"
        }
    }
    else {
        Write-ColorHost "`nNo admin access to $tasksPath. Listing non-Microsoft scheduled tasks instead...`n" "Red"

        Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | ForEach-Object {
            $taskInfo = $_ | Get-ScheduledTaskInfo
            $Actions = $_.Actions.Execute
            
            if ($Actions) {
                foreach ($a in $Actions) {
                    $resolvedPath = $a -replace '"', ''
                    
                    $resolvedPath = $resolvedPath -replace "%windir%", $env:windir
                    $resolvedPath = $resolvedPath -replace "%SystemRoot%", $env:windir
                    $resolvedPath = $resolvedPath -replace "%localappdata%", "$env:UserProfile\AppData\Local"
                    $resolvedPath = $resolvedPath -replace "%appdata%", $env:AppData

                    Test-FileSystemPermissions -Target $resolvedPath

                    Write-ColorHost "`n`nTaskName: $($_.TaskName)`n" "Cyan"
                    Write-Host "--------------------------------------------"
                    
                    [PSCustomObject]@{
                        LastResult = $taskInfo.LastTaskResult
                        NextRun    = $taskInfo.NextRunTime
                        Status     = $_.State
                        Command    = $_.Actions.Execute
                        Arguments  = $_.Actions.Arguments
                    } | Format-List
                }
            }
        }
    }
}

function Get-ProcessPermissions {
    Write-Host "`n"

    $processes = Get-Process | Where-Object { $_.Path } | Select-Object -ExpandProperty Path -Unique
    
    foreach ($processPath in $processes) {
        Write-ColorHost "`n-> " "yellow"
        Write-Host "Process Path: $processPath"
        
        if ($null -ne $processPath) {
            try {
                $ACLObject = Get-Acl $processPath -ErrorAction SilentlyContinue
            }
            catch {
                Write-ColorHost "Error: Could not retrieve ACL for $processPath" "Red"
                continue
            }

            if ($ACLObject) {
                $userPermissions = @()

                $identities = @("$env:COMPUTERNAME\$env:USERNAME")
                $identities += (whoami.exe /groups /fo csv | Select-Object -Skip 2 | ConvertFrom-Csv -Header 'group name' | Select-Object -ExpandProperty 'group name')

                foreach ($identity in $identities) {
                    $ACLObject.Access | Where-Object { $_.IdentityReference -like $identity } | ForEach-Object {
                        $permission = ""

                        switch -Wildcard ($_.FileSystemRights) {
                            "FullControl" { $permission = "FullControl" }
                            "Write*" { $permission = "Write" }
                            "Modify" { $permission = "Modify" }
                        }

                        if ($permission) {
                            $userPermissions += "$identity has '$permission' permissions"
                        }
                    }
                }

                if ($userPermissions.Count -gt 0) {
                    Write-ColorHost "Permissions for ${processPath}: `n" "Green"
                    $userPermissions | ForEach-Object { Write-Host $_ }
                } 
                else {
                    Write-ColorHost "No specific user permissions found for $processPath`n" "DarkRed"
                }
            }
        }
    }
}

function Test-RegistryValue {
    param (
        [string] $value
    )
    
    if ($null -eq $value -or $value -eq "") {
        Write-ColorHost "No Value has been found! `n" "red"
    } 
    else {
        Write-Output "$value"
    }
}

#########################################################

Write-Output ("{0,-50}" -f"======================================================")

$OS_info = Get-ComputerInfo -Property WindowsProductName 
$OS_Version = Get-ComputerInfo -Property OSVersion | Select-Object -ExpandProperty OSVersion
$Output_info = $OS_info -replace ".*=" -replace "}"
$OS_Hostname = [System.Environment]::UserDomainName
$OS_CurrentUsername = [System.Environment]::UserName
$OS_SystemUsers = Get-WmiObject -Class Win32_UserAccount | Select-Object Name 
$Output_Users = $OS_SystemUsers | ForEach-Object { $_.Name } 
$Home_Folders = Get-ChildItem C:\Users

Write-ColorHost "`nOperational System: " "Green"
Write-Host "$Output_info | $OS_Version"
Write-ColorHost "Hostname: " "Green"
Write-Host $OS_Hostname
Write-ColorHost "Current Username: " "Green"
Write-Host $OS_CurrentUsername
Write-ColorHost "Other Users: " "Green"
Write-Host ($Output_Users -join ", ") "`n"  
Write-ColorHost "Home Folders: "  "Green"
Write-Host ($Home_Folders -join ", ") "`n"
Write-Output ("{0,-50}`n" -f"======================================================")

Write-ColorHost "Users directory (read acess): `n" "Magenta"

Get-ChildItem C:\Users\* | ForEach-Object {
    if (Get-ChildItem $_.FullName -ErrorAction SilentlyContinue) {
        Write-ColorHost "`n->" "Yellow"
        Write-ColorHost " Read Access to $($_.FullName)" "Green"
    }
}

Write-Output ("`n`n{0,-50}`n" -f"======================================================")

$defaultDomain = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultDomainName
$defaultUser = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultUserName
$defaultPassword = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultPassword
$altDefaultDomain = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultDomainName
$altDefaultUser = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultUserName
$altDefaultPassword = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultPassword

Write-ColorHost "`nDefault Domain " "Magenta"
Test-RegistryValue $defaultDomain
Write-ColorHost "Default User " "Magenta"
Test-RegistryValue $defaultUser
Write-ColorHost "Default Password " "Magenta"
Test-RegistryValue $defaultPassword
Write-ColorHost "Alternate Default Domain " "Magenta"
Test-RegistryValue $altDefaultDomain
Write-ColorHost "Alternate Default User " "Magenta"
Test-RegistryValue $altDefaultUser
Write-ColorHost "Alternate Default Password " "Magenta"
Test-RegistryValue $altDefaultPassword

Get-RemoteSessionInfo
Get-LoggedOnUserInfo

Write-Output ("`n`n{0,-50}`n" -f"======================================================")

Write-ColorHost "`nCurrent Privileges: `n`n" "Magenta"
whoami /priv

Write-Output ("`n`n{0,-50}`n" -f"======================================================")

Write-ColorHost "Antivirus: " "Magenta"
Get-AntiVirusProductInfo

Write-Output ("{0,-50}`n" -f"======================================================")

Write-ColorHost "Installed Applications: " "Magenta"
Get-InstalledApplicationsList

Write-Output ("{0,-50}`n" -f"======================================================")

Write-ColorHost "Process Info/Permissions: " "Magenta"
Get-ProcessPermissions

Write-Output ("`n{0,-50}`n" -f"======================================================")

Write-ColorHost "`Checking access to scheduled tasks folder:`n" "Magenta"
Get-ScheduledTasksStatus

Write-Output ("`n{0,-50}`n" -f"======================================================")

Write-ColorHost "HotFixes: `n" "Yellow"
Get-SystemHotFixes

Write-Output ("{0,-50}`n" -f"======================================================")

Write-ColorHost "AlwaysInstallElevated (HKCU): " "Yellow"
Write-Host "$(Get-RegistryKeyValue -keyPath 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -keyName 'AlwaysInstallElevated')"

Write-ColorHost "AlwaysInstallElevated (HKLM): " "Yellow"
Write-Host "$(Get-RegistryKeyValue -keyPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -keyName 'AlwaysInstallElevated')`n"

Write-ColorHost "WDigest (Plain-Text Password Storage LSASS): " "Yellow"
Write-Host "$(Get-RegistryKeyValue -keyPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -keyName 'UseLogonCredential')`n"

Write-ColorHost "Cached WinLogon Credentials: " "Yellow"
Write-Host "$(Get-RegistryKeyValue -keyPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -keyName 'CACHEDLOGONSCOUNT')`n"

Write-ColorHost "Checking SNMP Passwords: " "Yellow"
Write-Host "$(Get-RegistryKeyValue -keyPath 'HKLM:\SYSTEM\CurrentControlSet\Services\' -keyName 'SNMP')`n"

Write-ColorHost "Checking WinVNC Passwords: " "Yellow"
Write-Host "$(Get-RegistryKeyValue -keyPath 'HKCU:\Software\ORL\WinVNC3\' -keyName 'Password')`n"

Write-ColorHost "Checking LSA Protection...: " "Yellow"
Test-LSAProtection

Write-ColorHost "`n`nChecking UAC Settings...: " "Yellow"
Test-UACStatus

Write-ColorHost "`n`nChecking Windows Event Forwarding: " "Yellow"
if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager) {
    Get-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
}
else {
    Write-ColorHost "The log entry was not found, it is not possible know where the logs are being saved.`n" "Red"
}

Write-ColorHost "`nChecking Audit Log Settings: " "Yellow"
if ((Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\).Property) {
    Get-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\
}
else {
    Write-ColorHost "The system was unable to find the Audit Log settings, registry key or value.`n" "Red"
}

Write-ColorHost "`nCredential Guard Check: " "Yellow"
Test-CredentialGuardAndLAPS
Write-Host "`n"

if (Test-Path HKCU:\Software\OpenSSH\Agent\Keys) {
    Write-ColorHost "`n[+] " "Green"
    Write-Output "OpenSSH keys found! Try Extracting the keys! `n"
}
else {
    Write-ColorHost "`n[X] " "Red"
    Write-Output "No OpenSSH Keys found!" 
}

Write-Output ("`n{0,-50}`n" -f"======================================================")
Write-ColorHost "Clipboard info:`n`n" "Yellow" 
Write-ColorHost "Trying to read clipboard info...`n" "Blue" 
Get-ClipboardData

Write-Output ("`n{0,-50}`n" -f"======================================================")

Write-ColorHost "Extracting windows command history...:`n" "Yellow"
Get-CommandHistory

Write-Output ("`n{0,-50}`n" -f"======================================================")

Write-ColorHost "Listing SMBSHARES with acess permissions: " "Yellow"
Get-SMBShareInfo

Write-Output ("`n{0,-50}`n" -f"======================================================")

Write-ColorHost "Checking PowerShell Execution Policy:`n" "Yellow"

try {
    $execPolicies = Get-ExecutionPolicy -List
    
    $execPolicies | ForEach-Object {
        Write-ColorHost "Scope: " "Cyan"
        Write-Host "$($_.Scope) - Policy: $($_.ExecutionPolicy)"
    }

    $localMachinePolicy = ($execPolicies | Where-Object { $_.Scope -eq 'LocalMachine' }).ExecutionPolicy
    
    if ($localMachinePolicy -eq 'Restricted') {
        Write-ColorHost "`n[!] Execution policy at LocalMachine scope is set to 'Restricted' (scripts are disabled).`n`n" "Red"
    }
    elseif ($localMachinePolicy -in @('Unrestricted', 'Bypass', 'Undefined')) {
        Write-ColorHost "`n[+] Execution policy at LocalMachine scope allows script execution: $localMachinePolicy.`n`n" "Green"
    }
}
catch {
    Write-ColorHost "`n[X] Failed to retrieve execution policy information.`n`n" "Red"
}

#########################################################
