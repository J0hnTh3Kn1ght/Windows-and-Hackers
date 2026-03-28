<#
.SYNOPSIS
Windows Credential Scanner

.DESCRIPTION
This script scans the filesystem for files containing potential credentials, passwords, API keys, 
and other sensitive authentication information. 
The script can work with default file extensions (txt, log, ini, conf, xml, html, csv, json, env) 
or custom extensions you specify.

.EXAMPLE
.\LookForCredencials.ps1
Search for credentials in all common text file types across all drives

.\LookForCredencials.ps1 -Extensions ".txt,.xml"
Search only in txt and xml files

.\LookForCredencials.ps1 -Extensions ".conf,.ini,.config"
Target configuration files specifically

.\LookForCredencials.ps1 -OutputFile "results.txt"
Write all findings to results.txt instead of the console

.\LookForCredencials.ps1 -SearchPath "C:\Users" -OutputFile "C:\out.txt"
Scan only the C:\Users directory and save results to C:\out.txt

.NOTES
This tool searches for common credential patterns. 
Review findings carefully.
#>

[CmdletBinding()]
param (
    [switch] $Help,
    [string[]] $Extensions,
    [int] $MaxLines = 300,
    [string] $OutputFile,
    [string] $SearchPath
)

function Normalize-Extensions {
    param ([string[]] $ExtensionList)
    
    if ($ExtensionList -and $ExtensionList.Count -eq 1 -and $ExtensionList[0] -like "*,*") {
        $ExtensionList = $ExtensionList[0] -split "," | ForEach-Object {
            $_ = $_.Trim()
            if ($_ -notlike '.*') { ".$_" } else { $_ }
        }
    }
    
    return $ExtensionList
}

function Search-FilesForCredentials {
    param (
        [string[]] $Extensions,
        [int] $MaxLines,
        [string] $OutputFile,
        [string] $SearchPath
    )

    $Extensions = Normalize-Extensions -ExtensionList $Extensions

    $patterns += @(
        'password\s*[:=]\s*.+',
        'senha\s*[:=]\s*.+',
        'pass.*[=:].+',
        'pwd.*[=:].+',
        'secret\s*[:=]\s*.+',
        'client[_\-]?secret\s*[:=]\s*.+',
        'api[_\-]?key\s*[:=]\s*.+',
        'access[_\-]?token\s*[:=]\s*.+',
        'bearer\s+[a-zA-Z0-9\-_=]+\.*[a-zA-Z0-9\-_=]*',
        'authorization\s*[:=]?\s*(Basic|Bearer)?\s+[a-zA-Z0-9\-\._~\+\/]+=*',
        'user(name)?\s*[:=]\s*.+',
        'login\s*[:=]\s*.+',
        'usuario\s*[:=]\s*.+',
        'utilisateur\s*[:=]\s*.+',
        'usuário\s*[:=]\s*.+',
        'benutzer\s*[:=]\s*.+',
        'user id\s*[:=]\s*.+',
        'account\s*[:=]\s*.+',
        '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}',
        '((key|api|token|secret|password)[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}[''"]([0-9a-zA-Z_=\-]{8,64})[''"]'
    )
    $maxLines = $MaxLines
    $maxLineLength = 300
    $outputLines = @()

    if (-not $Extensions -or $Extensions.Count -eq 0) {
        $Extensions = '.txt', '.log', '.ini', '.conf', '.xml', '.html', '.htm', '.csv', '.json', '.env'
    }

    if ($SearchPath) {
        $searchRoots = @($SearchPath)
    } 
    else {
        $searchRoots = (Get-PSDrive -PSProvider 'FileSystem') | ForEach-Object { "$($_.Name):\" }
    }

    foreach ($root in $searchRoots) {
        try {
            Get-ChildItem -Path $root -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { 
                $Extensions -contains $_.Extension.ToLower()
            } |
            ForEach-Object {
                $matchesFound = @()
                $lineCount = 0
                $limitReached = $false

                try {
                    $lines = Get-Content -Path $_.FullName -ErrorAction Stop
                    
                    foreach ($line in $lines) {
                        if ($line.Length -gt $maxLineLength) { continue }

                        foreach ($pattern in $patterns) {
                            if ($line -match $pattern) {
                                $matchesFound += $line.Trim()
                                $lineCount++
                                break
                            }
                        }

                        if ($lineCount -ge $maxLines) {
                            $limitReached = $true
                            break
                        }
                    }
                } catch {
                    Write-Verbose "Cannot read file: $($_.FullName)"
                }

                if ($matchesFound.Count -gt 0) {
                    if ($OutputFile) {
                        $outputLines += "`n[!] Potential matches in file: $($_.FullName)"
                        
                        foreach ($m in $matchesFound | Select-Object -Unique) {
                            $outputLines += "> $m"
                        }
                        if ($limitReached) {
                            $outputLines += "[!] File has reached the $maxLines-line limit. Output canceled."
                        }
                    } 
                    else {
                        Write-Host "`n[!] Potential matches in file: $($_.FullName)" -ForegroundColor Red
                        foreach ($m in $matchesFound | Select-Object -Unique) {
                            Write-Host "> $m" -ForegroundColor DarkYellow
                        }
                        if ($limitReached) {
                            Write-Host "[!] File has reached the $maxLines-line limit. Output canceled." -ForegroundColor Magenta
                        }
                    }
                }
            }
        } catch {
            Write-Warning "Could not search in path $root`: $_"
        }
    }

    if ($OutputFile -and $outputLines.Count -gt 0) {
        $outputLines | Out-File -FilePath $OutputFile -Encoding UTF8
        Write-Host "[+] Results written to: $OutputFile" -ForegroundColor Green
    } 
    elseif ($OutputFile) {
        Write-Host "[+] No matches found. Nothing written to file." -ForegroundColor Yellow
    }
}

Write-Host ""
$hostUI = $host.UI.RawUI
$ForegroundColor = $hostUI.ForegroundColor
$hostUI.ForegroundColor = "Cyan"
Write-Host "[+] Searching for passwords and usernames...:`n"
$hostUI.ForegroundColor = $ForegroundColor

if ($Extensions) {
    $hostUI.ForegroundColor = "Yellow"
    Write-Host "-> " -NoNewline
    $hostUI.ForegroundColor = "Cyan"
    Write-Host "Selected Extensions: $($Extensions -join ', ')`n"
    $hostUI.ForegroundColor = $ForegroundColor
}

if ($Help) {
    Write-Host @"

USAGE: .\LookForCredencials.ps1 [OPTIONS]

  -Help                  Show this help message
  -Extensions            Comma-separated list of file extensions to scan (e.g. ".txt,.xml")
  -MaxLines <int>        Max number of matching lines captured per file (default: 40)
  -OutputFile <path>     Write all results to a file instead of printing to console
  -SearchPath <path>     Scan a specific folder or path instead of all drives

EXAMPLES:
  .\LookForCredencials.ps1
  .\LookForCredencials.ps1 -Extensions ".txt,.json" -MaxLines 100
  .\LookForCredencials.ps1 -OutputFile "results.txt"
  .\LookForCredencials.ps1 -SearchPath "C:\Users" -OutputFile "C:\out.txt"

"@ -ForegroundColor Cyan
    exit
}

Search-FilesForCredentials -Extensions $Extensions -MaxLines $MaxLines -OutputFile $OutputFile -SearchPath $SearchPath