param(
    [string]$Path,
    [switch]$Help
)

$signature = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public class ResourceExtractor {

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr FindResource(IntPtr hModule, IntPtr lpName, IntPtr lpType);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadResource(IntPtr hModule, IntPtr hResInfo);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LockResource(IntPtr hResData);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint SizeofResource(IntPtr hModule, IntPtr hResInfo);

    public const uint LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020;
    public const uint LOAD_LIBRARY_AS_DATAFILE = 0x00000002;
    public const int RT_MANIFEST = 24;

    public static string ExtractManifest(string filePath) {
        IntPtr hModule = LoadLibraryEx(filePath, IntPtr.Zero, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);

        if (hModule == IntPtr.Zero)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

        try {
            foreach (int id in new int[] { 1, 2, 3 }) {
                IntPtr hResInfo = FindResource(hModule, new IntPtr(id), new IntPtr(RT_MANIFEST));
                
                if (hResInfo == IntPtr.Zero) continue;

                uint   size  = SizeofResource(hModule, hResInfo);
                IntPtr hRes  = LoadResource(hModule, hResInfo);
                IntPtr pData = LockResource(hRes);

                if (pData == IntPtr.Zero || size == 0) continue;

                byte[] bytes = new byte[size];
                Marshal.Copy(pData, bytes, 0, (int)size);

                int offset = 0;
                
                if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
                    offset = 3;

                return Encoding.UTF8.GetString(bytes, offset, bytes.Length - offset);
            }
            return null;
        }
        finally {
            FreeLibrary(hModule);
        }
    }
}
'@

if ($Help) {
    Write-Host "`nUsage:" -ForegroundColor Cyan
    Write-Host ".\Get-Manifest.ps1 -Path <file>"
    Write-Host ".\Get-Manifest.ps1`n"
    exit
}

if (-not ([System.Management.Automation.PSTypeName]'ResourceExtractor').Type) {
    Add-Type -TypeDefinition $signature -Language CSharp
}

if (-not $Path) {
    $Path = Read-Host "`nFile path"
}

$Path = [System.Environment]::ExpandEnvironmentVariables($Path)
$Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

if (-not (Test-Path $Path -PathType Leaf)) {
    Write-Host "`n[ERROR] File not found: $Path`n" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "[MANIFEST]  $Path" -ForegroundColor Yellow
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host ""

try {
    $rawXml = [ResourceExtractor]::ExtractManifest($Path)

    if (-not $rawXml) {
        Write-Host "No embedded manifest found." -ForegroundColor DarkYellow
        exit 0
    }

    $xmlDoc = New-Object System.Xml.XmlDocument
    $xmlDoc.LoadXml($rawXml.Trim())

    $sw = New-Object System.IO.StringWriter
    $settings = New-Object System.Xml.XmlWriterSettings
    $settings.Indent = $true
    $settings.IndentChars = "    "
    $settings.OmitXmlDeclaration = $false
    $settings.Encoding = [System.Text.Encoding]::UTF8

    $writer = [System.Xml.XmlWriter]::Create($sw, $settings)
    $xmlDoc.Save($writer)
    $writer.Flush()

    foreach ($line in $sw.ToString() -split "`n") {
        
        if ($line -match '^\s*<\?xml') {
            Write-Host $line -ForegroundColor DarkGray
        } 
        
        elseif ($line -match '<!--') {
            Write-Host $line -ForegroundColor DarkGreen
        } 
        
        elseif ($line -match '^\s*</') {
            Write-Host $line -ForegroundColor Cyan
        } 
        
        elseif ($line -match '^\s*<[^/]') {
            $line -split '(?=\s\w+=)' | ForEach-Object {
                
                if ($_ -match '=') {
                    $parts = $_ -split '=', 2
                    Write-Host -NoNewline $parts[0] -ForegroundColor DarkYellow
                    Write-Host -NoNewline "=" -ForegroundColor White
                    Write-Host -NoNewline $parts[1] -ForegroundColor Green
                } 
                else {
                    Write-Host -NoNewline $_ -ForegroundColor Cyan
                }
            }
            Write-Host ""
        } 
        else {
            Write-Host $line -ForegroundColor White
        }
    }

} catch {
    Write-Host "[ERROR] $_" -ForegroundColor Red
    exit 1
}