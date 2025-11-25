Write-Host "=== Potential DLL Hijacking (Process Loaded Modules) ===`n"

# ---------------------------------------------------------
# Function: Check if current user has Write/Modify on a file
# ---------------------------------------------------------
function Test-ModifiableFile($path) {
    try {
        if (-not (Test-Path $path)) { return $false }

        $acl = Get-Acl $path
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $sidUser = $user.User
        $sidGroups = $user.Groups

        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne "Allow") { continue }

            if ($ace.IdentityReference -eq $sidUser -or $sidGroups -contains $ace.IdentityReference) {
                if ($ace.FileSystemRights.ToString() -match "Write|Modify|FullControl") {
                    return $true
                }
            }
        }
    } catch { return $false }

    return $false
}

# ---------------------------------------------------------
# Load KnownDLL list from registry
# ---------------------------------------------------------
$knownDllsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDlls"

$knownDlls = @()
try {
    $names = Get-ItemProperty -Path $knownDllsPath | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
    foreach ($n in $names) {
        $knownDlls += $n.ToLower()
    }
} catch {
    Write-Host "[X] Unable to read KnownDLLs registry key." -ForegroundColor Red
}

# ---------------------------------------------------------
# Enumerate all processes
# ---------------------------------------------------------
$processes = Get-Process -ErrorAction SilentlyContinue

foreach ($proc in $processes) {

    try {
        $modules = $proc.Modules
    }
    catch {
        # No access to this process
        continue
    }

    foreach ($m in $modules) {

        $dllName = $m.ModuleName.ToLower()
        $dllPath = $m.FileName.ToLower()

        # Exclude items that:
        # - are not DLLs
        # - are in KnownDLLs
        # - are under c:\windows
        if (-not $dllPath.EndsWith(".dll")) { continue }
        if ($knownDlls -contains $dllName) { continue }
        if ($dllPath.StartsWith("c:\windows")) { continue }

        # Check if modifiable by user
        $modifiable = Test-ModifiableFile $dllPath
        if (-not $modifiable) { continue }

        # Output
        if ($dllPath.Contains("c:\program files")) {
            Write-Host "[+] Potentially Hijackable DLL (may be false positive):" -ForegroundColor Yellow
        } else {
            Write-Host "[+] Hijackable DLL:" -ForegroundColor Green
        }

        Write-Host "    DLL Path   : $($m.FileName)"
        Write-Host "    Process     : $($proc.ProcessName)  (PID $($proc.Id))"
        Write-Host ""
    }
}

Write-Host "Scan complete."
