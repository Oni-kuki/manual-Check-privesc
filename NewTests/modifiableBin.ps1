Write-Host "=== Modifiable Service Binaries ===`n"

function Test-Modifiable($path) {
    try {
        if (-not (Test-Path $path)) { return $false }

        $acl = Get-Acl $path

        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $userSID = $user.User
        $groups = $user.Groups

        foreach ($ace in $acl.Access) {
            # ACE applicable au user ou à un groupe du user
            if ($ace.IdentityReference -eq $userSID -or $groups -contains $ace.IdentityReference) {
                
                # Permissions suffisamment fortes
                if ($ace.AccessControlType -eq "Allow" -and
                    ($ace.FileSystemRights -match "Write|Modify|FullControl"))
                {
                    return $true
                }
            }
        }
    }
    catch { return $false }

    return $false
}

# Obtenir tous les services via WMI
$services = Get-CimInstance Win32_Service

# Regex pour extraire le binaire du PathName
$regex = '^\W*([a-z]:\\.+?(\.exe|\.dll|\.sys))\W*'

foreach ($svc in $services) {
    if ([string]::IsNullOrWhiteSpace($svc.PathName)) { continue }

    $match = [regex]::Match($svc.PathName, $regex, "IgnoreCase")
    if (-not $match.Success) { continue }

    $binary = $match.Groups[1].Value

    if (Test-Modifiable $binary) {
        Write-Host "[!]" -ForegroundColor Yellow -NoNewline
        Write-Host " Service: $($svc.Name)"
        Write-Host "     State:     $($svc.State)"
        Write-Host "     StartMode: $($svc.StartMode)"
        Write-Host "     Binary:    $binary"
        Write-Host ""
    }
}

Write-Host "Scan terminé."
