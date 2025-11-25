Write-Host "=== Services with Modifiable Registry Keys ===`n"

function Test-RegKeyModifiable($regPath) {
    try {
        $key = Get-Acl -Path $regPath -ErrorAction Stop

        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $userSID = $user.User
        $groups = $user.Groups

        foreach ($ace in $key.Access) {

            # ACE applicable ?
            if ($ace.IdentityReference -eq $userSID -or $groups -contains $ace.IdentityReference) {

                if ($ace.AccessControlType -ne "Allow") { continue }

                # Droits considérés comme "modifiables"
                if ($ace.RegistryRights.ToString() -match "Write|SetValue|FullControl|CreateSubKey") {
                    return $true
                }
            }
        }
    }
    catch {
        return $false
    }

    return $false
}

# Récupérer les services
$services = Get-CimInstance Win32_Service

foreach ($svc in $services) {

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"

    if (Test-RegKeyModifiable $regPath) {

        Write-Host "[!]" -ForegroundColor Yellow -NoNewline
        Write-Host " Service: $($svc.Name)"
        Write-Host "     State:     $($svc.State)"
        Write-Host "     StartMode: $($svc.StartMode)"
        Write-Host "     Registry:  SYSTEM\\CurrentControlSet\\Services\\$($svc.Name)"
        Write-Host ""
    }
}

Write-Host "Scan terminé."
