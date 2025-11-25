Write-Host "=== Modifiable Services ===`n"

# Droits considérés "dangereux" (équivalent ServiceAccessRights)
$modifyRights = @(
    "ChangeConfig",
    "WriteDac",
    "WriteOwner",
    "GenericWrite",
    "GenericAll",
    "AllAccess"
)

# Fonction : retourne true si l'utilisateur courant possède un droit dangereux sur le service
function Test-ServiceModifiable($svcName) {
    try {
        $sd = Get-Acl "Win32_Service::$svcName" -ErrorAction Stop

        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $sidUser = $user.User
        $sidGroups = $user.Groups

        foreach ($ace in $sd.Access) {

            # ACE applicable ?
            if ($ace.IdentityReference -eq $sidUser -or $sidGroups -contains $ace.IdentityReference) {

                if ($ace.AccessControlType -ne "Allow") { continue }

                foreach ($right in $modifyRights) {
                    if ($ace.FileSystemRights.ToString().Contains($right)) {
                        return $true
                    }
                }
            }
        }
    }
    catch {
        return $false
    }

    return $false
}

# Liste tous les services via CIM (équivalent Win32_Service)
$services = Get-CimInstance Win32_Service

foreach ($svc in $services) {
    if (Test-ServiceModifiable $svc.Name) {

        Write-Host "[!]" -ForegroundColor Yellow -NoNewline
        Write-Host " Service: $($svc.Name)"
        Write-Host "     State:     $($svc.State)"
        Write-Host "     StartMode: $($svc.StartMode)"
        Write-Host ""
    }
}

Write-Host "Scan terminé."
