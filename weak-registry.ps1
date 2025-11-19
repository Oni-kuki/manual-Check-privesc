# Récupère SIDs utilisateur + groupes
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$userSIDs = $user.Groups | ForEach-Object { $_.Value }
$userSIDs += $user.User.Value

$hives = @(
    "HKLM:\SOFTWARE",
    "HKLM:\SYSTEM",
    "HKCU:\Software"
)

foreach ($hive in $hives) {

    Write-Host "`n--- Scanning $hive ---" -ForegroundColor Cyan

    Get-ChildItem $hive -Recurse -ErrorAction SilentlyContinue | ForEach-Object {

        try {
            $acl = Get-Acl $_.PSPath
        } catch {
            # On ignore simplement cette clé
            continue
        }

        $weakACEs = @()

        foreach ($ace in $acl.Access) {

            # On essaie de récupérer le SID comme string, sans planter
            try {
                $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            } catch {
                continue
            }

            # Vérifie si ACE applicable
            if ($userSIDs -contains $sid) {

                # Vérifie si droits dangereux
                if ($ace.RegistryRights -band (
                    [System.Security.AccessControl.RegistryRights]::FullControl +
                    [System.Security.AccessControl.RegistryRights]::WriteKey +
                    [System.Security.AccessControl.RegistryRights]::CreateSubKey +
                    [System.Security.AccessControl.RegistryRights]::SetValue
                )) {
                    $weakACEs += $ace
                }
            }
        }

        if ($weakACEs.Count -gt 0) {
            foreach ($ace in $weakACEs) {
                [PSCustomObject]@{
                    RegistryPath = $_.PSPath
                    Identity     = $ace.IdentityReference.ToString()
                    Rights       = $ace.RegistryRights.ToString()
                }
            }
        }
    }
}
