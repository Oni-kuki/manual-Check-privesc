# Récupère les SIDs de l'utilisateur courant + ses groupes
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$userSIDs = $user.Groups | ForEach-Object { $_.Value }
$userSIDs += $user.User.Value

# Liste des hives à auditer
$hives = @(
    "HKLM:\SOFTWARE",
    "HKLM:\SYSTEM",
    "HKCU:\Software"
)

foreach ($hive in $hives) {

    Write-Host "`n--- Scanning $hive ---" -ForegroundColor Cyan

    # Récupère récursivement toutes les clés accessibles (en silence si erro)
    Get-ChildItem $hive -Recurse -ErrorAction SilentlyContinue | ForEach-Object {

        try {
            $acl = Get-Acl $_.PSPath
        } catch {
            return
        }

        # Permissions faibles si l'utilisateur ou ses groupes ont Write/Modify/FullControl
        $weak = $acl.Access | Where-Object {
            ($_.RegistryRights -match "Write|FullControl|SetValue|CreateSubKey") -and
            ($userSIDs -contains $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value)
        }

        if ($weak) {
            [PSCustomObject]@{
                RegistryPath = $_.PSPath
                Identity     = $weak.IdentityReference
                Rights       = $weak.RegistryRights
            }
        }
    }
}
