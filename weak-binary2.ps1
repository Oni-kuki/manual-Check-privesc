# Récupère tous les groupes / SID de l'utilisateur courant
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$userSIDs = $user.Groups | ForEach-Object { $_.Value }
$userSIDs += $user.User.Value   # Ajoute le SID direct de l'utilisateur

Get-CimInstance Win32_Service | ForEach-Object {

    # Nettoyage du chemin
    $raw = $_.PathName
    $exe = ($raw -replace '"','').Trim()
    $exe = ($exe -split '\.exe')[0] + ".exe"

    if (Test-Path $exe) {

        $acl = Get-Acl $exe

        # Filtrer uniquement les ACE où l'utilisateur courant OU un groupe dont il fait partie a des droits d'écriture
        $weak = $acl.Access | Where-Object {
            ($_.FileSystemRights -match "Write|Modify|FullControl") -and
            ($userSIDs -contains $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value)
        }

        if ($weak) {
            [PSCustomObject]@{
                Service            = $_.Name
                Executable         = $exe
                UserCanWrite       = $true
                IdentityReference  = $weak.IdentityReference
                Rights             = $weak.FileSystemRights
            }
        }
    }
}
