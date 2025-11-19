Get-CimInstance Win32_Service | ForEach-Object {

    # Nettoyage du chemin brut
    $raw = $_.PathName

    # Extraction fiable du .exe (détecte le premier .exe)
    $exe = ($raw -replace '"','').Trim()
    $exe = ($exe -split '\.exe')[0] + ".exe"

    if (Test-Path $exe) {
        $acl = Get-Acl $exe

        # Détection des permissions faibles
        $weak = $acl.Access | Where-Object {
            $_.FileSystemRights -match "Write|Modify|FullControl"
        }

        if ($weak) {
            [PSCustomObject]@{
                Service         = $_.Name
                BinaryPath      = $exe
                WeakPermissions = $weak.IdentityReference
            }
        }
    }
}
