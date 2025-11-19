Get-CimInstance Win32_Service |
Where-Object {
    $_.PathName -notlike '"*"' -and $_.PathName -match " "
} | ForEach-Object {

    # Nettoyage du chemin : on retire arguments et guillemets
    $raw = $_.PathName
    $exe = ($raw -replace '"','' -replace '(^\s+|\s+$)','')  `
            -split '\.exe' | Select-Object -First 1
    $exe = $exe + ".exe"

    # Si le fichier existe, on récupère le dossier parent
    $folder = if (Test-Path $exe) {
        Split-Path $exe -Parent
    } else {
        "Inconnu ou inexistant"
    }

    [PSCustomObject]@{
        Service     = $_.Name
        DisplayName = $_.DisplayName
        PathName    = $_.PathName
        Executable  = $exe
        Folder      = $folder
    }
}
