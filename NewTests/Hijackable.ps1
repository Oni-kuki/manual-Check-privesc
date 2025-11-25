Write-Host "=== Modifiable Folders in %PATH% ===`n"

# Récupère la variable PATH système via le registre
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
$path = (Get-ItemProperty -Path $regPath -Name Path -ErrorAction SilentlyContinue).Path

if ([string]::IsNullOrWhiteSpace($path)) {
    Write-Host "Impossible de lire la valeur PATH dans le registre."
    exit
}

# Sépare les entrées du PATH
$folders = $path.Split(";")

function Test-Modifiable($folder) {
    try {
        if (-not (Test-Path $folder)) { return $false }

        $acl = Get-Acl $folder

        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $userSID = $user.User
        $groups = $user.Groups

        foreach ($ace in $acl.Access) {
            # Si l’ACE s’applique au user ou à un groupe auquel il appartient
            if ($ace.IdentityReference -eq $userSID -or $groups -contains $ace.IdentityReference) {
                
                # Permissions modifiables : Write, Modify, FullControl
                if ($ace.FileSystemRights -match "Write|Modify|FullControl") {
                    if ($ace.AccessControlType -eq "Allow") {
                        return $true
                    }
                }
            }
        }
    } catch {
        return $false
    }

    return $false
}

foreach ($folder in $folders) {
    $folderTrim = $folder.Trim()
    if ([string]::IsNullOrWhiteSpace($folderTrim)) { continue }

    if (Test-Modifiable $folderTrim) {
        Write-Host "[!]" -ForegroundColor Yellow -NoNewline
        Write-Host " $folderTrim"
    }
}

Write-Host "`nScan terminé."
