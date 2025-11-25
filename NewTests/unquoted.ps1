Write-Host "=== Unquoted Service Paths ===`n"

# Récupère tous les services depuis le registre
$servicesKey = "HKLM:\SYSTEM\CurrentControlSet\Services"
$services = Get-ChildItem $servicesKey -ErrorAction SilentlyContinue

foreach ($service in $services) {
    $imagePath = (Get-ItemProperty -Path $service.PSPath -Name ImagePath -ErrorAction SilentlyContinue).ImagePath

    if ([string]::IsNullOrWhiteSpace($imagePath)) {
        continue
    }

    $pathTrimmed = $imagePath.Trim()

    # Trouve l’index du .exe
    $exeIndex = $pathTrimmed.ToLower().IndexOf(".exe")
    if ($exeIndex -lt 0) {
        continue
    }

    # extrait le chemin jusqu'au .exe
    $exeSegment = $pathTrimmed.Substring(0, $exeIndex + 4)

    # Condition : pas de guillemets + espace avant .exe
    if (-not ($pathTrimmed.StartsWith('"')) -and $exeSegment.Contains(" ")) {

        # Récupération du Start Mode
        $start = (Get-ItemProperty -Path $service.PSPath -Name Start -ErrorAction SilentlyContinue).Start
        switch ($start) {
            2 { $startMode = "Automatic"; break }
            3 { $startMode = "Manual"; break }
            4 { $startMode = "Disabled"; break }
            default { $startMode = "Unknown"; break }
        }

        Write-Host "[!]" -ForegroundColor Yellow -NoNewline
        Write-Host " Service: $($service.PSChildName)"

        Write-Host "     Path : $pathTrimmed"
        Write-Host "     Start: $startMode"
        Write-Host ""
    }
}

Write-Host "Scan terminé."
