Get-Service | ForEach-Object {
    $name = $_.Name
    $sd = sc.exe sdshow $name 2>$null
    if ($sd -and ($sd -match "WD" -or $sd -match "AU")) {
        [PSCustomObject]@{
            Service = $name
            SD = $sd
        }
    }
}
