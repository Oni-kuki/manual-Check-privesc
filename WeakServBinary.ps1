Get-CimInstance Win32_Service | ForEach-Object {
    $path = $_.PathName -replace '"','' -replace ' .*$',''
    if (Test-Path $path) {
        $acl = Get-Acl $path
        $weak = $acl.Access | Where-Object { $_.FileSystemRights -match "Write|Modify|FullControl" }
        if ($weak) {
            [PSCustomObject]@{
                Service = $_.Name
                BinaryPath = $path
                WeakPermissions = $weak.IdentityReference
            }
        }
    }
}
