$user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$userSIDs = $user.Groups | ForEach-Object { $_.Value }
$userSIDs += $user.User.Value

Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -Recurse -ErrorAction SilentlyContinue |
ForEach-Object {
    try {
        $acl = Get-Acl $_.PSPath
    } catch {
        return
    }

    $weak = $acl.Access | Where-Object {
        ($_.RegistryRights -match "Write|FullControl|SetValue|CreateSubKey") -and
        ($userSIDs -contains $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value)
    }

    if ($weak) {
        [PSCustomObject]@{
            ServiceRegistryPath = $_.PSPath
            Identity            = $weak.IdentityReference
            Rights              = $weak.RegistryRights
        }
    }
}
