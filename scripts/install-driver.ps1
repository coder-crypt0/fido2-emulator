param([switch]$DownloadOnly)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskDownloadDirectory = Join-Path $taskRoot '.downloads'
New-Item -ItemType Directory -Force -Path $taskDownloadDirectory | Out-Null
$taskArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
switch ($taskArchitecture) {
    'X64' {
        $taskAsset = 'USBip-0.9.8.1-x64.exe'
        $taskDigest = '38cad6d4432b52d5bb9409d9ad03b72fdffc4ada4cd3a48fbeca1a2752a8518a'
    }
    'Arm64' {
        $taskAsset = 'USBip-0.9.8.1-arm64.exe'
        $taskDigest = 'cab7ff97f79275eeb5c5b8bb2eb3111ff6b6c4eead07d9bec9be5bd1e3a35800'
    }
    default { throw "Unsupported architecture: $taskArchitecture" }
}
$taskInstaller = Join-Path $taskDownloadDirectory $taskAsset
if (-not (Test-Path -LiteralPath $taskInstaller)) {
    Invoke-WebRequest -Uri "https://github.com/vadimgrn/usbip-win2/releases/download/v.0.9.8.1/$taskAsset" -OutFile $taskInstaller
}
if ((Get-FileHash -LiteralPath $taskInstaller -Algorithm SHA256).Hash.ToLowerInvariant() -ne $taskDigest) {
    throw 'USB/IP installer SHA256 mismatch. Refusing installation.'
}
$taskSignature = Get-AuthenticodeSignature -LiteralPath $taskInstaller
if ($taskSignature.Status -ne 'Valid') { throw "Installer signature is not valid: $($taskSignature.Status)" }
Write-Host 'Verified upstream release SHA256 and Authenticode signature.'
if ($DownloadOnly) { exit 0 }
$taskIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$taskIdentity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script in an Administrator PowerShell to install the virtual USB driver.'
}
Write-Host 'Installing signed USB/IP virtual USB controller. USB hubs may briefly restart.'
$taskLog = Join-Path $taskDownloadDirectory 'driver-install.log'
$taskProcess = Start-Process -FilePath $taskInstaller -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/COMPONENTS=main,client', "/LOG=`"$taskLog`"") -PassThru -Wait -WindowStyle Hidden
if ($taskProcess.ExitCode -notin @(0, 3010)) { throw "Installer failed ($($taskProcess.ExitCode)); inspect $taskLog" }
if (Select-String -LiteralPath $taskLog -SimpleMatch 'Need to restart Windows? Yes' -Quiet) {
    Write-Warning 'Windows requested a reboot to finish USB filter setup. Restart when convenient; this script will not reboot.'
}
$taskUsbip = Join-Path $env:ProgramFiles 'USBip\usbip.exe'
& $taskUsbip port
if ($LASTEXITCODE -ne 0) { throw 'Controller unavailable. Inspect installation log; a reboot may be required.' }
Write-Host 'Virtual USB driver installed. No boot security settings were changed.'
