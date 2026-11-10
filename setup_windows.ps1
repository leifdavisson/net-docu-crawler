<#
Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later

.SYNOPSIS
  Assess and fix a Windows machine so Net-Docu-Crawler can run.

.DESCRIPTION
  Checks (and with -Fix, repairs) the problems seen on first Windows runs:
    1. Python / Git missing, or installed but not on PATH
    2. Python version too new/old for prebuilt wheels (supported: 3.10-3.12)
    3. Missing Microsoft Visual C++ Redistributable (x64 vs x86 mismatch)
    4. Virtual environment + dependency install (wheels only, no compiler needed)
    5. Windows Defender slowdown (reports only; exclusion needs -DefenderExclusion)

  Default is ASSESS ONLY (changes nothing). Use -Fix to install/repair.
  Installs use winget: https://learn.microsoft.com/windows/package-manager/winget/
  Read-only with respect to the network: this script never touches any target device.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1          # assess only
  powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1 -Fix     # assess + fix
#>
[CmdletBinding()]
param(
    [switch]$Fix,
    [switch]$DefenderExclusion   # optional, needs admin: exclude project folder from real-time scan
)

$ErrorActionPreference = 'Continue'
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:Problems = 0
$script:Fixed = 0
$script:NeedNewShell = $false

function Ok($m)   { Write-Host "[ OK ]  $m" -ForegroundColor Green }
function Bad($m)  { Write-Host "[FAIL]  $m" -ForegroundColor Red; $script:Problems++ }
function Info($m) { Write-Host "[INFO]  $m" -ForegroundColor Cyan }
function Fixd($m) { Write-Host "[FIXD]  $m" -ForegroundColor Yellow; $script:Fixed++ }

function Refresh-Path {
    $m = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $u = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = "$m;$u"
}

function Add-ToUserPath($dir) {
    if (-not (Test-Path $dir)) { return $false }
    $u = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (($u -split ';') -notcontains $dir) {
        [Environment]::SetEnvironmentVariable('Path', ($u.TrimEnd(';') + ";$dir"), 'User')
        $env:Path += ";$dir"
        $script:NeedNewShell = $true
        return $true
    }
    return $false
}

# Direct-download fallbacks, used when winget is unavailable and cannot be bootstrapped.
$Fallbacks = @{
    'Python.Python.3.12' = @{ Url = 'https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe';
        Args = '/quiet InstallAllUsers=1 PrependPath=1 Include_launcher=1 Include_test=0' }
    'Git.Git' = @{ Url = 'https://github.com/git-for-windows/git/releases/download/v2.47.1.windows.1/Git-2.47.1-64-bit.exe';
        Args = '/VERYSILENT /NORESTART' }
    'Microsoft.VCRedist.2015+.x64' = @{ Url = 'https://aka.ms/vs/17/release/vc_redist.x64.exe';
        Args = '/install /quiet /norestart' }
    'Microsoft.VCRedist.2015+.x86' = @{ Url = 'https://aka.ms/vs/17/release/vc_redist.x86.exe';
        Args = '/install /quiet /norestart' }
}

function Ensure-Winget {
    if (Get-Command winget -ErrorAction SilentlyContinue) { return $true }
    Info "winget missing; trying to register/install App Installer..."
    try { Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -ErrorAction Stop } catch {}
    Refresh-Path
    if (Get-Command winget -ErrorAction SilentlyContinue) { return $true }
    try {
        $tmp = Join-Path $env:TEMP 'winget-bootstrap'; New-Item -ItemType Directory -Force $tmp | Out-Null
        Invoke-WebRequest 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx' -OutFile "$tmp\vclibs.appx" -UseBasicParsing
        Invoke-WebRequest 'https://aka.ms/getwinget' -OutFile "$tmp\winget.msixbundle" -UseBasicParsing
        Add-AppxPackage "$tmp\vclibs.appx" -ErrorAction SilentlyContinue
        Add-AppxPackage "$tmp\winget.msixbundle" -ErrorAction Stop
    } catch { Info "winget bootstrap failed: $($_.Exception.Message)" }
    $env:Path += ";$env:LOCALAPPDATA\Microsoft\WindowsApps"
    return [bool](Get-Command winget -ErrorAction SilentlyContinue)
}

function Winget-Install($id) {
    if (Ensure-Winget) {
        winget install --id $id -e --silent --accept-package-agreements --accept-source-agreements
        Refresh-Path
        if ($LASTEXITCODE -eq 0) { return $true }
        Info "winget install of $id failed (exit $LASTEXITCODE); trying direct download."
    }
    $fb = $Fallbacks[$id]
    if (-not $fb) { Bad "No installer available for $id."; return $false }
    $exe = Join-Path $env:TEMP (Split-Path $fb.Url -Leaf)
    try {
        Info "Downloading $($fb.Url)"
        Invoke-WebRequest $fb.Url -OutFile $exe -UseBasicParsing
        $p = Start-Process $exe -ArgumentList $fb.Args -Wait -PassThru
        Refresh-Path
        return ($p.ExitCode -in 0, 3010)   # 3010 = success, reboot required
    } catch { Bad "Direct download failed: $($_.Exception.Message)"; return $false }
}

# --- Basic environment prerequisites ---------------------------------------
function Test-Prereqs {
    # Modern TLS: older Windows PowerShell defaults to TLS 1.0 and fails against python.org/github.com.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    if ($PSVersionTable.PSVersion.Major -lt 5) { Bad "PowerShell 5.1+ required (found $($PSVersionTable.PSVersion))." }
    if (-not [Environment]::Is64BitOperatingSystem) { Bad "32-bit Windows detected; current Python 3.12 installers target 64-bit." }
    # Internet / proxy reachability for the installers and pip.
    foreach ($h in 'pypi.org', 'files.pythonhosted.org', 'github.com') {
        if (-not (Test-NetConnection $h -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue)) {
            Bad "Cannot reach $h:443 (firewall/proxy?). Set HTTPS_PROXY or ask IT to allow it."
        } else { Ok "Reachable: $h" }
    }
    # Windows long paths: deep site-packages trees can exceed 260 chars.
    $lp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -ErrorAction SilentlyContinue).LongPathsEnabled
    if ($lp -ne 1) {
        Info "Windows long paths are disabled (can break pip on deep paths)."
        if ($Fix) {
            try { Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' LongPathsEnabled 1 -ErrorAction Stop; Fixd "Enabled long paths." }
            catch { Info "Run as Administrator to enable long paths." }
        }
    } else { Ok "Long paths enabled" }
    # Admin rights are needed for machine-wide installs.
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')
    if ($Fix -and -not $admin) { Info "Not running as Administrator: installs may prompt for UAC or fail. Prefer an elevated PowerShell." }
}

Write-Host "`n=== Net-Docu-Crawler Windows setup ($(if ($Fix) {'FIX'} else {'ASSESS ONLY'})) ===`n"

Test-Prereqs

# --- OS / architecture ---------------------------------------------------
$os = Get-CimInstance Win32_OperatingSystem
Info "OS: $($os.Caption) build $($os.BuildNumber), arch: $($env:PROCESSOR_ARCHITECTURE)"
if ([int]$os.BuildNumber -lt 17763) { Bad "Windows older than 10 1809 is unsupported by current Python." }

# --- Git -------------------------------------------------------------------
Refresh-Path
$git = Get-Command git -ErrorAction SilentlyContinue
if (-not $git) {
    $gitDir = @("$env:ProgramFiles\Git\cmd", "${env:ProgramFiles(x86)}\Git\cmd", "$env:LOCALAPPDATA\Programs\Git\cmd") |
        Where-Object { Test-Path "$_\git.exe" } | Select-Object -First 1
    if ($gitDir) {
        Bad "Git is installed at $gitDir but is not on PATH."
        if ($Fix -and (Add-ToUserPath $gitDir)) { Fixd "Added $gitDir to user PATH." }
    } else {
        Bad "Git is not installed."
        if ($Fix -and (Winget-Install 'Git.Git')) { Fixd "Installed Git." ; $script:NeedNewShell = $true }
    }
} else { Ok "Git: $(& git --version)" }

# --- Python ----------------------------------------------------------------
# Prefer the 'py' launcher (works even when PATH is broken), then python.exe.
function Find-Python {
    foreach ($v in '3.12', '3.11', '3.10') {
        if (Get-Command py -ErrorAction SilentlyContinue) {
            $p = & py "-$v" -c "import sys;print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $p) { return $p.Trim() }
        }
    }
    $c = Get-Command python -ErrorAction SilentlyContinue
    # Ignore the Microsoft Store "python" alias stub (WindowsApps), it is not a real install.
    if ($c -and $c.Source -notlike '*\WindowsApps\*') {
        $ver = & $c.Source -c "import sys;print('%d.%d'%sys.version_info[:2])" 2>$null
        if ($ver -in '3.10', '3.11', '3.12') { return $c.Source }
        Info "Found Python $ver at $($c.Source) (outside supported 3.10-3.12)."
    }
    $roots = "$env:LOCALAPPDATA\Programs\Python", "$env:ProgramFiles\Python*", "${env:ProgramFiles(x86)}\Python*"
    foreach ($r in $roots) {
        Get-ChildItem $r -Directory -ErrorAction SilentlyContinue | Where-Object Name -match 'Python3(10|11|12)' |
            ForEach-Object { if (Test-Path "$($_.FullName)\python.exe") { return "$($_.FullName)\python.exe" } }
    }
    return $null
}

$py = Find-Python
if (-not $py) {
    Bad "No usable Python 3.10-3.12 found (3.13+ may lack prebuilt wheels and force C++ compilation)."
    if ($Fix -and (Winget-Install 'Python.Python.3.12')) {
        $py = Find-Python
        if ($py) { Fixd "Installed Python 3.12 at $py" ; $script:NeedNewShell = $true }
    }
}
if ($py) {
    Ok "Python: $py ($(& $py --version))"
    $pyDir = Split-Path $py
    $onPath = (Get-Command python -ErrorAction SilentlyContinue) -and ((Get-Command python).Source -notlike '*\WindowsApps\*')
    if (-not $onPath) {
        Bad "python.exe is not on PATH (use 'py' or the venv below, or fix PATH)."
        if ($Fix) {
            $a = Add-ToUserPath $pyDir; $b = Add-ToUserPath "$pyDir\Scripts"
            if ($a -or $b) { Fixd "Added $pyDir and Scripts to user PATH (open a NEW terminal)." }
        }
    }
    $pipOk = & $py -m pip --version 2>$null
    if ($LASTEXITCODE -ne 0) {
        Bad "pip is not available."
        if ($Fix) { & $py -m ensurepip --upgrade | Out-Null; if ($LASTEXITCODE -eq 0) { Fixd "Bootstrapped pip." } }
    } else { Ok "pip: $pipOk" }

    $bits = & $py -c "import struct;print(struct.calcsize('P')*8)"
    Info "Python is $bits-bit"
}

# --- Visual C++ Redistributable -------------------------------------------
# Python 64-bit needs the x64 runtime. Installing x86 alone does NOT help.
$arch = if ($py -and $bits -eq '32') { 'x86' } else { 'x64' }
$vcKey = "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\$arch"
$vc = Get-ItemProperty $vcKey -ErrorAction SilentlyContinue
if ($vc -and $vc.Installed -eq 1) {
    Ok "VC++ Redistributable ($arch) $($vc.Version)"
} else {
    Bad "VC++ 2015-2022 Redistributable ($arch) is missing. Python needs the $arch build."
    if ($Fix) {
        $id = if ($arch -eq 'x64') { 'Microsoft.VCRedist.2015+.x64' } else { 'Microsoft.VCRedist.2015+.x86' }
        if (Winget-Install $id) { Fixd "Installed VC++ Redistributable ($arch). A REBOOT may be required." }
    }
}
if (Get-ChildItem "$env:SystemRoot\System32\vcruntime140.dll" -ErrorAction SilentlyContinue) {
    Ok "vcruntime140.dll present in System32"
} else { Bad "vcruntime140.dll not found in System32 (reboot after installing the redistributable)." }
if ((Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue) -and
    (Get-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -ErrorAction SilentlyContinue).GetValue('PendingFileRenameOperations')) {
    Info "A reboot is pending; finish it before retrying if imports still fail."
}

# --- venv + dependencies ---------------------------------------------------
if ($py) {
    $venv = Join-Path $ProjectDir '.venv'
    $vpy = Join-Path $venv 'Scripts\python.exe'
    if (-not (Test-Path $vpy)) {
        Bad "Virtual environment not created ($venv)."
        if ($Fix) { & $py -m venv $venv; if (Test-Path $vpy) { Fixd "Created venv." } }
    } else { Ok "venv: $venv" }
    if (Test-Path $vpy) {
        & $vpy -c "import netmiko, paramiko, netaddr, cryptography" 2>$null
        if ($LASTEXITCODE -eq 0) { Ok "Dependencies import cleanly (netmiko, paramiko, netaddr, cryptography)." }
        else {
            Bad "Dependencies missing or failing to import."
            if ($Fix) {
                Info "Installing (wheels only, so no C++ compiler is ever needed)..."
                & $vpy -m pip install --upgrade pip 2>&1 | Out-Null
                & $vpy -m pip install --only-binary=:all: -r (Join-Path $ProjectDir 'requirements.txt')
                if ($LASTEXITCODE -ne 0) {
                    Info "Retrying project install without --only-binary for pure-Python packages..."
                    & $vpy -m pip install -r (Join-Path $ProjectDir 'requirements.txt')
                }
                & $vpy -c "import netmiko, paramiko, netaddr, cryptography" 2>$null
                if ($LASTEXITCODE -eq 0) { Fixd "Dependencies installed and importing." }
                else {
                    Write-Host "`nImport error detail:" -ForegroundColor Red
                    & $vpy -c "import cryptography" 2>&1 | Select-Object -Last 5
                    Write-Host "If this mentions DLL load failed / VCRUNTIME: install the $arch VC++ Redistributable and REBOOT." -ForegroundColor Red
                }
            }
        }
        & $vpy -m pip install --no-deps -e $ProjectDir 2>&1 | Out-Null
    }
}

# --- Defender (slowness) ---------------------------------------------------
try {
    $mp = Get-MpPreference -ErrorAction Stop
    if ($mp.DisableRealtimeMonitoring) { Ok "Defender real-time scan is off." }
    elseif ($mp.ExclusionPath -contains $ProjectDir) { Ok "Project folder excluded from Defender scans." }
    else {
        Info "Defender real-time scanning inspects every .py file, which slows Python start-up and large subnet crawls."
        if ($DefenderExclusion) {
            try { Add-MpPreference -ExclusionPath $ProjectDir -ErrorAction Stop; Fixd "Excluded $ProjectDir from Defender." }
            catch { Bad "Could not add Defender exclusion (run as Administrator)." }
        } else { Info "Re-run elevated with -DefenderExclusion to exclude the project folder (optional)." }
    }
} catch { Info "Defender status unavailable (third-party AV or no permission)." }

# --- Summary ---------------------------------------------------------------
Write-Host "`n=== Summary: $script:Problems problem(s) found, $script:Fixed fixed ===" -ForegroundColor White
if (-not $Fix -and $script:Problems -gt 0) { Write-Host "Re-run with -Fix to repair." -ForegroundColor Yellow }
if ($script:NeedNewShell) { Write-Host "PATH changed: CLOSE and reopen this terminal before continuing." -ForegroundColor Yellow }
Write-Host "`nRun the crawler with:"
Write-Host "  .\.venv\Scripts\python.exe net_crawler.py --targets 192.168.1.0/24"
Write-Host "Tip: crawl specific hosts first; a full subnet scan is slow on a cold machine.`n"
