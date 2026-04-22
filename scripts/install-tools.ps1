# install-tools.ps1 — install all scanner binaries required by supplychain-kit (Windows)
# Downloads pre-built binaries from GitHub Releases into $env:LOCALAPPDATA\supplychain-kit\bin
# and adds that directory to the current user's PATH if not already present.
#
# Usage: pwsh -ExecutionPolicy Bypass -File scripts\install-tools.ps1
#        (or run from a PowerShell window with the same flag)

$ErrorActionPreference = "Stop"

$SYFT_VERSION     = "1.4.1"
$GRYPE_VERSION    = "0.111.0"
$GITLEAKS_VERSION = "8.18.4"
$SEMGREP_VERSION  = "1.75.0"

$BinDir = "$env:LOCALAPPDATA\supplychain-kit\bin"

# ── helpers ──────────────────────────────────────────────────────────────────

function Info  { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Warn  { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Ok    { param($msg) Write-Host "[OK]    $msg" -ForegroundColor Green }
function Fail  { param($msg) Write-Host "[FAIL]  $msg" -ForegroundColor Red }

function Has-Command { param($name) $null -ne (Get-Command $name -ErrorAction SilentlyContinue) }

function Ensure-BinDir {
    if (-not (Test-Path $BinDir)) {
        New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
        Info "Created $BinDir"
    }
}

function Add-ToUserPath {
    $current = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($current -notlike "*$BinDir*") {
        [Environment]::SetEnvironmentVariable("PATH", "$current;$BinDir", "User")
        $env:PATH = "$env:PATH;$BinDir"
        Info "Added $BinDir to user PATH"
    }
}

function Download-Zip {
    param($url, $dest, $toolName)
    Info "Downloading $toolName from $url"
    $tmp = "$env:TEMP\$toolName-install"
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    $zipPath = "$tmp\archive.zip"
    Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
    Expand-Archive -Path $zipPath -DestinationPath $tmp -Force
    Remove-Item $zipPath
    return $tmp
}

# ── syft ─────────────────────────────────────────────────────────────────────

function Install-Syft {
    if (Has-Command syft) {
        $ver = (syft version 2>$null) | Select-Object -First 1
        Ok "syft already installed: $ver"
        return
    }
    Info "Installing syft v$SYFT_VERSION..."
    $url = "https://github.com/anchore/syft/releases/download/v$SYFT_VERSION/syft_${SYFT_VERSION}_windows_amd64.zip"
    $tmp = Download-Zip $url $BinDir "syft"
    Copy-Item "$tmp\syft.exe" "$BinDir\syft.exe" -Force
    Remove-Item $tmp -Recurse -Force
    Ok "syft installed -> $BinDir\syft.exe"
}

# ── grype ────────────────────────────────────────────────────────────────────

function Install-Grype {
    if (Has-Command grype) {
        $ver = (grype version 2>$null) | Select-Object -First 1
        Ok "grype already installed: $ver"
        return
    }
    Info "Installing grype v$GRYPE_VERSION..."
    $url = "https://github.com/anchore/grype/releases/download/v$GRYPE_VERSION/grype_${GRYPE_VERSION}_windows_amd64.zip"
    $tmp = Download-Zip $url $BinDir "grype"
    Copy-Item "$tmp\grype.exe" "$BinDir\grype.exe" -Force
    Remove-Item $tmp -Recurse -Force
    Ok "grype installed -> $BinDir\grype.exe"
}

# ── gitleaks ─────────────────────────────────────────────────────────────────

function Install-Gitleaks {
    if (Has-Command gitleaks) {
        $ver = (gitleaks version 2>$null)
        Ok "gitleaks already installed: $ver"
        return
    }
    Info "Installing gitleaks v$GITLEAKS_VERSION..."
    $url = "https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION/gitleaks_${GITLEAKS_VERSION}_windows_x64.zip"
    $tmp = Download-Zip $url $BinDir "gitleaks"
    Copy-Item "$tmp\gitleaks.exe" "$BinDir\gitleaks.exe" -Force
    Remove-Item $tmp -Recurse -Force
    Ok "gitleaks installed -> $BinDir\gitleaks.exe"
}

# ── semgrep ──────────────────────────────────────────────────────────────────

function Install-Semgrep {
    # Test if semgrep actually works (not just present as a broken wrapper)
    $works = $false
    try {
        $out = & semgrep --version 2>&1
        if ($LASTEXITCODE -eq 0) { $works = $true }
    } catch {}

    if ($works) {
        Ok "semgrep already installed: $(semgrep --version 2>$null)"
        return
    }

    Info "Installing semgrep $SEMGREP_VERSION via pip..."
    if (-not (Has-Command pip)) {
        Warn "pip not found. Install Python 3 and pip first, then re-run this script."
        return
    }
    # Force-reinstall to ensure osemgrep.exe is included
    pip install --force-reinstall --quiet "semgrep==$SEMGREP_VERSION"
    if ($LASTEXITCODE -eq 0) {
        Ok "semgrep installed via pip"
    } else {
        Warn "semgrep install failed. Try manually: pip install semgrep==$SEMGREP_VERSION"
    }
}

# ── verify ───────────────────────────────────────────────────────────────────

function Verify-All {
    $ok = $true
    Write-Host ""
    Info "=== Verification ==="
    foreach ($tool in @("syft", "grype", "gitleaks", "semgrep")) {
        if (Has-Command $tool) {
            Ok "$tool"
        } else {
            Fail "$tool — not found in PATH"
            $ok = $false
        }
    }
    if (Has-Command joern-parse) {
        Ok "joern-parse (optional)"
    } else {
        Info "joern-parse not installed (optional — needed for reachability analysis)"
    }
    return $ok
}

# ── main ─────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "supplychain-kit — Windows tool installer" -ForegroundColor White
Write-Host "Install directory: $BinDir" -ForegroundColor Gray
Write-Host ""

Ensure-BinDir
Add-ToUserPath

Install-Syft
Install-Grype
Install-Gitleaks
Install-Semgrep

$allOk = Verify-All
if ($allOk) {
    Write-Host ""
    Ok "All required tools installed successfully."
    Write-Host ""
    Write-Host "NOTE: If tools are not found in a new terminal, restart your shell or run:" -ForegroundColor Gray
    Write-Host "  `$env:PATH += `";$BinDir`"" -ForegroundColor Gray
} else {
    Write-Host ""
    Warn "Some tools are missing. See messages above."
    exit 1
}
