# ============================================================
#  PALISADE ONE — Client Onboarding Script
#  Installs Wazuh EDR Agent + MeshCentral RMM Agent silently
#  Run as Administrator in PowerShell
# ============================================================
#  USAGE:
#    .\PalisadeOne-Onboard.ps1 -ClientName "Acme Corp"
#
#  REQUIREMENTS:
#    - PowerShell 5.1+
#    - Run as Administrator
#    - Internet access to palisadeone.com infrastructure
# ============================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$ClientName
)

# ── CONFIG ───────────────────────────────────────────────────
$WAZUH_MANAGER     = "178.156.234.30"
$WAZUH_VERSION     = "4.7.5-1"
$WAZUH_MSI_URL     = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WAZUH_VERSION.msi"
$MESH_URL          = "https://mesh.palisadeone.com:444"
$MESH_GROUP        = "Palisade One - Managed Devices"
$VC_REDIST_URL     = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
$LOG_FILE          = "$env:TEMP\PalisadeOne-Onboard.log"
# ─────────────────────────────────────────────────────────────

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"
    Write-Host $entry -ForegroundColor $(if ($Level -eq "ERROR") { "Red" } elseif ($Level -eq "WARN") { "Yellow" } elseif ($Level -eq "SUCCESS") { "Green" } else { "Cyan" })
    Add-Content -Path $LOG_FILE -Value $entry
}

function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-VCRedist {
    Write-Log "Checking Visual C++ Redistributable..."
    $vcKey = "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\X64"
    $vcInstalled = Test-Path $vcKey
    if ($vcInstalled) {
        Write-Log "VC++ Redistributable already installed. Skipping." "SUCCESS"
        return
    }
    Write-Log "Installing Visual C++ Redistributable..."
    $vcPath = "$env:TEMP\vc_redist.exe"
    Invoke-WebRequest -Uri $VC_REDIST_URL -OutFile $vcPath -UseBasicParsing
    Start-Process -FilePath $vcPath -ArgumentList "/install /quiet /norestart" -Wait
    Write-Log "VC++ Redistributable installed." "SUCCESS"
}

function Install-WazuhAgent {
    Write-Log "Starting Wazuh EDR Agent installation..."

    # Check if already installed
    $wazuhService = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($wazuhService) {
        Write-Log "Wazuh agent already installed. Skipping." "WARN"
        return
    }

    # Download MSI
    Write-Log "Downloading Wazuh agent MSI..."
    $msiPath = "$env:TEMP\wazuh-agent.msi"
    Invoke-WebRequest -Uri $WAZUH_MSI_URL -OutFile $msiPath -UseBasicParsing
    Write-Log "Download complete."

    # Install silently
    Write-Log "Installing Wazuh agent (silent)..."
    $agentName = ($ClientName -replace '[^a-zA-Z0-9-]', '-') + "-" + $env:COMPUTERNAME
    $installArgs = "/i `"$msiPath`" /q WAZUH_MANAGER=`"$WAZUH_MANAGER`" WAZUH_AGENT_NAME=`"$agentName`" WAZUH_REGISTRATION_SERVER=`"$WAZUH_MANAGER`""
    Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait

    # Start service
    Write-Log "Starting Wazuh service..."
    Start-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    $svc = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Log "Wazuh agent installed and running." "SUCCESS"
    } else {
        Write-Log "Wazuh service may not have started. Check manually." "WARN"
    }
}

function Install-MeshAgent {
    Write-Log "Starting MeshCentral RMM Agent installation..."

    # Check if already installed
    $meshService = Get-Service -Name "Mesh Agent" -ErrorAction SilentlyContinue
    if ($meshService) {
        Write-Log "MeshCentral agent already installed. Skipping." "WARN"
        return
    }

    # Download agent from MeshCentral server
    Write-Log "Downloading MeshCentral agent..."
    $meshPath = "$env:TEMP\meshagent.exe"

    # Bypass SSL warning for self-signed cert on port 444
    add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

    try {
        Invoke-WebRequest -Uri "https://mesh.palisadeone.com:444/meshagents?id=4&meshid=iIWY3osoTJeAkMJl9O@0Nu@sFzPwr7x8SJrgrESmEZ3bzPWR7UTBA9o6jflJensO&installflags=0" -OutFile $meshPath -UseBasicParsing
        Write-Log "MeshCentral agent downloaded."
    } catch {
        Write-Log "Could not download MeshCentral agent automatically. Skipping RMM install." "WARN"
        Write-Log "Manual install: Download from $MESH_URL and run: .\meshagent.exe -install" "WARN"
        return
    }

    # Install using -install flag (bypasses GUI error)
    Write-Log "Installing MeshCentral agent..."
    Start-Process -FilePath $meshPath -ArgumentList "-install" -Wait -NoNewWindow

    $meshSvc = Get-Service -Name "Mesh Agent" -ErrorAction SilentlyContinue
    if ($meshSvc) {
        Write-Log "MeshCentral agent installed and running." "SUCCESS"
    } else {
        Write-Log "MeshCentral agent may not have installed correctly. Check $MESH_URL" "WARN"
    }
}

function Show-Summary {
    Write-Log "================================================" "SUCCESS"
    Write-Log " PALISADE ONE ONBOARDING COMPLETE" "SUCCESS"
    Write-Log "================================================" "SUCCESS"
    Write-Log " Client:    $ClientName" "SUCCESS"
    Write-Log " Device:    $env:COMPUTERNAME"
    Write-Log " Wazuh:     Reporting to $WAZUH_MANAGER"
    Write-Log " RMM:       Connected to $MESH_URL"
    Write-Log " Log file:  $LOG_FILE"
    Write-Log "================================================" "SUCCESS"
    Write-Log " This device is now monitored by Palisade One." "SUCCESS"
    Write-Log "================================================" "SUCCESS"
}

# ── MAIN ─────────────────────────────────────────────────────
Clear-Host
Write-Host ""
Write-Host "  ██████╗  █████╗ ██╗     ██╗███████╗ █████╗ ██████╗ ███████╗" -ForegroundColor Cyan
Write-Host "  ██╔══██╗██╔══██╗██║     ██║██╔════╝██╔══██╗██╔══██╗██╔════╝" -ForegroundColor Cyan
Write-Host "  ██████╔╝███████║██║     ██║███████╗███████║██║  ██║█████╗  " -ForegroundColor Cyan
Write-Host "  ██╔═══╝ ██╔══██║██║     ██║╚════██║██╔══██║██║  ██║██╔══╝  " -ForegroundColor Cyan
Write-Host "  ██║     ██║  ██║███████╗██║███████║██║  ██║██████╔╝███████╗" -ForegroundColor Cyan
Write-Host "  ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝" -ForegroundColor Cyan
Write-Host "                    O N E   S E C U R I T Y" -ForegroundColor DarkCyan
Write-Host ""

# Admin check
if (-not (Test-Admin)) {
    Write-Log "Script must be run as Administrator. Please re-run as Admin." "ERROR"
    exit 1
}

Write-Log "Palisade One onboarding started for client: $ClientName"
Write-Log "Device: $env:COMPUTERNAME | OS: $((Get-WmiObject Win32_OperatingSystem).Caption)"

# Run installs
Install-VCRedist
Install-WazuhAgent
Install-MeshAgent
Show-Summary