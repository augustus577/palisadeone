# Run on agent 005 as Administrator to update the poller with all new actions
# Copy this file to 005 and right-click -> Run with PowerShell as Admin

Write-Host "=== Updating PalisadeOne Poller to v5 (with WDAC) ===" -ForegroundColor Cyan

$pollerContent = @'
# PalisadeOne Agent Action Poller v4
$url = "https://api.palisadeone.com:9443"
$keysFile = "C:\Program Files (x86)\ossec-agent\client.keys"
$pollerLog = "C:\ProgramData\PalisadeOne\poller.log"
$agentId = $null
if (Test-Path $keysFile) {
    $line = (Get-Content $keysFile | Select-Object -First 1).Trim()
    $agentId = ($line -split '\s+')[0]
}
if (-not $agentId) { exit }
$logFile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

function Log($msg) { try { Add-Content $logFile "$(([DateTime]::UtcNow).ToString('yyyy/MM/dd HH:mm:ss')) active-response/bin/isolate-win.exe: $msg" } catch {} }
function PLog($msg) { try { Add-Content $pollerLog "$(Get-Date -F 'yyyy-MM-dd HH:mm:ss') $msg" } catch {} }

function RunNetsh($arguments) {
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "C:\Windows\System32\netsh.exe"
        $psi.Arguments = $arguments
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdout = $proc.StandardOutput.ReadToEnd()
        $proc.WaitForExit(15000)
        return $proc.ExitCode
    } catch { return -1 }
}

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $wc = New-Object Net.WebClient
    $resp = $wc.DownloadString("$url/agent-action/$agentId")
    $data = $resp | ConvertFrom-Json

    if ($data.action -eq "isolate") {
        PLog "[RECV] Isolate command for agent $agentId"
        Log "Starting (via polling)"
        RunNetsh "advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound"
        RunNetsh 'advfirewall firewall delete rule name="P1-Isolate-Allow-Wazuh-Out"'
        RunNetsh 'advfirewall firewall delete rule name="P1-Isolate-Allow-Wazuh-In"'
        RunNetsh 'advfirewall firewall add rule name="P1-Isolate-Allow-Wazuh-Out" dir=out action=allow remoteip=178.156.234.30 protocol=any'
        RunNetsh 'advfirewall firewall add rule name="P1-Isolate-Allow-Wazuh-In" dir=in action=allow remoteip=178.156.234.30 protocol=any'
        RunNetsh 'advfirewall firewall add rule name="P1-Isolate-Allow-Loopback-Out" dir=out action=allow remoteip=127.0.0.1 protocol=any'
        RunNetsh 'advfirewall firewall add rule name="P1-Isolate-Allow-Loopback-In" dir=in action=allow remoteip=127.0.0.1 protocol=any'
        RunNetsh 'advfirewall firewall add rule name="P1-Isolate-Allow-DNS" dir=out action=allow protocol=UDP remoteport=53'
        Log "Isolation applied - all traffic blocked except Wazuh manager"
        PLog "[ISOLATE] Complete"
    }
    elseif ($data.action -eq "unisolate") {
        PLog "[RECV] Unisolate command for agent $agentId"
        Log "Starting unisolation (via polling)"
        RunNetsh 'advfirewall firewall delete rule name="P1-Isolate-Allow-Wazuh-Out"'
        RunNetsh 'advfirewall firewall delete rule name="P1-Isolate-Allow-Wazuh-In"'
        RunNetsh 'advfirewall firewall delete rule name="P1-Isolate-Allow-Loopback-Out"'
        RunNetsh 'advfirewall firewall delete rule name="P1-Isolate-Allow-Loopback-In"'
        RunNetsh 'advfirewall firewall delete rule name="P1-Isolate-Allow-DNS"'
        RunNetsh "advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound"
        Log "Isolation removed - network access restored"
        PLog "[UNISOLATE] Complete"
    }
    elseif ($data.action -eq "restart") {
        PLog "[RESTART] Scheduling system restart in 60 seconds"
        Log "Restart command received from SOC dashboard"
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "C:\Windows\System32\shutdown.exe"
        $psi.Arguments = '/r /t 60 /c "PalisadeOne SOC-initiated restart"'
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        [System.Diagnostics.Process]::Start($psi) | Out-Null
        PLog "[RESTART] Restart scheduled"
    }
    elseif ($data.action -eq "kill") {
        $procName = $data.params.processName
        if ($procName) {
            PLog "[KILL] Killing process: $procName"
            Log "Kill command received for process: $procName"
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "C:\Windows\System32\taskkill.exe"
            $psi.Arguments = "/F /IM `"$procName`" /T"
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.CreateNoWindow = $true
            $proc = [System.Diagnostics.Process]::Start($psi)
            $out = $proc.StandardOutput.ReadToEnd()
            $proc.WaitForExit(10000)
            PLog "[KILL] Result: $($out.Trim())"
        }
    }
    elseif ($data.action -eq "fds") {
        $flagFile = "C:\ProgramData\PalisadeOne\fds-running.flag"
        if (Test-Path $flagFile) {
            PLog "[FDS] Scan already in progress"
        } else {
            PLog "[FDS] Starting Windows Defender Full Scan"
            Log "Full Disk Scan initiated from SOC dashboard"
            $fdsScript = @"
try {
    Set-Content '$flagFile' 'running'
    `$wc = New-Object Net.WebClient
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [Net.ServicePointManager]::ServerCertificateValidationCallback = {`$true}
    `$body = @{status='running';startedAt=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json
    `$wc.Headers.Add('Content-Type','application/json')
    `$wc.UploadString('$url/scan-status/$agentId', `$body) | Out-Null
    Start-MpScan -ScanType FullScan
    `$threats = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object -First 20 @{N='name';E={`$_.ThreatName}},@{N='severity';E={`$_.SeverityID}},@{N='process';E={`$_.ProcessName}},@{N='path';E={`$_.Resources -join ';'}})
    `$body2 = @{status='completed';completedAt=(Get-Date).ToUniversalTime().ToString('o');threatCount=`$threats.Count;threats=`$threats} | ConvertTo-Json -Depth 5
    `$wc2 = New-Object Net.WebClient
    [Net.ServicePointManager]::ServerCertificateValidationCallback = {`$true}
    `$wc2.Headers.Add('Content-Type','application/json')
    `$wc2.UploadString('$url/scan-status/$agentId', `$body2) | Out-Null
} catch {
    try {
        `$wc3 = New-Object Net.WebClient
        [Net.ServicePointManager]::ServerCertificateValidationCallback = {`$true}
        `$wc3.Headers.Add('Content-Type','application/json')
        `$wc3.UploadString('$url/scan-status/$agentId', (@{status='error';error=`$_.Exception.Message} | ConvertTo-Json)) | Out-Null
    } catch {}
} finally {
    Remove-Item '$flagFile' -Force -ErrorAction SilentlyContinue
}
"@
            Set-Content "C:\ProgramData\PalisadeOne\run-fds.ps1" $fdsScript -Force
            Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"C:\ProgramData\PalisadeOne\run-fds.ps1`"" -WindowStyle Hidden
            PLog "[FDS] Background scan process started"
        }
    }
    elseif ($data.action -eq "deploy-wdac") {
        $wdacMode = if ($data.params.mode) { $data.params.mode } else { "audit" }
        PLog "[WDAC] WDAC $wdacMode deployment requested"
        Log "WDAC $wdacMode deployment from ZT dashboard"
        try {
            New-Item -ItemType Directory -Path "C:\ProgramData\PalisadeOne\WDAC" -Force | Out-Null
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
            $wdacScript = (New-Object Net.WebClient).DownloadString("$url/ar-scripts/deploy-wdac.ps1")
            Set-Content "C:\ProgramData\PalisadeOne\WDAC\deploy-wdac.ps1" $wdacScript -Force
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "powershell.exe"
            $psi.Arguments = "-ExecutionPolicy Bypass -File `"C:\ProgramData\PalisadeOne\WDAC\deploy-wdac.ps1`" $wdacMode"
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.CreateNoWindow = $true
            $proc = [System.Diagnostics.Process]::Start($psi)
            $out = $proc.StandardOutput.ReadToEnd()
            $proc.WaitForExit(60000)
            PLog "[WDAC] Result: $($out.Trim().Substring(0, [Math]::Min($out.Trim().Length, 300)))"
        } catch { PLog "[WDAC] Error: $_" }
    }
    elseif ($data.action -eq "deploy-sysmon") {
        PLog "[SYSMON] Deployment requested"
        Log "Sysmon deployment from SOC dashboard"
        try {
            $sysmonDir = "C:\ProgramData\PalisadeOne\Sysmon"
            New-Item -ItemType Directory -Path $sysmonDir -Force | Out-Null
            if (-not (Test-Path "$sysmonDir\Sysmon64.exe")) {
                $wc2 = New-Object Net.WebClient
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
                $wc2.DownloadFile("https://live.sysinternals.com/Sysmon64.exe", "$sysmonDir\Sysmon64.exe")
                PLog "[SYSMON] Downloaded Sysmon64.exe"
            }
            $cfg = '<Sysmon schemaversion="4.90"><EventFiltering><ProcessCreate onmatch="exclude"/><NetworkConnect onmatch="exclude"/><ProcessTerminate onmatch="exclude"/><FileCreate onmatch="exclude"/><RegistryEvent onmatch="exclude"/><DnsQuery onmatch="exclude"/></EventFiltering></Sysmon>'
            Set-Content "$sysmonDir\sysmonconfig.xml" $cfg -Force
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "$sysmonDir\Sysmon64.exe"
            $psi.Arguments = "-accepteula -i `"$sysmonDir\sysmonconfig.xml`""
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.CreateNoWindow = $true
            $proc = [System.Diagnostics.Process]::Start($psi)
            $out = $proc.StandardOutput.ReadToEnd()
            $proc.WaitForExit(60000)
            PLog "[SYSMON] Done: $($out.Trim().Substring(0, [Math]::Min($out.Trim().Length, 200)))"
        } catch {
            PLog "[SYSMON] Error: $_"
        }
    }
} catch {
    PLog "[ERROR] $($_.Exception.Message)"
}
'@

Set-Content 'C:\ProgramData\PalisadeOne\agent-poller.ps1' $pollerContent -Force
Write-Host "[OK] Poller v5 deployed with restart, kill, FDS, WDAC, and Sysmon support" -ForegroundColor Green
Write-Host ""
Write-Host "Actions supported:" -ForegroundColor Cyan
Write-Host "  - isolate       Block all network traffic" -ForegroundColor Gray
Write-Host "  - unisolate     Restore network access" -ForegroundColor Gray
Write-Host "  - restart       Reboot endpoint in 60s" -ForegroundColor Gray
Write-Host "  - kill          Terminate a process by name" -ForegroundColor Gray
Write-Host "  - fds           Windows Defender full scan" -ForegroundColor Gray
Write-Host "  - deploy-sysmon Install Sysmon EDR telemetry" -ForegroundColor Gray
Write-Host ""
pause
