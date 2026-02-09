# SENTINEL Shield - Integration Test Harness
# ============================================
#
# End-to-end test: log file -> parser -> detection engine -> graph -> scorer -> response
#
# This script:
# 1. Creates a temp directory with test log files and config
# 2. Builds SENTINEL Shield in release mode
# 3. Runs the attack simulator to populate initial log data
# 4. Starts the SENTINEL Shield daemon watching those logs
# 5. Appends more attack patterns while the daemon is watching
# 6. Stops the daemon and checks outputs
# 7. Runs benign scenario and verifies NO alerts
# 8. Reports PASS/FAIL
#
# Copyright (c) 2026 CIPS Corps. All rights reserved.

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Test-Path "$ProjectRoot\Cargo.toml")) {
    # We might be running from within tests/ directly
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
    if (-not (Test-Path "$ProjectRoot\Cargo.toml")) {
        $ProjectRoot = $PSScriptRoot
        # Try one more level up
        while (-not (Test-Path "$ProjectRoot\Cargo.toml") -and $ProjectRoot -ne "") {
            $ProjectRoot = Split-Path -Parent $ProjectRoot
        }
    }
}

$ScriptDir = $PSScriptRoot
$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "sentinel-shield-integration-test-$(Get-Random)"
$AuthLog = Join-Path $TempDir "auth.log"
$WebLog = Join-Path $TempDir "access.log"
$SyslogFile = Join-Path $TempDir "syslog.log"
$DataDir = Join-Path $TempDir "sentinel-data"
$AlertLog = Join-Path $DataDir "alerts.jsonl"
$GraphState = Join-Path $DataDir "graph.json"
$ConfigFile = Join-Path $TempDir "sentinel-shield.toml"
$DaemonLog = Join-Path $TempDir "daemon-output.log"
$PythonExe = Join-Path $ScriptDir "venv\Scripts\python.exe"
$SimulatorScript = Join-Path $ScriptDir "attack_simulator.py"

# Fall back to system python if venv doesn't exist
if (-not (Test-Path $PythonExe)) {
    $PythonExe = "python"
}

$TestsPassed = 0
$TestsFailed = 0
$TestResults = @()

# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

function Write-TestHeader($msg) {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $msg" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}

function Write-TestResult($name, $passed, $detail = "") {
    if ($passed) {
        Write-Host "  [PASS] $name" -ForegroundColor Green
        $script:TestsPassed++
        $script:TestResults += @{ Name = $name; Passed = $true; Detail = $detail }
    } else {
        Write-Host "  [FAIL] $name" -ForegroundColor Red
        if ($detail) { Write-Host "         $detail" -ForegroundColor Yellow }
        $script:TestsFailed++
        $script:TestResults += @{ Name = $name; Passed = $false; Detail = $detail }
    }
}

function Write-Step($msg) {
    Write-Host "  >> $msg" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

Write-TestHeader "SENTINEL Shield Integration Test"
Write-Host "  Project root: $ProjectRoot"
Write-Host "  Temp dir:     $TempDir"
Write-Host "  Python:       $PythonExe"

# Create temp directory structure
Write-Step "Creating temp directory structure..."
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null

# Create empty log files (daemon needs them to exist)
"" | Out-File -FilePath $AuthLog -Encoding ASCII -NoNewline
"" | Out-File -FilePath $WebLog -Encoding ASCII -NoNewline
"" | Out-File -FilePath $SyslogFile -Encoding ASCII -NoNewline

# Write test config TOML
Write-Step "Writing test configuration..."
$ConfigContent = @"
[general]
eval_interval_secs = 2
data_dir = "$($DataDir -replace '\\', '\\\\')"
graph_state_file = "$($GraphState -replace '\\', '\\\\')"

[detection]
threat_threshold = 0.3
velocity_weight = 0.4
coverage_weight = 0.35
correlation_weight = 0.25
velocity_window_secs = 120
velocity_saturation = 50
coverage_saturation = 15
correlation_min_gap_secs = 1
correlation_max_gap_secs = 300

[log_sources]
auth_log_paths = ["$($AuthLog -replace '\\', '\\\\')"]
web_log_paths = ["$($WebLog -replace '\\', '\\\\')"]
syslog_paths = ["$($SyslogFile -replace '\\', '\\\\')"]

[response]
blocking_enabled = false
alert_log_path = "$($AlertLog -replace '\\', '\\\\')"

[dashboard]
enabled = false
bind_address = "127.0.0.1"
port = 0
"@
$ConfigContent | Out-File -FilePath $ConfigFile -Encoding UTF8

# ---------------------------------------------------------------------------
# Step 1: Build SENTINEL Shield
# ---------------------------------------------------------------------------

Write-TestHeader "Step 1: Building SENTINEL Shield (release mode)"
Write-Step "Running cargo build --release..."

$BuildOutput = & cargo build --release --manifest-path "$ProjectRoot\Cargo.toml" 2>&1
$BuildSuccess = $LASTEXITCODE -eq 0
Write-TestResult "cargo build --release" $BuildSuccess ($BuildOutput | Select-Object -Last 3 | Out-String).Trim()

if (-not $BuildSuccess) {
    Write-Host "  BUILD FAILED -- cannot continue integration tests" -ForegroundColor Red
    exit 1
}

$BinaryPath = Join-Path $ProjectRoot "target\release\sentinel-shield.exe"
if (-not (Test-Path $BinaryPath)) {
    Write-Host "  Binary not found at: $BinaryPath" -ForegroundColor Red
    exit 1
}
Write-Step "Binary: $BinaryPath"

# ---------------------------------------------------------------------------
# Step 2: Run attack simulator (populate initial data)
# ---------------------------------------------------------------------------

Write-TestHeader "Step 2: Running Attack Simulator (full_kill_chain)"
Write-Step "Populating log files before daemon start..."

& $PythonExe $SimulatorScript `
    --scenario full_kill_chain `
    --auth-log $AuthLog `
    --web-log $WebLog `
    --syslog-path $SyslogFile 2>&1

$SimSuccess = $LASTEXITCODE -eq 0
Write-TestResult "attack_simulator.py (full_kill_chain)" $SimSuccess

# Verify log files have content
$AuthSize = (Get-Item $AuthLog).Length
$WebSize = (Get-Item $WebLog).Length
$SysSize = (Get-Item $SyslogFile).Length
Write-TestResult "auth.log has content ($AuthSize bytes)" ($AuthSize -gt 0)
Write-TestResult "access.log has content ($WebSize bytes)" ($WebSize -gt 0)
Write-TestResult "syslog has content ($SysSize bytes)" ($SysSize -gt 0)

# ---------------------------------------------------------------------------
# Step 3: Start SENTINEL Shield daemon
# ---------------------------------------------------------------------------

Write-TestHeader "Step 3: Starting SENTINEL Shield Daemon"
Write-Step "Starting daemon in background..."

# Start the daemon as a background process
$DaemonProcess = Start-Process -FilePath $BinaryPath `
    -ArgumentList "--config", $ConfigFile, "start" `
    -RedirectStandardOutput $DaemonLog `
    -RedirectStandardError (Join-Path $TempDir "daemon-error.log") `
    -PassThru -NoNewWindow `
    -WorkingDirectory $TempDir

$DaemonPID = $DaemonProcess.Id
Write-Step "Daemon started with PID: $DaemonPID"
Write-TestResult "daemon started" ($DaemonPID -gt 0)

# Wait for first poll cycle
Write-Step "Waiting 4 seconds for initial poll cycle..."
Start-Sleep -Seconds 4

# ---------------------------------------------------------------------------
# Step 4: Append more attacks while daemon watches
# ---------------------------------------------------------------------------

Write-TestHeader "Step 4: Appending Attacks While Daemon Watches"
Write-Step "Running credential_spray scenario..."

& $PythonExe $SimulatorScript `
    --scenario credential_spray `
    --auth-log $AuthLog `
    --web-log $WebLog `
    --syslog-path $SyslogFile 2>&1

Write-Step "Running web_recon_to_exploit scenario..."

& $PythonExe $SimulatorScript `
    --scenario web_recon_to_exploit `
    --auth-log $AuthLog `
    --web-log $WebLog `
    --syslog-path $SyslogFile 2>&1

# Wait for detection cycles
Write-Step "Waiting 6 seconds for detection cycles..."
Start-Sleep -Seconds 6

# ---------------------------------------------------------------------------
# Step 5: Stop daemon
# ---------------------------------------------------------------------------

Write-TestHeader "Step 5: Stopping Daemon"

$StillRunning = -not $DaemonProcess.HasExited
Write-TestResult "daemon was still running" $StillRunning

if ($StillRunning) {
    Write-Step "Sending stop signal..."
    try {
        Stop-Process -Id $DaemonPID -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    } catch {
        Write-Step "Stop-Process exception (may be normal): $_"
    }
}

# ---------------------------------------------------------------------------
# Step 6: Check outputs
# ---------------------------------------------------------------------------

Write-TestHeader "Step 6: Checking Detection Outputs"

# Check daemon log output
if (Test-Path $DaemonLog) {
    $DaemonOutput = Get-Content $DaemonLog -Raw -ErrorAction SilentlyContinue
    Write-Step "Daemon log size: $((Get-Item $DaemonLog).Length) bytes"
} else {
    $DaemonOutput = ""
    Write-Step "No daemon log found"
}

# Check error log
$ErrorLogPath = Join-Path $TempDir "daemon-error.log"
if (Test-Path $ErrorLogPath) {
    $ErrorOutput = Get-Content $ErrorLogPath -Raw -ErrorAction SilentlyContinue
    if ($ErrorOutput -and $ErrorOutput.Trim()) {
        Write-Step "Daemon stderr (first 500 chars):"
        Write-Host ($ErrorOutput.Substring(0, [Math]::Min(500, $ErrorOutput.Length))) -ForegroundColor DarkYellow
    }
}

# Check alerts.jsonl
$AlertsExist = Test-Path $AlertLog
Write-TestResult "alerts.jsonl was created" $AlertsExist

if ($AlertsExist) {
    $AlertLines = Get-Content $AlertLog | Where-Object { $_.Trim() -ne "" }
    $AlertCount = ($AlertLines | Measure-Object).Count
    Write-TestResult "alerts were generated ($AlertCount alerts)" ($AlertCount -gt 0)

    if ($AlertCount -gt 0) {
        Write-Step "Alert samples:"
        $AlertLines | Select-Object -First 3 | ForEach-Object {
            try {
                $alert = $_ | ConvertFrom-Json
                Write-Host "    IP: $($alert.source_ip) | Score: $($alert.threat_score) | Level: $($alert.threat_level)" -ForegroundColor Yellow
            } catch {
                Write-Host "    (parse error: $_)" -ForegroundColor Red
            }
        }

        # Check that attacker IP was flagged
        $AttackerAlerted = $AlertLines | Where-Object { $_ -match "203\.0\.113\.50" }
        Write-TestResult "attacker IP 203.0.113.50 was flagged" (($AttackerAlerted | Measure-Object).Count -gt 0)

        # Check threat scores
        $MaxScore = 0.0
        foreach ($line in $AlertLines) {
            try {
                $a = $line | ConvertFrom-Json
                if ($a.threat_score -gt $MaxScore) { $MaxScore = $a.threat_score }
            } catch {}
        }
        Write-TestResult "peak threat score > 0.3 (got $([Math]::Round($MaxScore, 3)))" ($MaxScore -gt 0.3)
    }
} else {
    Write-TestResult "alerts were generated" $false "alerts.jsonl not found"
}

# Check graph state
$GraphExists = Test-Path $GraphState
Write-TestResult "graph state file was saved" $GraphExists

if ($GraphExists) {
    $GraphSize = (Get-Item $GraphState).Length
    Write-TestResult "graph state has content ($GraphSize bytes)" ($GraphSize -gt 100)

    try {
        $GraphData = Get-Content $GraphState -Raw | ConvertFrom-Json
        $TotalObs = $GraphData.total_observations
        $SourceCount = ($GraphData.sources | Get-Member -MemberType NoteProperty | Measure-Object).Count
        Write-Step "Graph: $TotalObs observations, $SourceCount sources"
        Write-TestResult "graph has observations" ($TotalObs -gt 0)
    } catch {
        Write-Step "Could not parse graph JSON: $_"
    }
}

# ---------------------------------------------------------------------------
# Step 7: Benign traffic test
# ---------------------------------------------------------------------------

Write-TestHeader "Step 7: Benign Traffic Test (False Positive Check)"

# Create fresh temp files for benign test
$BenignDir = Join-Path $TempDir "benign"
New-Item -ItemType Directory -Path $BenignDir -Force | Out-Null
$BenignAuth = Join-Path $BenignDir "auth.log"
$BenignWeb = Join-Path $BenignDir "access.log"
$BenignSys = Join-Path $BenignDir "syslog.log"
$BenignData = Join-Path $BenignDir "sentinel-data"
$BenignAlerts = Join-Path $BenignData "alerts.jsonl"
$BenignGraph = Join-Path $BenignData "graph.json"
$BenignConfig = Join-Path $BenignDir "sentinel-shield.toml"

New-Item -ItemType Directory -Path $BenignData -Force | Out-Null
"" | Out-File -FilePath $BenignAuth -Encoding ASCII -NoNewline
"" | Out-File -FilePath $BenignWeb -Encoding ASCII -NoNewline
"" | Out-File -FilePath $BenignSys -Encoding ASCII -NoNewline

# Write benign test config (higher threshold to be strict)
$BenignConfigContent = @"
[general]
eval_interval_secs = 2
data_dir = "$($BenignData -replace '\\', '\\\\')"
graph_state_file = "$($BenignGraph -replace '\\', '\\\\')"

[detection]
threat_threshold = 0.3
velocity_weight = 0.4
coverage_weight = 0.35
correlation_weight = 0.25
velocity_window_secs = 120
velocity_saturation = 50
coverage_saturation = 15
correlation_min_gap_secs = 1
correlation_max_gap_secs = 300

[log_sources]
auth_log_paths = ["$($BenignAuth -replace '\\', '\\\\')"]
web_log_paths = ["$($BenignWeb -replace '\\', '\\\\')"]
syslog_paths = ["$($BenignSys -replace '\\', '\\\\')"]

[response]
blocking_enabled = false
alert_log_path = "$($BenignAlerts -replace '\\', '\\\\')"

[dashboard]
enabled = false
bind_address = "127.0.0.1"
port = 0
"@
$BenignConfigContent | Out-File -FilePath $BenignConfig -Encoding UTF8

# Run benign traffic
Write-Step "Running benign_traffic scenario..."
& $PythonExe $SimulatorScript `
    --scenario benign_traffic `
    --auth-log $BenignAuth `
    --web-log $BenignWeb `
    --syslog-path $BenignSys 2>&1

# Start daemon for benign test
$BenignDaemonLog = Join-Path $BenignDir "daemon.log"
$BenignProcess = Start-Process -FilePath $BinaryPath `
    -ArgumentList "--config", $BenignConfig, "start" `
    -RedirectStandardOutput $BenignDaemonLog `
    -RedirectStandardError (Join-Path $BenignDir "daemon-error.log") `
    -PassThru -NoNewWindow `
    -WorkingDirectory $BenignDir

Write-Step "Benign daemon PID: $($BenignProcess.Id)"
Start-Sleep -Seconds 5

# Stop benign daemon
if (-not $BenignProcess.HasExited) {
    Stop-Process -Id $BenignProcess.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# Check that NO alerts were generated for benign traffic
$BenignAlertsExist = (Test-Path $BenignAlerts) -and ((Get-Item $BenignAlerts).Length -gt 10)
if ($BenignAlertsExist) {
    $BenignAlertLines = Get-Content $BenignAlerts | Where-Object { $_.Trim() -ne "" }
    $BenignAlertCount = ($BenignAlertLines | Measure-Object).Count
    Write-TestResult "no alerts for benign traffic (got $BenignAlertCount)" ($BenignAlertCount -eq 0)
} else {
    Write-TestResult "no alerts for benign traffic" $true "alerts.jsonl empty or missing (correct)"
}

# ---------------------------------------------------------------------------
# Step 8: Summary
# ---------------------------------------------------------------------------

Write-TestHeader "Integration Test Summary"

$TotalTests = $TestsPassed + $TestsFailed
Write-Host ""
foreach ($r in $TestResults) {
    $icon = if ($r.Passed) { "[PASS]" } else { "[FAIL]" }
    $color = if ($r.Passed) { "Green" } else { "Red" }
    Write-Host "  $icon $($r.Name)" -ForegroundColor $color
}

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor $(if ($TestsFailed -eq 0) { "Green" } else { "Red" })
Write-Host "  RESULTS: $TestsPassed passed, $TestsFailed failed, $TotalTests total" -ForegroundColor $(if ($TestsFailed -eq 0) { "Green" } else { "Red" })
Write-Host ("=" * 70) -ForegroundColor $(if ($TestsFailed -eq 0) { "Green" } else { "Red" })

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

Write-Step "Cleaning up temp directory: $TempDir"
try {
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Step "Cleanup complete."
} catch {
    Write-Step "Cleanup warning: $_"
}

# Exit with appropriate code
if ($TestsFailed -gt 0) {
    exit 1
} else {
    exit 0
}
