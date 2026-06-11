# Windows PowerShell Script to Register DeepCytes DNS Security Agent in Task Scheduler
# This script must be run as an Administrator.

$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}

$MainScript = Join-Path $ScriptDir "main.py"
$PythonExe = (Get-Command python.exe -ErrorAction SilentlyContinue).Source

if (-not $PythonExe) {
    Write-Error "Python.exe was not found in the system PATH. Please ensure Python is installed and available."
    exit 1
}

Write-Host "Registering DeepCytes DNS Agent in Windows Task Scheduler..." -ForegroundColor Cyan
Write-Host "Script Path: $MainScript"
Write-Host "Python Path: $PythonExe"
Write-Host "Working Directory: $ScriptDir"

# Action: Run Python main.py in the project directory
$Action = New-ScheduledTaskAction -Execute $PythonExe -Argument "`"$MainScript`"" -WorkingDirectory $ScriptDir

# Trigger: Run at user logon (so the console is visible, but runs with admin rights)
$Trigger = New-ScheduledTaskTrigger -AtLogon

# Settings: Allow running on batteries, restart if failed
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

# Principal: Run with Highest Privileges (required for Scapy raw socket packet sniffing)
# We run under the current user's domain/username with elevated credentials.
$CurrentUser = "$env:USERDOMAIN\$env:USERNAME"
$Principal = New-ScheduledTaskPrincipal -UserId $CurrentUser -LogonType Interactive -RunLevel Highest

# Register task (overwrite if exists)
$TaskName = "DeepCytesDNSAgent"
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Force

Write-Host "`nTask '$TaskName' has been successfully registered!" -ForegroundColor Green
Write-Host "It will run automatically whenever you log into the machine." -ForegroundColor Green
Write-Host "It is configured to run with Administrator privileges so the live packet sniffer can access raw sockets." -ForegroundColor Green
Write-Host "To verify or manage the task, open 'Task Scheduler' (taskschd.msc) and look for '$TaskName' in the Active Tasks." -ForegroundColor Cyan
