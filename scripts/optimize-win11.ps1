# PowerShell script to optimize Windows 11

[CmdletBinding()]
param (
    [Parameter()]
    [switch]$Interactive = $false,
    [switch]$SkipRestorePoint = $false,
    [switch]$QuietMode = $false,
    [string]$LogFile = "$env:USERPROFILE\Desktop\Windows11Optimizer_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

# Configuration - Define what gets optimized
$config = @{
    DisableServices = $true
    OptimizeStartup = $true
    CleanTempFiles = $true
    ClearWindowsUpdateCache = $true
    AdjustPerformanceSettings = $true
    DisableTelemetry = $true
    RemoveBloatware = $true
    EmptyRecycleBin = $true
    DisableCortana = $true
    DisableBackgroundApps = $true
    OptimizePowerPlan = $true
    DisableWindowsDefender = $false  # Set to false by default for security
    OptimizeNetwork = $true
    DisableIndexing = $true
}

# Setup logging
function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    
    if (-not $QuietMode) {
        switch ($Level) {
            'Info' { Write-Host $logEntry }
            'Warning' { Write-Host $logEntry -ForegroundColor Yellow }
            'Error' { Write-Host $logEntry -ForegroundColor Red }
        }
    }
    
    Add-Content -Path $LogFile -Value $logEntry
}

# Function to show interactive menu and get user choices
function Show-InteractiveMenu {
    Clear-Host
    Write-Host "=== Windows 11 Optimizer ===" -ForegroundColor Cyan
    Write-Host "Please select which optimizations to apply:" -ForegroundColor White
    
    $menuItems = @(
        @{Name = "Disable Unnecessary Services"; ConfigKey = "DisableServices"},
        @{Name = "Optimize Startup Programs"; ConfigKey = "OptimizeStartup"},
        @{Name = "Clean Temporary Files"; ConfigKey = "CleanTempFiles"},
        @{Name = "Clear Windows Update Cache"; ConfigKey = "ClearWindowsUpdateCache"},
        @{Name = "Adjust Performance Settings"; ConfigKey = "AdjustPerformanceSettings"},
        @{Name = "Disable Telemetry"; ConfigKey = "DisableTelemetry"},
        @{Name = "Remove Bloatware Apps"; ConfigKey = "RemoveBloatware"},
        @{Name = "Empty Recycle Bin"; ConfigKey = "EmptyRecycleBin"},
        @{Name = "Disable Cortana"; ConfigKey = "DisableCortana"},
        @{Name = "Disable Background Apps"; ConfigKey = "DisableBackgroundApps"},
        @{Name = "Optimize Power Plan"; ConfigKey = "OptimizePowerPlan"},
        @{Name = "Disable Windows Defender"; ConfigKey = "DisableWindowsDefender"},
        @{Name = "Optimize Network Settings"; ConfigKey = "OptimizeNetwork"},
        @{Name = "Disable Windows Search Indexing"; ConfigKey = "DisableIndexing"}
    )
    
    for ($i = 0; $i -lt $menuItems.Count; $i++) {
        $status = if ($config[$menuItems[$i].ConfigKey]) { "[X]" } else { "[ ]" }
        Write-Host "$($i+1). $status $($menuItems[$i].Name)"
    }
    
    Write-Host "`nEnter the number to toggle an option (or 'A' for all, 'N' for none, 'R' to run):" -ForegroundColor Yellow
    $choice = Read-Host
    
    switch ($choice) {
        'A' { 
            foreach ($item in $menuItems) {
                $config[$item.ConfigKey] = $true
            }
        }
        'N' { 
            foreach ($item in $menuItems) {
                $config[$item.ConfigKey] = $false
            }
        }
        'R' { return }
        default {
            if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $menuItems.Count) {
                $configKey = $menuItems[[int]$choice - 1].ConfigKey
                $config[$configKey] = -not $config[$configKey]
            }
        }
    }
    
    Show-InteractiveMenu
}

# Function to create a backup of registry keys
function Backup-RegistryKeys {
    $backupFolder = "$env:USERPROFILE\Desktop\Win11Optimizer_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
    
    Write-Log "Creating registry backups in $backupFolder" -Level Info
    
    # Backup important registry hives
    $registryPaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications",
        "HKCU:\Control Panel\System"
    )
    
    foreach ($path in $registryPaths) {
        $hiveName = ($path -split '\\', 3)[2]
        $backupFile = Join-Path -Path $backupFolder -ChildPath "$($hiveName -replace '\\', '_').reg"
        
        try {
            if (Test-Path $path) {
                # Fix: Use single string argument format
                $regPath = $path.Replace('HKLM:', 'HKEY_LOCAL_MACHINE').Replace('HKCU:', 'HKEY_CURRENT_USER')
                Start-Process -FilePath "reg.exe" -ArgumentList "export `"$regPath`" `"$backupFile`" /y" -WindowStyle Hidden -Wait
                Write-Log "Backed up registry key: $path" -Level Info
            }
        }
        catch {
            Write-Log "Failed to backup registry key $path. Error: $_" -Level Error
        }
    }
    
    Write-Log "Registry backup complete" -Level Info
}

# Function to check system compatibility
function Test-SystemCompatibility {
    Write-Log "Checking system compatibility..." -Level Info
    
    # Check if running on Windows 11
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $isWin11 = $osInfo.Caption -match "Windows 11"
    
    if (-not $isWin11) {
        Write-Log "WARNING: This script is designed for Windows 11. You appear to be running $($osInfo.Caption)" -Level Warning
        
        if ($Interactive) {
            $continue = Read-Host "Continue anyway? (y/n)"
            if ($continue -ne 'y') {
                Write-Log "Script execution cancelled by user" -Level Info
                exit 0
            }
        }
    }
    
    # Check for pending reboots
    $pendingReboot = $false
    
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
        $pendingReboot = $true
    }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
        $pendingReboot = $true
    }
    
    if ($pendingReboot) {
        Write-Log "WARNING: System has a pending reboot. Optimizations may not apply correctly." -Level Warning
        
        if ($Interactive) {
            $continue = Read-Host "Continue anyway? (y/n)"
            if ($continue -ne 'y') {
                Write-Log "Script execution cancelled by user" -Level Info
                exit 0
            }
        }
    }
    
    Write-Log "System compatibility check completed" -Level Info
}

# Function to optimize network settings
function Optimize-NetworkSettings {
    if (-not $config.OptimizeNetwork) { return }
    
    Write-Log "Optimizing network settings..." -Level Info
    
    try {
        # Enable network auto-tuning
        netsh int tcp set global autotuninglevel=normal
        
        # Set DNS Cache size
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "CacheHashTableBucketSize" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "CacheHashTableSize" -Value 384 -Type DWord
        
        # Disable Network Throttling
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 0xffffffff -Type DWord
        
        Write-Log "Network settings optimized" -Level Info
    }
    catch {
        Write-Log "Failed to optimize network settings: $_" -Level Error
    }
}

# Function to disable Windows Search Indexing
function Disable-WindowsSearchIndexing {
    if (-not $config.DisableIndexing) { return }
    
    Write-Log "Disabling Windows Search Indexing..." -Level Info
    
    try {
        Stop-Service "WSearch" -Force -ErrorAction SilentlyContinue
        Set-Service "WSearch" -StartupType Disabled
        
        # Disable Windows Search in registry
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "PreventIndexingLowDiskSpaceMB" -Type DWORD -Value 0 -Force
        
        Write-Log "Windows Search Indexing disabled" -Level Info
    } 
    catch {
        Write-Log "Failed to disable Windows Search Indexing: $_" -Level Error
    }
}

# Function to check for administrator privileges
function Assert-Administrator {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "This script must be run as Administrator."
        exit 1
    }
}

# Function to create a system restore point
function Create-SystemRestorePoint {
    Write-Log "Creating a system restore point..." -Level Info
    try {
        # First ensure System Protection is enabled
        $systemDrive = $env:SystemDrive
        
        # Enable System Restore if needed
        Write-Log "Enabling system protection on $systemDrive..." -Level Info
        Enable-ComputerRestore -Drive $systemDrive -ErrorAction SilentlyContinue
        
        # Ensure Volume Shadow Copy service is running and set to Manual
        $vsService = Get-Service -Name VSS -ErrorAction SilentlyContinue
        if ($vsService) {
            if ($vsService.StartType -eq 'Disabled') {
                Set-Service -Name VSS -StartupType Manual -ErrorAction SilentlyContinue
            }
            if ($vsService.Status -ne 'Running') {
                Start-Service -Name VSS -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
        } else {
            Write-Log "Volume Shadow Copy service not found" -Level Warning
            return $false
        }
        
        # Ensure System Restore Service is running
        $srService = Get-Service -Name SDRSVC -ErrorAction SilentlyContinue
        if ($srService) {
            if ($srService.StartType -eq 'Disabled') {
                Set-Service -Name SDRSVC -StartupType Manual -ErrorAction SilentlyContinue
            }
            if ($srService.Status -ne 'Running') {
                Start-Service -Name SDRSVC -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
        }
        
        # Create the restore point
        Write-Log "Creating the restore point..." -Level Info
        Checkpoint-Computer -Description "Pre-Optimization Restore Point" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Log "System restore point created successfully." -Level Info
        return $true
    }
    catch {
        Write-Log "Failed to create system restore point: $_" -Level Warning
        Write-Log "Continuing without restore point..." -Level Warning
        return $false
    }
}

# Function to disable unnecessary services
function Disable-UnnecessaryServices {
    $services = @(
        "wuauserv",  # Windows Update
        "XblGameSave",  # Xbox Game Save
        "DiagTrack"  # Connected User Experiences and Telemetry
    )
    
    foreach ($service in $services) {
        Get-Service -Name $service -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Status -eq 'Running') {
                Stop-Service -Name $service -Force
                Set-Service -Name $service -StartupType Disabled
                Write-Host "Disabled service: $service"
            }
        }
    }
}

# Function to check if required services are available
function Test-RequiredServices {
    Write-Log "Checking required services..." -Level Info
    
    $requiredServices = @{
        "VSS" = "Volume Shadow Copy (required for restore points)"
        "wuauserv" = "Windows Update (required for update cache cleaning)"
        "WSearch" = "Windows Search (for indexing optimization)"
    }
    
    $issues = @()
    
    foreach ($service in $requiredServices.Keys) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if (-not $svc) {
            $issues += "$service ($($requiredServices[$service])) - Not found"
        }
        elseif ($svc.StartType -eq 'Disabled') {
            # Attempt to enable the service if it's disabled
            try {
                Write-Log "Enabling disabled service: $service" -Level Warning
                Set-Service -Name $service -StartupType Manual -ErrorAction Stop
            }
            catch {
                $issues += "$service ($($requiredServices[$service])) - Disabled (Failed to enable)"
            }
        }
    }
    
    if ($issues.Count -gt 0) {
        Write-Log "Some required services have issues:" -Level Warning
        foreach ($issue in $issues) {
            Write-Log "  - $issue" -Level Warning
        }
        
        if ($Interactive) {
            $continue = Read-Host "Some services may not be available. Continue anyway? (y/n)"
            if ($continue -ne 'y') {
                Write-Log "Script execution cancelled by user" -Level Info
                exit 0
            }
        }
    }
    else {
        Write-Log "All required services are available" -Level Info
    }
}

# Function to optimize startup programs
function Optimize-StartupPrograms {
    $startupPath = [System.Environment]::GetFolderPath('Startup')
    $programsToDisable = @(
        "SomeUnnecessaryApp.lnk"
    )
    
    foreach ($program in $programsToDisable) {
        $programPath = Join-Path -Path $startupPath -ChildPath $program
        if (Test-Path $programPath) {
            Remove-Item -Path $programPath -Force
            Write-Host "Removed startup program: $program"
        }
    }
}

# Function to clean temporary files
function Clean-TemporaryFiles {
    $tempPath = [System.IO.Path]::GetTempPath()
    Remove-Item "$tempPath\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Cleaned temporary files."
}

# Function to clear Windows Update cache
function Clear-WindowsUpdateCache {
    Write-Host "Clearing Windows Update cache..."
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    Write-Host "Windows Update cache cleared."
}

# Function to adjust system settings for performance
function Adjust-SystemSettings {
    Write-Log "Adjusting system settings for performance..." -Level Info
    
    try {
        # Fix: Use the correct registry path for visual effects
        $visualEffectsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
        
        # Create the path if it doesn't exist
        if (-not (Test-Path $visualEffectsPath)) {
            New-Item -Path $visualEffectsPath -Force | Out-Null
        }
        
        # Set visual effects for best performance
        Set-ItemProperty -Path $visualEffectsPath -Name "VisualFXSetting" -Value 2 -Type DWord
        
        # Additional performance settings
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value ([byte[]](0x90, 0x12, 0x03, 0x80, 0x10, 0x00, 0x00, 0x00)) -Type Binary
        
        Write-Log "System performance settings adjusted" -Level Info
    } 
    catch {
        Write-Log "Failed to adjust system settings: $_" -Level Error
    }
}

# Function to disable telemetry
function Disable-Telemetry {
    Write-Host "Disabling telemetry..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Force
    Write-Host "Telemetry disabled."
}

# Function to uninstall pre-installed bloatware apps
function Remove-BloatwareApps {
    $bloatwareApps = @(
        "Microsoft.XboxGamingOverlay",
        "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo",
        "Microsoft.GetHelp",
        "Microsoft.Getstarted",
        "Microsoft.Microsoft3DViewer",
        "Microsoft.MicrosoftSolitaireCollection"
    )
    foreach ($app in $bloatwareApps) {
        Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
        Write-Host "Attempted to remove: $app"
    }
}

# Function to empty Recycle Bin
function Empty-RecycleBin {
    Write-Host "Emptying Recycle Bin..."
    try {
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        Write-Host "Recycle Bin emptied."
    } catch {
        Write-Warning "Could not empty Recycle Bin."
    }
}

# Function to disable Cortana
function Disable-Cortana {
    Write-Host "Disabling Cortana..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Force
        Write-Host "Cortana disabled."
    } catch {
        Write-Warning "Could not disable Cortana."
    }
}

# Function to disable background apps
function Disable-BackgroundApps {
    Write-Host "Disabling background apps..."
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Value 1 -Force
        Write-Host "Background apps disabled."
    } catch {
        Write-Warning "Could not disable background apps."
    }
}

# Function to optimize power plan for performance
function Optimize-PowerPlan {
    Write-Host "Setting power plan to High Performance..."
    $highPerf = powercfg -l | Select-String -Pattern "High performance"
    if ($highPerf) {
        $guid = ($highPerf -split ' ')[3]
        powercfg -setactive $guid
        Write-Host "Power plan set to High Performance."
    } else {
        Write-Warning "High Performance power plan not found."
    }
}

# Function to display a summary report
function Show-Summary {
    Write-Host "`nOptimization complete. Summary:"
    Write-Host "- Unnecessary services disabled"
    Write-Host "- Startup programs optimized"
    Write-Host "- Temporary files cleaned"
    Write-Host "- Windows Update cache cleared"
    Write-Host "- System settings adjusted"
    Write-Host "- Telemetry disabled"
    Write-Host "- Bloatware apps removed"
    Write-Host "- Recycle Bin emptied"
    Write-Host "- Cortana disabled"
    Write-Host "- Background apps disabled"
    Write-Host "- Power plan optimized"
}

# Main script execution
try {
    Write-Log "====== Windows 11 Optimizer Started ======" -Level Info
    
    # Check if user wants interactive mode
    if ($Interactive) {
        Show-InteractiveMenu
    }
    
    # Verify privileges
    Assert-Administrator
    
    # Test system compatibility
    Test-SystemCompatibility

    # Test required services
    Test-RequiredServices
    
    # Create backup
    Backup-RegistryKeys
    
    # Create restore point if not skipped
    if (-not $SkipRestorePoint) {
        $restorePointCreated = Create-SystemRestorePoint
        if (-not $restorePointCreated -and $Interactive) {
            $continue = Read-Host "Failed to create restore point. Continue anyway? (y/n)"
            if ($continue -ne 'y') {
                Write-Log "Script execution cancelled by user" -Level Info
                exit 0
            }
        }
    }
    
    # Track progress
    $totalSteps = ($config.GetEnumerator() | Where-Object { $_.Value -eq $true }).Count
    $currentStep = 0
    
    # Run optimizations
    if ($config.DisableServices) {
        $currentStep++
        Write-Progress -Activity "Windows 11 Optimization" -Status "Step ${currentStep} of ${totalSteps}: Disabling Services" -PercentComplete (($currentStep / $totalSteps) * 100)
        Disable-UnnecessaryServices
    }
    
    if ($config.OptimizeStartup) {
        $currentStep++
        Write-Progress -Activity "Windows 11 Optimization" -Status "Step ${currentStep} of ${totalSteps}: Optimizing Startup" -PercentComplete (($currentStep / $totalSteps) * 100)
        Optimize-StartupPrograms
    }
    
    if ($config.CleanTempFiles) {
        $currentStep++
        Write-Progress -Activity "Windows 11 Optimization" -Status "Step ${currentStep} of ${totalSteps}: Cleaning Temp Files" -PercentComplete (($currentStep / $totalSteps) * 100)
        Clean-TemporaryFiles
    }
    
    if ($config.ClearWindowsUpdateCache) {
        $currentStep++
        Write-Progress -Activity "Windows 11 Optimization" -Status "Step ${currentStep} of ${totalSteps}: Clearing Windows Update Cache" -PercentComplete (($currentStep / $totalSteps) * 100)
        Clear-WindowsUpdateCache
    }
    
    if ($config.AdjustPerformanceSettings) {
        $currentStep++
        Write-Progress -Activity "Windows 11 Optimization" -Status "Step ${currentStep} of ${totalSteps}: Adjusting Performance Settings" -PercentComplete (($currentStep / $totalSteps) * 100)
        Adjust-SystemSettings
    }
    
    if ($config.DisableTelemetry) {
        $currentStep++
        Write-Progress -Activity "Windows 11 Optimization" -Status "Step ${currentStep} of ${totalSteps}: Disabling Telemetry" -PercentComplete (($currentStep / $totalSteps) * 100)
        Disable-Telemetry
    }
    
    if ($config.RemoveBloatware) {
        $currentStep++
        Write-Progress -Activity "Windows 11 Optimization" -Status "Step ${currentStep} of ${totalSteps}: Removing Bloatware" -PercentComplete (($currentStep / $totalSteps) * 100)
        Remove-BloatwareApps
    }
    
    if ($config.EmptyRecycleBin) {
        $currentStep++
        Write-Progress -Activity "Windows 11 Optimization" -Status "Step ${currentStep} of ${totalSteps}: Emptying Recycle Bin" -PercentComplete (($currentStep / $totalSteps) * 100)
        Empty-RecycleBin
    }
    
    if ($config.DisableCortana) {
        $currentStep++
        Write-Progress -Activity "Windows 11 Optimization" -Status "Step ${currentStep} of ${totalSteps}: Disabling Cortana" -PercentComplete (($currentStep / $totalSteps) * 100)
        Disable-Cortana
    }
    
    if ($config.DisableBackgroundApps) {
        $currentStep++
        Write-Progress -Activity "Windows 11 Optimization" -Status "Step ${currentStep} of ${totalSteps}: Disabling Background Apps" -PercentComplete (($currentStep / $totalSteps) * 100)
        Disable-BackgroundApps
    }
    
    if ($config.OptimizePowerPlan) {
        $currentStep++
        Write-Progress -Activity "Windows 11 Optimization" -Status "Step ${currentStep} of ${totalSteps}: Optimizing Power Plan" -PercentComplete (($currentStep / $totalSteps) * 100)
        Optimize-PowerPlan
    }
    
    if ($config.OptimizeNetwork) {
        $currentStep++
        Write-Progress -Activity "Windows 11 Optimization" -Status "Step ${currentStep} of ${totalSteps}: Optimizing Network Settings" -PercentComplete (($currentStep / $totalSteps) * 100)
        Optimize-NetworkSettings
    }
    
    if ($config.DisableIndexing) {
        $currentStep++
        Write-Progress -Activity "Windows 11 Optimization" -Status "Step ${currentStep} of ${totalSteps}: Disabling Windows Search Indexing" -PercentComplete (($currentStep / $totalSteps) * 100)
        Disable-WindowsSearchIndexing
    }
    
    Write-Progress -Activity "Windows 11 Optimization" -Completed
    
    # Show summary
    Show-Summary
    
    Write-Log "====== Windows 11 Optimization Completed Successfully ======" -Level Info
    Write-Log "Log file saved to: $LogFile" -Level Info
    
    if ($Interactive) {
        Write-Host "`nPress any key to exit..." -ForegroundColor Green
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}
catch {
    Write-Log "Critical error occurred: $_" -Level Error
    Write-Log "Script execution failed!" -Level Error
    
    if ($Interactive) {
        Write-Host "`nPress any key to exit..." -ForegroundColor Red
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    exit 1
}