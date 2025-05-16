# Windows 11 Optimizer

This project provides a PowerShell script designed to optimize Windows 11 performance by implementing various techniques. The script includes functions to:

- Disable unnecessary services
- Optimize startup programs
- Clean temporary files
- Adjust system settings for enhanced performance

# Key Features
- Interactive Mode: Users can select which optimizations to apply through a menu
-Comprehensive Optimizations: Covers services, startup programs, temporary files, Windows features, and more
- Safety Measures: Creates system restore points and registry backups before making changes
- Progress Tracking: Shows a progress bar during optimization
- Detailed Logging: Writes all operations to a log file
- Error Handling: Robust error trapping and reporting
- System Compatibility Checks: Ensures the script is running on Windows 11 and checks for pending reboots

## Getting Started

To use the Windows 11 Optimizer script, follow these steps:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/lvictorerod/win11-optimizer.git
   cd win11-optimizer
   ```

2. **Usage: Open PowerShell as Administrator**:
   Right-click on the Start menu and select "Windows Terminal (Admin)" or "Windows PowerShell (Admin). Add parameters as needed".

- Interactive: Show menu to select optimizations
- SkipRestorePoint: Skip creating a system restore point
- QuietMode: Suppress console output
- LogFile: Specify a custom log file path

3. **Run the Script**:
   Navigate to the `scripts` directory and execute the optimization script:
   ```powershell
   cd scripts
   .\optimize-win11.ps1 -Interactive
   ```

## Optimizations Performed

The script performs the following optimizations:

- Disables services that are not essential for most users.
- Removes unnecessary startup programs to speed up boot time.
- Cleans up temporary files to free up disk space.
- Adjusts system settings to improve overall performance.

## Issues:
1. [Error] Critical error occurred: The 'Get-AppxPackage' command was found in the module 'Appx': 

[Fix] The error indicates that the PowerShell script failed because the Appx module could not be loaded, specifically due to a missing file in the Temp directory.
This usually happens if the Appx module is not installed, is corrupted, or if there are permission or environment issues with the Temp directory.
To resolve:
- Open a new PowerShell session as Administrator.
- Run Import-Module Appx to see if it loads without error.
- If it fails, ensure the Appx module is present by running Get-Module -ListAvailable Appx.
- If missing, repair your Windows installation or re-register built-in modules using:

```powershell
Get-WindowsCapability -Online | Where-Object Name -like '*App.Support*' | Add-WindowsCapability -Online
```
- Ensure your Temp directory exists and is accessible: $env:TEMP and $env:TMP should point to valid, writable locations.
For more details, see [Troubleshoot PowerShell module loading errors](https://learn.microsoft.com/powershell/scripting/troubleshooting/module-not-loading?view=powershell-7.4).

## Disclaimer

Use this script at your own risk. It is recommended to create a system restore point before running the optimizer to ensure you can revert any changes if necessary.

## License

This project is licensed under the MIT License - see the [[LICENSE](LICENSE)] file for details.
