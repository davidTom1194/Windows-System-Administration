
<#
.SYNOPSIS
    This script syncs Intune-managed devices based on their serial numbers and enrolls them in AutoPilot.
    It checks if the Get-WindowsAutoPilotInfo script is installed and installs it if not.

.DESCRIPTION
    1. Checks if the Get-WindowsAutoPilotInfo script is installed and installs it if not.
    2. Connects to Microsoft Graph.
    3. Retrieves the Intune-managed device record via the serial number.
    4. Runs the Get-WindowsAutoPilotInfo script to sync the device to Intune.
    5. Moves the log file to a shared location.
    6. Closes the terminal window after a specified delay.
    7. Logs all actions and errors to a log file.

.NOTES
    Author:  David Tom
    Date:    03/19/2025
    File:    Intune - AutoPilot Enrollment.ps1
    Version: 1.0
    Edits:   1.0 - Initial version based on Jira Project Requirements.
    Brief:   This script syncs Intune-managed devices based on their serial
                numbers and enrolls them in AutoPilot.
    Purpose: To ensure devices are compliant with Intune policies and to
                facilitate the enrollment process.
    Contact: David Tom (Office of Technology Services)
    Email:   David.Tom@CSN.edu

    Permissions required:
    - Microsoft Graph API permissions to access device information.
    - PowerShell execution policy set to allow script execution.
#>

############################## Global Variables ###############################
$global:hostname = hostname
$global:serialNumber = ((Get-CimInstance -ClassName Win32_BIOS).SerialNumber).Trim().ToUpper()
$global:loggedInUser = $env:USERNAME
$global:LogRootPath = "C:\Logs\IntuneAutoPilot\$($global:serialNumber)\"
$global:LogDestination = "\\cyapsft01\software\Intune Scripts\Logs\Intune - AutoPilot Enrollment"

############################## Global Functions ###############################

function Initialize-Logging {
        <#
    .SYNOPSIS
        Initializes logging for the script.

    .DESCRIPTION
        This function sets up the logging environment by creating a log file
        in the specified directory. It also ensures that the directory exists.

    .PARAMETER LogRootPath 
        The root path where the log file will be created.

    .EXAMPLE
        Initialize-Logging -LogRootPath "C:\Logs\IntuneSyncLog"
    
    .NOTES
        Author:  David Tom
        Date:    03/19/2025
        Version: 1.0
        Edits:   1.0 - Initial version based on Jira Project Requirements.
        Brief:   This function initializes logging for the script.
        Purpose: To create a log file for tracking script execution and errors.
        Contact: David Tom (Office of Technology Services)
        Email:   David.Tom@CSN.edu
    #>

    param (
        [string]$LogRootPath = "C:\Logs\IntuneSyncLog\${serialNumber}\"
    )

    # Get basic system information
    $hostname = hostname
    $serialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber

    # Build the global log file path
    $global:LogFilePath = Join-Path -Path $LogRootPath -ChildPath (
        "Intune_Sync_${hostname}_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
    )

    # Ensure the log directory exists
    $logDir = Split-Path -Parent $global:LogFilePath
    if (-not (Test-Path -Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a timestamped message to the current log file.

    .DESCRIPTION
        Appends the specified message to the log file located at $global:LogFilePath
        (or at a custom path, if provided). Each log entry is prepended with a 
        timestamp. The message is also displayed on the console in yellow text.

    .PARAMETER Message
        The text to be written to the log file and echoed to the console.

    .PARAMETER ForegroundColor
        The console text color for the message. Defaults to 'Yellow' if not specified.
        Other options include 'Red', 'Green', 'Blue', etc.

    .PARAMETER LogFilePath
        The path to the log file. If not specified, $global:LogFilePath is used.
        If $global:LogFilePath is not set, an error is thrown.

    .PARAMETER BackgroundColor
        The console background color for the message. Defaults to 'Black' if not specified.
        Other options include 'White', 'Gray', etc.

    .PARAMETER Silent
        If set to $true, the message will not be displayed on the console.

    .EXAMPLE
        PS C:\> Write-Log -Message "All updates have been applied."
        Appends a timestamped message “All updates have been applied.” to the current log file 
        and prints it on screen in yellow by default.

        PS C:\> Write-Log -Message "Success!" -ForegroundColor Green -BackgroundColor Black
        Appends a timestamped message “Success!” to the log file 
        and prints it in green text in the console with a black background.

        PS C:\> Write-Log -Message "Function has finished" -Silent $true
        Appends a timestamped message “Function has finished” to the log file
        but does not print it on the console.

    .NOTES
        No direct return value. Write-Log depends on Initialize-Logging having been called first 
        to set the global log file path (unless you specify -LogFilePath explicitly).
    #>

    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [string]$LogFilePath = $global:LogFilePath,

        [System.ConsoleColor]
        $ForegroundColor = [System.ConsoleColor]::Yellow,

        [System.ConsoleColor]
        $BackgroundColor = [System.ConsoleColor]::Black,

        [switch]$Silent
    )

    if (-not $LogFilePath) {
        throw "No log file path has been set. Please call Initialize-Logging first."
    }

    $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    try {
        "$stamp - $Message" | Out-File -FilePath $LogFilePath -Append
    } catch {
    }
    
    if (-not $Silent) {
        Write-Host "$Message" -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor
    }
}

################################## Functions ##################################

function Verify-ScriptInstalledAndImport {
    <#
    .SYNOPSIS
        Verifies if a specified PowerShell module is installed and installs it if not.

    .DESCRIPTION
        This function checks if a specified PowerShell module is installed. If the module is not found, it installs the module from the PowerShell Gallery.

    .PARAMETER moduleName
        The name of the PowerShell module to verify.

    .EXAMPLE
        Verify-ModuleInstalled -moduleName "Microsoft.Graph.DeviceManagement"

    .NOTES
        Author:  David Tom
        Date:    03/19/2025
        Version: 1.0
        Edits:   1.0 - Initial version based on Jira Project Requirements.
        Brief:   This function verifies if a specified PowerShell module is
                    installed and installs it if not.
        Purpose: To ensure that the required PowerShell modules are available
                    for the script to run successfully.
        Contact: David Tom (Office of Technology Services)
        Email:   David.Tom@CSN.edu
    #>

    param (
        [string]$moduleName
    )

    # Log the start of the module verification
    Write-Log -Message "Verifying $moduleName script..." -Silent

    # Check if the module is installed and install if necessary
    $script = Get-InstalledScript -Name Get-WindowsAutoPilotInfo -ErrorAction SilentlyContinue

    if (-not $script) {
        # If the module is not installed, install it
        Write-Log "$moduleName is not installed. Installing..." -ForegroundColor Yellow -BackgroundColor Black
        
        # Install the module from the PowerShell Gallery
        Install-Script -Name $moduleName -Force -Confirm:$false | Out-Null
        Write-Log "$moduleName installation complete." -ForegroundColor Green -BackgroundColor Black
    } else {
        # If the module is already installed, notify the user
        Write-Log "$moduleName is already installed." -ForegroundColor Green -BackgroundColor Black
    }

    # Log the verified module installation status
    Write-Log "$moduleName script installation verification complete." -Silent

    Write-Log "Script verification and import complete." -Silent
}

function Sync-DeviceToAutopilot {
    <#
    .SYNOPSIS
        Syncs a device to Intune using its serial number.

    .DESCRIPTION
        This function syncs a device to Intune using its serial number. 
        It retrieves the device record from Intune and triggers a sync.

    .PARAMETER SerialNumber
        The serial number of the device to be synced.

    .EXAMPLE
        Sync-DeviceToIntune -SerialNumber "123456789"

    .NOTES
        Author:  David Tom
        Date:    03/19/2025
        Version: 1.0
        Edits:   1.0 - Initial version based on Jira Project Requirements.
        Brief:   This function syncs a device to Intune using its serial 
                    number.
        Purpose: To ensure that the device is located in Intune and to trigger
                    a sync.
        Contact: David Tom (Office of Technology Services)
        Email:   David.Tom@CSN.edu
    #>

    param (
        [Parameter(Mandatory = $true)]
        [string]$SerialNumber
    )

    # Retrieve the Intune-managed device record via the serial number
    Write-Log "Attempting to sync device with Serial Number: $global:serialNumber" -ForegroundColor Cyan -BackgroundColor Black

    try {
        # --- 1. Run AutoPilot script on the computer ---
        Write-Log "Running Get-WindowsAutoPilotInfo script..." -ForegroundColor Yellow -BackgroundColor Black
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Force
        
        # # Obtain the device's group tag
        # $groupTag = Read-Host "Enter the Group Tag (e.g., FS,WC) or leave blank for none"
        # # Remove spaces
        # $groupTag = $groupTag -replace "\s", ""
        # # Convert to uppercase
        # $groupTag = $groupTag.ToUpper()

        Get-WindowsAutoPilotInfo -Online   # -GroupTag $groupTag   # -AddToGroup "Group Name" -Assign
    } catch {
        # Any failure above brings us here
        Write-Log "ERROR on ${currentHostname}: $($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
    }

}

function Exit-Process {
    <#
    .SYNOPSIS
        Exits the script and closes the terminal window.

    .DESCRIPTION
        This function closes the terminal window after a specified delay.

    .EXAMPLE
        Exit-Process

    .NOTES
        Author:  David Tom
        Date:    03/19/2025
        Version: 1.0
        Edits:   1.0 - Initial version based on Jira Project Requirements.
        Brief:   This function exits the script and closes the terminal window.
        Purpose: To close the terminal window after a specified delay.
        Contact: David Tom (Office of Technology Services)
        Email:   David.Tom@CSN.edu
    #>

    # Finalize logging
    Write-Log "Script completed. Moving file to J Drive..." -Silent

    # Move the log file to a shared location
    Move-Item -Path "$global:LogRootPath" `
            -Destination "$global:LogDestination" `
            -Force

    # Wait for 30 seconds before closing the terminal window
    Write-Log "Closing window in 30 seconds..." -ForegroundColor Yellow -BackgroundColor Black
    Start-Sleep -Seconds 30

    # Close the terminal window
    exit
}

function Main {
    <#
    .SYNOPSIS
        Main function to execute the script.

    .DESCRIPTION
        This function serves as the entry point for the script. It initializes logging,
        imports required modules, connects to Microsoft Graph, and syncs the device.

    .EXAMPLE
        Main

    .NOTES
        Author:  David Tom
        Date:    03/19/2025
        Version: 1.0
        Edits:   1.0 - Initial version based on Jira Project Requirements.
        Brief:   This function serves as the entry point for the script.
        Purpose: To initialize logging, import required modules, connect to
                    Microsoft Graph, and sync the device.
        Contact: David Tom (Office of Technology Services)
        Email:   David.Tom@CSN.edu
    #>

    # Initialize and log the start of the script
    Initialize-Logging -LogRootPath $global:LogRootPath
    Write-Log -Message "Script started by $global:loggedInUser for SN: $global:serialNumber DN: $global:hostname." -ForegroundColor Green

    # Install and import the required modules
    foreach ($module in $ModulesToImport) {
        # Check if the module is installed and import it
        Write-Log -Message "Checking for $module module..." -ForegroundColor Yellow
        Verify-ScriptInstalledAndImport -moduleName $module
    }

    # Sync the device to Intune
    Sync-DeviceToAutopilot -SerialNumber $global:serialNumber

    # Exit the script and close the terminal window
    Exit-Process
}

######################## Variable & Array Declarations ########################

# Define the modules to import
$ModulesToImport = @(
    "Get-WindowsAutoPilotInfo"
)

###############################################################################
################################ Main Function ################################
###############################################################################

Main

#EOF: Intune - AutoPilot Enrollment.ps1