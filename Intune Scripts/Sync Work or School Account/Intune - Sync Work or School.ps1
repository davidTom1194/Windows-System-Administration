
<#
.SYNOPSIS
    This script checks for the Microsoft.Graph.DeviceManagement module, 
    installs it if missing, imports it, connects to Microsoft Graph, 
    and syncs an Intune-managed device based on its serial number.

.DESCRIPTION
    1. Ensures Microsoft.Graph.DeviceManagement is installed and imports it.
    2. Connects to Microsoft Graph.
    3. Retrieves the local device’s serial number.
    4. Queries Intune for a matching managed device.
    5. If found, triggers a sync.
    6. Opens Company Portal to prompt the user for compliance.
    7. Waits 30 seconds before closing.

.NOTES
    Author:  David Tom
    Date:    03/19/2025
    File:    Intune - Sync Work or School.ps1
    Version: 1.0
    Edits:   1.0 - Initial version based on Jira Project Requirements.
    Brief:   This script syncs Intune-managed devices based on their serial
                numbers.
    Purpose: To ensure devices are compliant with Intune policies and to
                facilitate the opening of the Company Portal app for user
                interaction.
    Contact: David Tom (Office of Technology Services)
    Email:   David.Tom@CSN.edu

    Permissions required:
    - DeviceManagementManagedDevices.Read.All
    - Group.Read.All
    - Directory.Read.All
#>

############################## Global Variables ###############################
$global:hostname = hostname
$global:serialNumber = ((Get-CimInstance -ClassName Win32_BIOS).SerialNumber).Trim().ToUpper()
$global:loggedInUser = $env:USERNAME
$global:LogRootPath = "C:\Logs\IntuneSyncLog\$($global:serialNumber)\"
$global:LogDestination = "\\cyapsft01\software\Intune Scripts\Logs\Intune - Sync Work or School"

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

function Verify-ModuleInstalledAndImport {
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
    Write-Log -Message "Verifying $moduleName module..." -Silent
    # "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Verifying $moduleName module..." | Out-File -FilePath $logFile -Append

    # Check if the module is installed and install if necessary
    $module = Get-Module -ListAvailable -Name $moduleName -ErrorAction SilentlyContinue
    if ($null -eq $module) {
        # If the module is not installed, install it
        Write-Log "$moduleName is not installed. Installing..." -ForegroundColor Yellow -BackgroundColor Black
        
        # Install the module from the PowerShell Gallery
        Install-Module -Name $moduleName -Scope CurrentUser -Force
        Write-Log "$moduleName installation complete." -ForegroundColor Green -BackgroundColor Black
    } else {
        # If the module is already installed, notify the user
        Write-Log "$moduleName is already installed." -ForegroundColor Green -BackgroundColor Black
    }

    # Log the verified module installation status
    Write-Log "$moduleName module installation verification complete." -Silent

    # Import the Microsoft.Graph.DeviceManagement module
    Write-Log "Importing $moduleName module..." -ForegroundColor Yellow -BackgroundColor Black
    Import-Module $moduleName -Force
    Write-Log "$moduleName module imported successfully." -ForegroundColor Green -BackgroundColor Black

    Write-Log "Module verification and import complete." -Silent
}

function ConnectToMgGraph {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph with the specified scopes.

    .DESCRIPTION
        This function connects to Microsoft Graph using the specified scopes. 
        It is assumed that the user has already authenticated and has the necessary permissions.

    .PARAMETER Scopes
        The scopes required for the connection. Defaults to "DeviceManagementServiceConfig.ReadWrite.All".

    .EXAMPLE
        Connect-MgGraph -Scopes "DeviceManagementServiceConfig.ReadWrite.All"

    .NOTES
        Author:  David Tom
        Date:    03/19/2025
        Version: 1.0
        Edits:   1.0 - Initial version based on Jira Project Requirements.
        Brief:   This function connects to Microsoft Graph with the specified 
                    scopes.
        Purpose: To establish a connection to Microsoft Graph for managing
                    Intune devices.
        Contact: David Tom (Office of Technology Services)
        Email:   David.Tom@CSN.edu
    #>

    # Connect to Microsoft Graph
    Write-Log "Connecting to Microsoft Graph..." -Silent
    Connect-MgGraph -NoWelcome
    Write-Log "Connected to Microsoft Graph!" -ForegroundColor Green -BackgroundColor Black

}

function Sync-DeviceToIntune {
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
    Write-Log "Attempting to locate device with Serial Number: $global:serialNumber" -ForegroundColor Cyan -BackgroundColor Black
    $managedDevice = Get-MgDeviceManagementManagedDevice -Filter "serialNumber eq '$global:serialNumber'"

    # Check if the device is found
    if ($managedDevice) {
        # If a matching device is found
        Write-Log "Device found in Intune. Initiating sync..." -ForegroundColor Yellow -BackgroundColor Black

        # Invoke an on-demand sync
        try {
            # Send a sync request to Intune
            Sync-MgDeviceManagementManagedDevice -ManagedDeviceId $managedDevice.Id -ErrorAction Stop
            Write-Log "Sync request has been sent to Intune. Policies will be applied upon next check-in." -ForegroundColor Green -BackgroundColor Black
        } catch {
            # Handle any errors that occur during the sync request
            Write-Host "Sync request failed with error:" $_.Exception.Message -ForegroundColor Red
        }

    } else {
        # If no matching device is found
        Write-Log "No Intune-managed device found with that serial number!" -ForegroundColor Red -BackgroundColor Black
    }
}

function Open-CompanyPortal {
    <#
    .SYNOPSIS
        Opens the Company Portal app.

    .DESCRIPTION
        This function opens the Company Portal app to prompt the user for compliance.

    .EXAMPLE
        Open-CompanyPortal

    .NOTES
        Author:  David Tom
        Date:    03/19/2025
        Version: 1.0
        Edits:   1.0 - Initial version based on Jira Project Requirements.
        Brief:   This function opens the Company Portal app.
        Purpose: To prompt the user for compliance and to facilitate the opening
                    of the Company Portal app.
        Contact: David Tom (Office of Technology Services)
        Email:   David.Tom@CSN.edu
    #>

    # Open the Company Portal app - defaults to File Explorer
    Write-Log "Attempting to open the Company Portal app..." -ForegroundColor Yellow -BackgroundColor Black
    Start-Process "explorer.exe" "shell:AppsFolder\Microsoft.CompanyPortal_8wekyb3d8bbwe!App"
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
        Verify-ModuleInstalledAndImport -moduleName $module
    }

    # Connect to Microsoft Graph
    ConnectToMgGraph

    # Sync the device to Intune
    Sync-DeviceToIntune -SerialNumber $global:serialNumber

    # Open the Company Portal app
    Open-CompanyPortal

    # Exit the script and close the terminal window
    Exit-Process
}

######################## Variable & Array Declarations ########################

# Define the modules to import
$ModulesToImport = @(
    "Microsoft.Graph.DeviceManagement"
)

###############################################################################
################################ Main Function ################################
###############################################################################

Main

#EOF: Intune - Sync Work or School.ps1