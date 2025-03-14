<#
.SYNOPSIS
    This Windows 11 PowerShell script attempts to update all required software,
    settings, and registry keys during a device’s post-checks with minimal user
    intervention.

.DESCRIPTION
    As per CSN's OTS imaging requirements, the script verifies Windows 11 licenses
    and, if necessary, updates them to Enterprise. It also attempts to update
    crucial software (e.g., browsers) and perform other post-imaging tasks.

    Some manual tasks, such as updating Creative Cloud and flashing Asset Tags, will
    still be required.

.EXAMPLE
    PS C:\> .\postChecks.ps1
    Runs all of the automated post-check updates and validations.

.NOTES
    Author:  David Tom
    Date:    03/14/2025
    File:    postChecks.ps1
    Version: 1.4
    Edits:   1.0 - Initial version based on Jira Project Requirements.
                1.1 - Added more functions and error handling with logging functions.
                1.2 - Modified the script to use the new logging functions.
                1.3 - Modified script to implement PowerShell 7 functionality.
                1.4 - Cleaned up the script and added more comments.
    Brief:   This script performs post-checks on Windows 10/11 devices.
    Contact: David Tom (OTS)

    TODO:
        1. Add more error handling and logging.
        2. Update Intune integration for software deployment.
        3. Implement Lenovo Vantage software deployment.
#>

# TODO: Install PowerShell Version 7 and utilize the most effective version after testing/development
# PS C:\Users\david.tom> iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI"

# TODO:
# Ensure script functions as intended with noted functions: 
# WindowsUpdaterPowerShell, wingetUpdater, RemoveBloat, and MainFunction

############################## Global Functions ###############################

function Initialize-Logging {
    <#
    .SYNOPSIS
        Initializes logging for the script.

    .DESCRIPTION
        Retrieves hostname, serial number, and logged-in user to create a uniquely
        named log file in the specified root path. Ensures the necessary directory
        structure exists and writes a “start of script” message to the new log file.

    .PARAMETER LogRootPath
        The root directory where log files will be stored. Defaults to
        \\cyapsft01\software\postChecks\logs if not specified.

    .EXAMPLE
        PS C:\> Initialize-Logging
        Creates a log file in the default path using hostname, serial number, 
        and current date/time in the file name.

    .NOTES
        No return value. Throws no exceptions beyond directory creation errors.
        Global variable $global:LogFilePath is set and used for subsequent logging.
    #>
    param (
        [string]$LogRootPath = "\\cyapsft01\software\postChecks\logs"
    )

    # Get basic machine/user info
    $hostname = (hostname).Trim()
    $serialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
    $loggedInUser = (whoami).Trim()
    
    # Build the global log file path
    $global:LogFilePath = Join-Path -Path $LogRootPath -ChildPath (
        "$hostname $serialNumber\postChecks-log_$($env:UserName)_$((Get-Date).ToString('yyyyMMdd_HHmmss'))_$serialNumber`_$hostname.log"
    )

    # Ensure the Logs directory exists
    $logDir = Split-Path -Parent $global:LogFilePath
    if (-not (Test-Path -Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    # Write start of script message
    $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
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

function UserAcknowledgement {
    <#
    .SYNOPSIS
        Advises the user on how to run the script and provides contact information.

    .DESCRIPTION
        This function displays a message box explaining manual and automatic tasks 
        required after imaging (or during post checks). It informs the user about 
        updating Lenovo System Updater, Creative Cloud, verifying SCCM actions, 
        flashing Asset Tag, and installing missing apps. It also provides contact 
        information (David Tom) for additional help.

    .PARAMETER None
        This function does not accept parameters.

    .EXAMPLE
        PS C:\> UserAcknowledgement
        Displays a pop-up message with instructions and logs the user acknowledgement.

    .NOTES
        Author: David Tom (OTS)
        Questions, comments, or concerns: David.Tom@CSN.edu
    #>

    # Load Windows Forms Assembly
    Add-Type -AssemblyName System.Windows.Forms

    # Display the popup message box
    $result = [System.Windows.Forms.MessageBox]::Show("Note:

        The program will automatically perform a majority of the required post checks but manual verification is needed for the below processes:

        1. Manually update:
            - Lenovo System Update
            - Creative Cloud

        2. Manually verify:
            - SCCM Actions are available
            - Run Action [User Policy Retrieval & Evaluation Cycle]

        3. Manually verify and flash Asset Tag as needed.

        4. Manually install any missing Apps & Programs.

        5. Run the following after you reboot!
            - Window's Update
            - Lenovo System Update

        Any questions, comments, or concerns please contact:
        David Tom (David.Tom@CSN.edu)", "Post Checks - Acknowledgement", 
        [System.Windows.Forms.MessageBoxButtons]::OK, 
        [System.Windows.Forms.MessageBoxIcon]::Information
    )

    # Handle the user's response
    $acknowledgedUser = whoami

    # Log the user acknowledgement
    switch ($result) {
        'OK' {
            Write-Log -Message "$acknowledgedUser has acknowledged the notice." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
        } Default {
            Write-Log -Message "User response: $result" -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black     
        }
    }
}

function UserSelection {
    <#
    .SYNOPSIS
        Prompts the user to select either "Quick" or "Full" post-check operations.

    .DESCRIPTION
        Presents a GUI form with two buttons:
        - Quick
        - Full
        The user’s choice is stored in the form’s Tag property and is returned
        once the form is closed. If no choice is made, the function defaults to
        "Full" before returning.

    .PARAMETER None
        This function does not accept any parameters.

    .EXAMPLE
        PS C:\> $selection = UserSelection
        Prompts the user with a form to choose either "Quick" or "Full." 
        The user's choice ("Quick" or "Full") is stored in $selection.

    .NOTES
        Author:  David Tom (OTS)
        Contact: David.Tom@CSN.edu for questions, comments, or concerns.
    #>

    # Load Windows Forms and Drawing Assemblies
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # Create the form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Post-Check Selection"
    $form.Size = New-Object System.Drawing.Size(320, 180)
    $form.StartPosition = "CenterScreen"

    # Initialize the Tag property to $null
    $form.Tag = $null

    # Create a label for the prompt
    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Please select a Quick or Full operation..."
    $label.AutoSize = $true
    $label.Location = New-Object System.Drawing.Point(15, 20)

    # Create the Quick button
    $buttonQuick = New-Object System.Windows.Forms.Button
    $buttonQuick.Text = "Quick"
    $buttonQuick.Width = 100
    $buttonQuick.Height = 30
    $buttonQuick.Location = New-Object System.Drawing.Point(30, 70)
    $buttonQuick.Add_Click({
        $form.Tag = "Quick"
        # Write-Host "DEBUG: Quick button clicked"
        $form.Close()
    })

    # Create the Full button
    $buttonFull = New-Object System.Windows.Forms.Button
    $buttonFull.Text = "Full"
    $buttonFull.Width = 100
    $buttonFull.Height = 30
    $buttonFull.Location = New-Object System.Drawing.Point(170, 70)
    $buttonFull.Add_Click({
        $form.Tag = "Full"
        # Write-Host "DEBUG: Full button clicked"
        $form.Close()
    })

    # Add controls to the form
    $form.Controls.Add($label)
    $form.Controls.Add($buttonQuick)
    $form.Controls.Add($buttonFull)

    # Show the form (modal)
    $form.ShowDialog() | Out-Null

    # If no selection was made, default to "Full"
    if (-not $form.Tag) {
        $form.Tag = "Full"
    }

    # Return the selection stored in the Tag property
    return $form.Tag
}

function Get-ADRecoveryKey {
    <#
    .SYNOPSIS
        Retrieves the BitLocker recovery key for a computer from Active Directory.

    .DESCRIPTION
        Given a computer name, this function queries Active Directory for the
        associated computer object and retrieves the BitLocker Recovery Password
        from the msFVE-RecoveryInformation object.

    .PARAMETER ComputerName
        The name of the computer to retrieve the BitLocker recovery key for.

    .EXAMPLE
        PS C:\> Get-ADRecoveryKey -ComputerName "MyComputer01"
        Returns the BitLocker recovery key for "MyComputer01" if it exists in AD.

    .NOTES
        Author:  David Tom (OTS)
        Brief:   Get the BitLocker recovery key for a computer from Active Directory.
        Contact: David.Tom@CSN.edu
        This function requires:
        - RSAT Tools
        - Active Directory module
    #>

    param (
        [string]$computerName
    )

    # Import the Active Directory module 
    Import-Module ActiveDirectory

    # Get the computer object from Active Directory
    $objComputer = Get-ADComputer -Identity $computerName

    # Retrieve BitLocker recovery information from the computer object
    $Bitlocker_Object = Get-ADObject -Filter {
        objectclass -eq 'msFVE-RecoveryInformation'
    } -SearchBase $objComputer.DistinguishedName -Properties 'msFVE-RecoveryPassword'

    # Display the BitLocker recovery key
    return $Bitlocker_Object.'msFVE-RecoveryPassword'
}

function Write-DeviceInformationHeader {
    <#
    .SYNOPSIS
        Obtains and outputs device & user information, then verifies Windows license.

    .DESCRIPTION
        This function retrieves and logs several pieces of device information:
        - Hostname
        - Serial Number
        - Asset Tag
        - Logged-In User
        - Windows Domain

        It also writes this data to a log file and the console. Finally, it calls 
        VerifyAndApplyWindowsLicense to ensure the system is using the correct 
        Windows Enterprise license.

    .PARAMETER None
        This function does not accept parameters.

    .EXAMPLE
        PS C:\> Write-DeviceInformationHeader
        Retrieves and displays the device information, logs it to the log file, 
        then applies the Windows Enterprise license if needed.

    .NOTES
        Author:  David Tom (OTS)
        Contact: David.Tom@CSN.edu
        Questions, comments, or concerns, please contact the author.
    #>

    # Function to get the serial number
    function Get-SerialNumber {
        # Deprecated: $serialNumber = (wmic bios get serialnumber | Select-Object -Skip 1 | Where-Object { $_ -ne "" }).Trim()
        $serialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
        return $serialNumber
    }

    # Function to get the hostname
    function Get-Hostname {
        $hostname = hostname
        return $hostname
    }

    # Function to get the asset tag
    function Get-AssetTag {
        $assetTag = (Get-WmiObject -Class Win32_SystemEnclosure | Select-Object -ExpandProperty SMBiosAssetTag).Trim()
        return $assetTag
    }

    # Function to get the currently logged-in user
    function Get-LoggedInUser {
        # Deprecated: # $loggedInUser = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName).Trim()
        $loggedInUser = whoami    
        return $loggedInUser
    }

    # Function to get the Active Directory domain
    function Get-ADDomain {
        $ADDomain = (Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty Domain).Trim()
        return $ADDomain
    }

    # Gather device information
    Write-Log -Message "Starting Write-DeviceInformationHeader function." -LogFilePath $logFile -Silent
    Write-Log -Message "============================== Device Information ==============================" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    $hostname = Get-Hostname
    Write-Log "Hostname: $hostname" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    $serialNumber = Get-SerialNumber
    Write-Log -Message "Serial Number: $serialNumber" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    $assetTag = Get-AssetTag
    Write-Log -Message "Asset Tag: $assetTag" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    $loggedInUser = Get-LoggedInUser
    Write-Log -Message "Logged-In User: $loggedInUser" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    $ADDomain = Get-ADDomain
    Write-Log -Message "Windows Domain: $ADDomain" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    # $recoveryKey = Get-ADRecoveryKey -computerName $hostname
    # Write-Log -Message "BitLocker Recovery Key: $recoveryKey" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    Write-Log "================================================================================" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    # Write Detailed Device Information
    Get-ComputerInfo | Select-Object CsSystemFamily, WindowsProductName, OsName, WindowsVersion, OsHardwareAbstractionLayer, WindowsRegisteredOrganization, WindowsRegisteredOwner

    # Log the detailed device information
    Write-Log -Message "Detailed Device Information:" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    # Collect computer info into an object.
    $computerInfo = Get-ComputerInfo |
        Select-Object CsSystemFamily, WindowsProductName, OsName, WindowsVersion,
                    OsHardwareAbstractionLayer, WindowsRegisteredOrganization,
                    WindowsRegisteredOwner

    # Format it to a string.
    $computerInfoString = $computerInfo | Format-List | Out-String

    # Write the computer info string to the log file.
    Write-Log -Message $computerInfoString -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    # Verify Windows License
    VerifyAndApplyWindowsLicense
    Write-Log -Message "Called VerifyAndApplyWindowsLicense function." -LogFilePath $logFile -Silent
}

function VerifyAndApplyWindowsLicense {
    <#
    .SYNOPSIS
        Verifies whether Windows OS is Enterprise or Pro & applies a license key.

    .DESCRIPTION
        Checks if the system runs Windows Enterprise. If not (i.e., Pro or other 
        editions), it applies the supplied (or default) Windows Enterprise key 
        and reboots.

    .PARAMETER LicenseKey
        An encoded license key for Windows 11 Enterprise. Defaults to a 
        known generic key if not supplied.

    .EXAMPLE
        PS C:\> VerifyAndApplyWindowsLicense
        Checks the current edition and, if required, applies the default 
        Enterprise key and restarts the machine.

    .NOTES
        Author:  David Tom (OTS)
        Brief:   Verifies Windows OS edition and applies license as needed.
        Contact: David.Tom@CSN.edu
        You can encode a key by running:
            [System.Convert]::ToBase64String(
                [System.Text.Encoding]::UTF8.GetBytes("YOUR-LICENSE-KEY")
            )
        You can decode a key by running:
            [System.Text.Encoding]::UTF8.GetString(
                [System.Convert]::FromBase64String("BASE64-STRING")
            )
    #>

    param(
        # Base64 Encoded License Key for Windows 11 Enterprise
        [string]$licenseKey = [System.Text.Encoding]::UTF8.GetString(
            [System.Convert]::FromBase64String("TlBQUjktRldEQ1gtRDJDOEotSDg3MkstMllUNDM=")
        )
    )

    Write-Log -Message "================================================================================" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    # Begin logging
    Write-Log -Message "Starting VerifyAndApplyWindowsLicense function." -LogFilePath $logFile -Silent

    # Get Windows OS Edition
    $windowsEdition = (Get-WmiObject -Query "SELECT * FROM Win32_OperatingSystem").Caption
    Write-Log -Message "Detected Windows Edition: $windowsEdition" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    # Check if Windows is Enterprise
    if ($windowsEdition -like "*Enterprise*") {
        Write-Log -Message "This IS Windows ENTERPRISE" -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    } elseif ($windowsEdition -like "*Pro*") {
    # Check if Windows is a Pro License and apply license, then reboot
        Write-Log -Message "This is Windows Pro -- NOT ENTERPRISE" -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black

        # Apply license, then reboot
        slmgr /ipk $licenseKey
        Write-Log -Message "Applied Enterprise license key successfully." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
        Write-Log -Message "Restarting in 10 seconds..." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
        Start-Sleep -Seconds 10
        Restart-Computer
    } else {
    # Apply license, then reboot
        Write-Log -Message "This is NOT Windows ENTERPRISE" -LogFilePath $logFile -ForegroundColor Red -BackgroundColor Black

        # Apply license, then reboot
        slmgr /ipk $licenseKey
        Write-Log -Message "Applied Enterprise license key successfully." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
        Write-Log -Message "Restarting in 10 seconds..." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
        Start-Sleep -Seconds 10
        Restart-Computer
    }

    # End logging
    Write-Log -Message "Completed VerifyAndApplyWindowsLicense function." -LogFilePath $logFile -Silent
}

function powerSettings {
    <#
    .SYNOPSIS
        Disables sleep and display timeout settings on both AC and DC power.

    .DESCRIPTION
        Sets the standby (sleep) and monitor (display) timeouts to zero,
        effectively disabling them. It applies to both AC (plugged in)
        and DC (battery) power modes.

    .PARAMETER None
        This function does not accept any parameters.

    .EXAMPLE
        PS C:\> powerSettings
        Disables sleep and display timeouts for AC and DC power.

    .NOTES
        Author:  David Tom (OTS)
        Contact: David.Tom@CSN.edu
        Brief:   Function will disable sleep and display timeout settings.
    #>

    # Disable sleep and display timeout when plugged in (AC power)
    powercfg /change standby-timeout-ac 0
    powercfg /change monitor-timeout-ac 0

    # Disable sleep and display timeout when on battery (DC power)
    powercfg /change standby-timeout-dc 0
    powercfg /change monitor-timeout-dc 0

    # Disable sleep and display timeout when on battery (DC power)
    Write-Log -Message "Sleep and display timeouts have been disabled." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black

    # Set the registry to allow remote desktop connections
    Write-Log -Message "Enabled Remote Desktop connections." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
}

function VerifyAndFlashAssetTag {
    <#
    .SYNOPSIS
        Identifies and verifies the device's Asset Tag, then optionally flashes it.

    .DESCRIPTION
        Checks the device model to see if it's supported (e.g., T14, X13, M90q).
        If the device is not supported (e.g., Yoga), it skips Asset Tag flashing.
        If the Asset Tag is invalid or missing, the function prompts the user
        to provide a new Asset Tag. It then copies the necessary asset-flashing
        utilities locally and executes them based on the detected model.
        
        It also disables Memory Integrity before flashing if necessary.

    .PARAMETER None
        This function does not accept parameters.

    .EXAMPLE
        PS C:\> VerifyAndFlashAssetTag
        Prompts the user to flash the asset tag if invalid or missing for supported
        models, then executes the flashing utilities.

    .NOTES
        Author: David Tom (OTS)
        Contact: David.Tom@CSN.edu
        Questions, comments, or concerns: Please reach out to the author.

        Currently supports:
            - T14
            - X13
            - M90q
    #>

    # Begin logging
    Write-Log -Message "Starting VerifyAndFlashAssetTag function." -LogFilePath $logFile -Silent

    # Function to check and disable Memory Integrity
    function DisableMemoryIntegrity {
        $hvciKeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\'
        $hvciEnabled = Get-ItemProperty -Path $hvciKeyPath -Name 'Enabled' -ErrorAction SilentlyContinue

        if ($hvciEnabled.Enabled -eq 1) {
            Write-Log -Message "Memory Integrity is currently ON. Disabling and restarting..." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black            
            Set-ItemProperty -Path $hvciKeyPath -Name 'Enabled' -Value 0 -Force

            Write-Log -Message "Computer will restart in 10 seconds..." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black
            Start-Sleep -Seconds (10)
            Restart-Computer
        } else {
            Write-Log -Message "Memory Integrity is already OFF." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
        }
    }

    # Obtains device information
    $modelName = (Get-ComputerInfo | Select-Object -ExpandProperty CsSystemFamily).Trim()
    Write-Log -Message "Device model name: $modelName" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    # Check if the device is a Yoga
    if ($modelName -like "*Yoga*" -or $modelName -like "*9[^0]+0*") {
        Write-Log -Message "Device is not currently supported.  Skipping asset tag flashing." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black
    } else {
        # Check if asset tag is missing or invalid
        if (-not $assetTag -or $assetTag -notmatch '^\d+$') {
            # Log that no valid asset tag is found
            Write-Log -Message "No valid Asset Tag found." -LogFilePath $logFile -ForegroundColor Red -BackgroundColor Black
            $tmpAnswer = Read-Host "Error: No valid Asset Tag found... Would you like to flash the asset tag now? (Y for yes, N for no)"
            
            # Convert user input to upper
            if ($tmpAnswer.ToUpper() -eq 'Y') {
                # Obtain a valid AssetTag
                $tmpAsset = Read-Host "Enter an asset tag for the device"
                Write-Log -Message "User chose to flash asset tag with value: $tmpAsset" -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black

                # Verify if device is a laptop
                if ($modelName -like "*ThinkPad*" -or $modelName -like "*T14*" -or $modelName -like "*X13*") {
                    $sourcePath = "\\cyapsft01\software\Lenovo\Laptops\"
                    Copy-Item -Recurse -Path $sourcePath -Destination "C:\"
                    Write-Log -Message "Copied files from $sourcePath to C:\" -LogFilePath $logFile -Silent
                    
                    # Run the Asset Tag Flashing program
                    & "C:\Laptops\WinAIA.exe" -set "USERASSETDATA.ASSET_NUMBER=$tmpAsset"
                    Write-Log -Message "Flashed asset tag on laptop with WinAIA.exe" -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
                }
                elseif ($modelName -like "*90q*") {
                    $sourcePath = "\\cyapsft01\software\ASSETTAG\LENOVO\M90\"
                    Copy-Item -Recurse -Path $sourcePath -Destination "C:\"
                    Write-Log -Message "Copied files from $sourcePath to C:\" -LogFilePath $logFile -Silent

                    # Run the Asset Tag Flashing program
                    & "C:\M90\AMIDEWIN.exe" /CA $tmpAsset
                    Write-Log -Message "Flashed asset tag on laptop with AMIDEWIN.exe" -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
                }
                elseif ($modelName -like "*ThinkCentre*") {
                    # Verify if device is a desktop
                    $model = $modelName -replace "ThinkCentre ", "" -replace "[a-zA-Z]+$", ""
                    $sourcePath = "\\cyapsft01\software\ASSETTAG\LENOVO\$model\"
                    Copy-Item -Recurse -Path $sourcePath -Destination "C:\LENOVO\$model\"
                    Write-Log -Message "Copied files from $sourcePath to C:\LENOVO\$model\" -LogFilePath $logFile -Silent
                    
                    # Run the Asset Tag Flashing program
                    & "C:\LENOVO\$model\wflash2.exe" -set "/tag:$tmpAsset"
                    Write-Log -Message "Flashed asset tag on desktop with wflash2.exe" -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
                }
                else {
                    # Log that the model is invalid
                    Write-Log -Message "Invalid Model: $modelName." -LogFilePath $logFile -ForegroundColor Red -BackgroundColor Black
                    return
                }
            } else {
                # Log that the user chose not to flash the asset tag
                Write-Log -Message "Continuing with program without changing Asset Tag..." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black
            }
        } else {
            # Log that a valid asset tag is found
            Write-Log -Message "Valid asset tag found: $assetTag" -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
        }
    }

    # End logging
    Write-Log -Message "================================================================================" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black
    Write-Log -Message "Completed VerifyAndFlashAssetTag function." -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black
}

# Format for PS7
function RegistryKeyModifications {
    <#
    .SYNOPSIS
        Modifies registry keys based on entries in a global array.

    .DESCRIPTION
        Iterates through a global array ($registryModifications) containing 
        registry paths, property names, and values to be applied. For each 
        valid registry path, updates the specified key with the specified value.
        If the path does not exist or cannot be modified, it logs an error.

    .PARAMETER None
        This function does not accept any parameters directly.

    .EXAMPLE
        PS C:\> RegistryKeyModifications
        Modifies registry keys as specified in $registryModifications.

    .NOTES
        Author:  David Tom (OTS)
        Contact: David.Tom@CSN.edu
        Dependencies: 
        - $registryModifications must be defined as an array of objects 
            with the properties Path, Name, and Value.
    #>

    # Begin logging
    Write-Log -Message "Starting RegistryKeyModifications function." -LogFilePath $logFile -Silent

    # Define the PowerShell Version
    $psVersion = $PSVersionTable.PSVersion.Major

    # # Verify version and run appropriate for-loop
    # if ($psVersion -lt 6) {
    #     # For PowerShell 5.1 and below: Use the standard ForEach-Object loop

        # Loop through the registry array and modify the keys
        foreach ($modification in $registryModifications) {
            if (Test-Path $modification.Path) {
                try {
                    Set-ItemProperty -Path $modification.Path -Name $modification.Name -Value $modification.Value -Force | Out-Null
                    Write-Log -Message "Modified registry key '$($modification.Name)' at '$($modification.Path)' with value '$($modification.Value)'" -LogFilePath $logFile -Silent
                } catch {
                    Write-Log -Message "Error modifying registry key '$($modification.Name)' at '$($modification.Path)': $_" -LogFilePath $logFile -ForegroundColor Red -BackgroundColor Black
                }
            } else {
                Write-Log -Message "Registry path does not exist: '$($modification.Path)'. Cannot modify key '$($modification.Name)'." -LogFilePath $logFile -ForegroundColor Red -BackgroundColor Black
            }
        }
    # } else {
    #     # For PowerShell 7 and above: Use the ForEach-Object -Parallel loop
    #     $registryModifications |
    #         ForEach-Object -Parallel {
    #             # In this scenario, $_ is just the registry path string
    #             $regPath = $_

    #             if (Test-Path $regPath) {
    #                 try {
    #                     # Suppose we hardcode 'Name' and 'Value' for all items
    #                     Set-ItemProperty -Path $regPath -Name 'MyValueName' -Value 1 -Force | Out-Null
    #                     Write-Log -Message "Modified registry path '$regPath'." -LogFilePath $using:logFile -ForegroundColor Green -BackgroundColor Black
    #                 }
    #                 catch {
    #                     Write-Log -Message "Error modifying registry path '$regPath': $_" -LogFilePath $using:logFile -ForegroundColor Red -BackgroundColor Black
    #                 }
    #             }
    #             else {
    #                 Write-Log -Message "Registry path does not exist: '$regPath'." -LogFilePath $using:logFile -ForegroundColor Red -BackgroundColor Black
    #             }
    #         } -ThrottleLimit 4
    # }

    Write-Log -Message "===============================================================================" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black
    
    # End logging
    Write-Log -Message "Completed RegistryKeyModifications function." -LogFilePath $logFile -Silent
}

function VerifyInstalledApps {
    <#
    .SYNOPSIS
        Verifies that specified applications are installed.

    .DESCRIPTION
        Reads installed application names from the Windows registry (both 32-bit 
        and 64-bit uninstall paths). Compares them against a user-supplied 
        parameter ($appArray). Logs the result for each application (installed 
        or missing).

    .PARAMETER appArray
        An array of application names (strings) to check for installation.

    .EXAMPLE
        PS C:\> VerifyInstalledApps -appArray @("Google Chrome", "Microsoft Edge")
        Checks if "Google Chrome" and "Microsoft Edge" are installed, logging
        whether each one was found.

    .NOTES
        Author:  David Tom (OTS)
        Contact: David.Tom@CSN.edu
        Throws no error if an application is not installed; only logs a warning.
    #>

    param (
        [Parameter(Mandatory=$true)]
        [string[]]$appArray
    )

    # Begin logging
    Write-Log -Message "Starting VerifyInstalledApps function." -LogFilePath $logFile -Silent

    # Get a list of installed applications from the registry
    $installedApps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                       HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* `
                      | Where-Object { $_.DisplayName -ne $null } `
                      | Select-Object DisplayName

    # Print all discovered application names for debugging
    Write-Log -Message "Installed Applications:" -LogFilePath $logFile -Silent
    # $installedApps | ForEach-Object { Write-Host $_.DisplayName }

    # Define the PowerShell Version
    $psVersion = $PSVersionTable.PSVersion.Major

    # Verify version and run appropriate for-loop
    if ($psVersion -lt 6) {
        # For PowerShell 5.1 and below: Use the standard ForEach-Object loop
        foreach ($app in $appArray) {
            $appFound = $installedApps | Where-Object { $_.DisplayName -like "*$app*" }

            if ($appFound) {
                Write-Log -Message "Success: $app is installed on the device..." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
            } else {
                Write-Log -Message "WARNING: $app cannot be found!" -LogFilePath $logFile -ForegroundColor Red -BackgroundColor Black
            }
        }
    } else {
        # For PowerShell 7 and above: Use the ForEach-Object -Parallel loop
        $appArray |
            ForEach-Object -Parallel {
                $app = $_
                $appFound = $using:installedApps | Where-Object { $_.DisplayName -like "*$app*" }

                if ($appFound) {
                    Write-Log -Message "Success: $app is installed on the device..." -LogFilePath $using:logFile -ForegroundColor Green -BackgroundColor Black
                } else {
                    Write-Log -Message "WARNING: $app cannot be found!" -LogFilePath $using:logFile -ForegroundColor Red -BackgroundColor Black
                }
            } -ThrottleLimit 4
    }

    Write-Log -Message "================================================================================" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    # End logging
    Write-Log -Message "Completed VerifyInstalledApps function." -LogFilePath $logFile -Silent
}

function VerifyLargerApps {
    <#
    .SYNOPSIS
        Attempts to load larger applications (e.g., major software) for manual checks.

    .DESCRIPTION
        Iterates over a global array ($majorArray), attempting to launch each 
        specified application via Start-Process. Logs whether each application 
        was launched successfully or not found.

    .PARAMETER None
        This function does not accept parameters directly.

    .EXAMPLE
        PS C:\> VerifyLargerApps
        Launches each application path specified in $majorArray, logging success or failure.

    .NOTES
        Author:  David Tom (OTS)
        Contact: David.Tom@CSN.edu
        Requires: 
        - A global array variable $majorArray defined with paths to applications.
    #>

    # Begin logging
    Write-Log -Message "Starting VerifyLargerApps function." -LogFilePath $logFile -Silent

    # Define the PowerShell Version
    $psVersion = $PSVersionTable.PSVersion.Major

    # Verify version and run appropriate for-loop
    if ($psVersion -lt 6) {
        # For PowerShell 5.1 and below: Use the standard ForEach-Object loop
        foreach ($node in $majorArray) {
            if (Test-Path $node) {
                try {
                    Start-Process -FilePath $node
                    Write-Log -Message "[$node] is attempting to load..." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
                } catch {
                    Write-Log -Message "Error: Issue found with loading [$node]! Error: $_" -LogFilePath $logFile -ForegroundColor Red -BackgroundColor Black
                }
            } else {
                Write-Log -Message "Failure - [$node] was not found!" -LogFilePath $logFile -Silent
            }
        }
    } else {
        # For PowerShell 7 and above: Use the ForEach-Object -Parallel loop
        $majorArray |
            ForEach-Object -Parallel {
                $node = $_
                if (Test-Path $node) {
                    try {
                        Start-Process -FilePath $node
                        Write-Log -Message "[$node] is attempting to load..." -LogFilePath $using:logFile -ForegroundColor Green -BackgroundColor Black
                    } catch {
                        Write-Log -Message "Error: Issue found with loading [$node]! Error: $_" -LogFilePath $using:logFile -ForegroundColor Red -BackgroundColor Black
                    }
                } else {
                    Write-Log -Message "Failure - [$node] was not found!" -LogFilePath $using:logFile -Silent
                }
            } -ThrottleLimit 4
    }

    # End logging
    Write-Log -Message "Completed VerifyLargerApps function." -LogFilePath $logFile -Silent
}

function VerifyBrowserVersions {
    <#
    .SYNOPSIS
        Launches each browser in an array for manual version checks or updates.

    .DESCRIPTION
        References a global array ($browserArray) that contains paths to different
        browsers (e.g., Chrome, Edge, Firefox). For each path, attempts to start 
        the browser process, writing success or failure to the log file.

    .PARAMETER None
        This function does not accept parameters directly.

    .EXAMPLE
        PS C:\> VerifyBrowserVersions
        Loads each browser listed in $browserArray, allowing the user to manually 
        verify or update the browser versions.

    .NOTES
        Author:  David Tom (OTS)
        Contact: David.Tom@CSN.edu
        Requires:
        - A global array variable $browserArray, containing paths to browser executables.
    #>

    # Begin logging
    Write-Log -Message "Starting VerifyBrowserVersions function." -LogFilePath $logFile -Silent
    
    # Define the PowerShell Version
    $psVersion = $PSVersionTable.PSVersion.Major

    # Verify version and run appropriate for-loop
    if ($psVersion -lt 6) {
        # For PowerShell 5.1 and below: Use the standard ForEach-Object loop
        foreach ($node in $browserArray) {
            if (Test-Path $node) {
                Start-Process -FilePath $node
                Write-Log -Message "$node is attempting to load..." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
            } else {
                Write-Log -Message "Failure - $node was not found!" -LogFilePath $logFile -ForegroundColor Red -BackgroundColor Black
            }
        }
    } else {
        # For PowerShell 7 and above: Use the ForEach-Object -Parallel loop
        $browserArray |
            ForEach-Object -Parallel {
                $node = $_
                if (Test-Path $node) {
                    Start-Process -FilePath $node
                    Write-Log -Message "$node is attempting to load..." -LogFilePath $using:logFile -ForegroundColor Green -BackgroundColor Black
                } else {
                    Write-Log -Message "Failure - $node was not found!" -LogFilePath $using:logFile -ForegroundColor Red -BackgroundColor Black
                }
            } -ThrottleLimit 4
    }

    Write-Log -Message "================================================================================" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    # End logging
    Write-Log -Message "Completed VerifyBrowserVersions function." -LogFilePath $logFile -Silent
}

function sccmModifications {
    <#
    .SYNOPSIS
        Loads SCCM Actions from Control Panel and triggers them via WMI.

    .DESCRIPTION
        Opens the SCCM Control Panel (via `control smscfgrc`) to allow the user to manually verify 
        that all SCCM Actions are available. Then, for each action specified in the global 
        `$SCCMActions` array, the function attempts to trigger the corresponding SCCM client action 
        using WMI methods. Any action that fails to run is logged, and the user must manually 
        invoke any actions that did not succeed.

    .PARAMETER None
        This function does not accept any parameters.

    .EXAMPLE
        PS C:\> sccmModifications
        Opens the SCCM Control Panel and iterates through `$SCCMActions`, invoking each action.

    .NOTES
        Author:  David Tom (OTS)
        Contact: David.Tom@CSN.edu
        Dependencies:
        - A global array `$SCCMActions` that contains the schedule IDs or action parameters for SCCM.
        - SCCM client must be installed and accessible via the `root\ccm` namespace.
        Attribution:
        - https://www.anoopcnair.com/trigger-sccm-client-agent-actions-powershell/
    #>

    # Begin logging
    Write-Log -Message "Starting sccmModifications function." -LogFilePath $logFile -Silent
    Write-Log -Message "Manually run User Policy Retrieval & Evaluation Cycle AND Visually inspect all the SCCM Actions are available..." -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black
    control smscfgrc

    # SCCM Actions Automation
    foreach ($action in $SCCMActions) {
        try {
            # Write-Host "Invoking SCCM Action: $action"
            Invoke-WmiMethod -Namespace "root\ccm" -Class "SMS_Client" -Name "TriggerSchedule" -ArgumentList $action
            $result = Invoke-WmiMethod -Namespace "root\ccm" -Class "SMS_Client" -Name "TriggerSchedule" -ArgumentList $action

            # Check the return value and output the result
            if ($result) {
                Write-Log -Message "SCCM Action $action invoked successfully." -LogFilePath $logFile -Silent
            } else {
                Write-Log -Message "SCCM Action $action returned a non-success status: $($result.ReturnValue)" -LogFilePath $logFile -ForegroundColor Red -BackgroundColor Black
            }
        } catch {
            Write-Log -Message "Error: $action could not be run! Error: $_" -LogFilePath $logFile -ForegroundColor Red -BackgroundColor Black
        }
    }

    # End logging
    Write-Log -Message "Completed sccmModifications function." -LogFilePath $logFile -Silent
}

# Format for PS7
function WindowsUpdaterPowerShell {
    <#
    .SYNOPSIS
        Loads and installs available Windows Updates using PSWindowsUpdate and winget.

    .DESCRIPTION
        Checks and installs dependencies (NuGet and PSWindowsUpdate module) required 
        for Windows Updates. It then imports the PSWindowsUpdate module, retrieves a list 
        of available updates, logs details for each update, and downloads updates in parallel 
        (for PowerShell 7+). After installing updates individually (skipping updates that 
        match specific titles), the function invokes a separate winget updater to upgrade applications.

    .PARAMETER None
        This function does not accept any parameters.

    .EXAMPLE
        PS C:\> WindowsUpdaterPowerShell
        Checks for, downloads, and installs available Windows updates and then runs wingetUpdater 
        to update applications.

    .NOTES
        Author:  David Tom (OTS)
        Contact: David.Tom@CSN.edu
        Dependencies:
        - PSWindowsUpdate module (installed if missing).
        - NuGet package provider.
        - A global variable `$wingetArrray` containing winget application IDs.
        - The function `wingetUpdater` must be defined in the session.
    #>

    # Begin logging
    Write-Log -Message "Starting WindowsUpdaterPowerShell function." -LogFilePath $logFile -Silent
    Write-Log -Message "Verifying and Installing Windows Updates..." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black

    # Install Dependencies
    # Check if NuGet package provider (>= 2.8.5.201) is installed
    $nugetProvider = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue -Force
    if (
        -not $nugetProvider -or
        $nugetProvider.Version -lt [Version]'2.8.5.201'
    ) {
        Write-Log -Message "NuGet package provider not found or too old. Installing..." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -ForceBootstrap -Force -Confirm:$false | Out-Null
        Write-Log -Message "Installed NuGet package provider." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    } else {
        Write-Log -Message "NuGet package provider is already installed and up to date." -LogFilePath $logFile -Silent
    }

    # Check if PSWindowsUpdate is installed
    if (-not (Get-Module PSWindowsUpdate -ListAvailable)) {
        Write-Log -Message "PSWindowsUpdate module not found. Installing..." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black
        Install-Module -Name PSWindowsUpdate -Force -Confirm:$false | Out-Null
        Write-Log -Message "Installed PSWindowsUpdate module." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    } else {
        Write-Log -Message "PSWindowsUpdate module already installed." -LogFilePath $logFile -Silent
    }

    # Import PSWindowsUpdate
    Import-Module PSWindowsUpdate 
    Write-Log -Message "PSWindowsUpdate module imported successfully." -LogFilePath $logFile -Silent

    # Check for Windows Updates
    Write-Log -Message "Checking for Windows Updates..." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black
    $updates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot
    Write-Log -Message "Found $($updates.Count) available updates." -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black
    
    # Log the available updates
    Write-Log -Message "List of available Windows Updates:" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black
    foreach ($update in $updates) {
        Write-Log -Message "Title: $($update.Title), KB: $($update.KBArticleID), Size: $([math]::Round($update.Size/1MB, 2)) MB" -LogFilePath $logFile -ForegroundColor Cyan -BackgroundColor Black
    }

    # Define the PowerShell Version
    $psVersion = $PSVersionTable.PSVersion.Major
    
    # Verify version and run appropriate for-loop
    if ($psVersion -gt 6) {
        # For PowerShell 7 and above: Use the ForEach-Object -Parallel loop
        Write-Log -Message "Starting parallel download of updates..." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black

        $updates | ForEach-Object -Parallel {
            Import-Module PSWindowsUpdate
            if ($_.Title -notmatch 'Windows 11, version 24H*') {
                Write-Log -Message "Downloading: $($_.Title)" -LogFilePath $using:logFile -ForegroundColor Cyan -BackgroundColor Black
                Download-WindowsUpdate -KBArticleID $($_.KBArticleID) -AcceptAll -IgnoreReboot -Confirm:$false
            } else {
                Write-Log -Message "Skipping download for: $($_.Title)" -LogFilePath $using:logFile -ForegroundColor Yellow -BackgroundColor Black
            }
        } -ThrottleLimit 5

        Write-Log -Message "Parallel downloads complete." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    }

    # Install updates individually based on their title
    if ($updates.Count -gt 0) {
        Write-Log -Message "Installing Windows Updates individually..." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black
        foreach ($update in $updates) {
            # Example: Skip updates with a title matching 'Windows 11, version 24H*'
            if ($_.Title -notmatch 'Windows 11, version 24H*') {
                Write-Log -Message "Installing update: $($update.Title)" -LogFilePath $logFile -ForegroundColor Cyan -BackgroundColor Black
                Install-WindowsUpdate -KBArticleID $update.KBArticleID -AcceptAll -IgnoreReboot -NotTitle 'Windows 11, version 24H*' -Confirm:$false
            } else {
                Write-Log -Message "Skipping update: $($update.Title)" -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black
            }
        }

        # Log the completion of updates
        Write-Log -Message "All Windows Updates installation tasks are completed." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    } else {
        Write-Log -Message "No updates available." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    }

    # # Install any available updates excluding Windows 11, 24H2
    # if ($updates.Count -gt 0) {
    #     Write-Host "Installing Windows Updates..." -ForegroundColor Yellow
    #     # Runs updater to install all available Windows updates
    #     Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -NotTitle 'Windows 11, version 24H*' -Confirm:$false | Out-Null  # -AutoReboot
    #     Write-Host "All Windows Updates are completed." -ForegroundColor Green
    #     "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Successfully installed Windows Updates." | Out-File -FilePath $logFile -Append
    #     Write-Host "================================================================================"
    # } else {
    #     Write-Host "No updates available." -ForegroundColor Green
    #     "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] No updates available." | Out-File -FilePath $logFile -Append
    # }

    # Runs winget updater to install all available updates
    wingetUpdater

    # End logging
    Write-Log -Message "Completed WindowsUpdaterPowerShell function." -LogFilePath $logFile -Silent
}

# Format for PS7
function wingetUpdater {
    <#
    .SYNOPSIS
        Uses winget to update available applications.

    .DESCRIPTION
        Checks if WinGet (Microsoft Desktop App Installer) is installed. If not, it downloads 
        and installs WinGet and its dependencies. It then resets and updates winget sources, 
        logs available application upgrades, and upgrades applications specified in a global 
        array (`$wingetArrray`). The function supports both serial and parallel processing 
        based on the PowerShell version.

    .PARAMETER None
        This function does not accept any parameters.

    .EXAMPLE
        PS C:\> wingetUpdater
        Checks for WinGet installation, updates dependencies, and upgrades all available 
        applications via winget.

    .NOTES
        Author:  David Tom (OTS)
        Contact: David.Tom@CSN.edu
        Dependencies:
        - Winget must be supported on the system.
        - `$wingetArrray` must be defined as an array of application IDs for upgrades.
        - PowerShell 7+ will process the winget upgrades in parallel.
    #>

    # Begin logging
    Write-Log -Message "Starting wingetUpdater function." -LogFilePath $logFile -Silent
    Write-Log -Message "================================================================================" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black
    Write-Log -Message "Running winget to update available applications..." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black
    Write-Log -Message "Verifying WinGet and its dependencies..." -LogFilePath $logFile -Silent

    $loggedInUser = whoami

    # Check if winget (Microsoft.DesktopAppInstaller) is installed for any user:
    if (-not (Get-AppxPackage -Name "Microsoft.DesktopAppInstaller" -AllUsers)) {
        Write-Log -Message "WinGet not installed. Installing now..." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black

        # Download dependencies and winget
        Invoke-WebRequest -Uri https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx `
                        -OutFile Microsoft.VCLibs.x64.14.00.Desktop.appx -UseBasicParsing
        Invoke-WebRequest -Uri https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx `
                        -OutFile Microsoft.UI.Xaml.2.8.x64.appx -UseBasicParsing
        Invoke-WebRequest -Uri https://aka.ms/getwinget `
                        -OutFile Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle -UseBasicParsing

        # Install dependencies and winget
        Add-AppxPackage -Path .\Microsoft.VCLibs.x64.14.00.Desktop.appx -ErrorAction SilentlyContinue | Out-Null
        Add-AppxPackage -Path .\Microsoft.UI.Xaml.2.8.x64.appx -ErrorAction SilentlyContinue | Out-Null
        Add-AppxPackage -Path .\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle -ErrorAction SilentlyContinue | Out-Null

        Write-Log -Message "WinGet and its dependencies have been installed." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    } else {
        Write-Log -Message "WinGet is already installed." -LogFilePath $logFile -Silent
    }

    # Log the output
    Write-Log -Message "Successfully verified WinGet and dependencies." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black

    # Update winget respositories
    winget source reset --force
    winget source update

    # Obtain a list of the available upgrades
    Write-Log -Message "Checking for available upgrades..." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black
    $upgradeListOutput = winget upgrade --silent --accept-source-agreements --accept-package-agreements --disable-interactivity | Out-String
    
    # Log the available upgrades
    Write-Log -Message "Applications available for upgrade via winget: " -LogFilePath $logFile -Silent
    $upgradeListOutput | Out-File -FilePath $logFile -Append

    # Run winget to upgrade all available updates
    # Use the command `winget upgrade --uninstall-previous` to uninstall the previous version regardless of what is in the package manifest1.
    # if ($LoggedInUser -eq "csn\david.tom") {
    #         $wingetOutput = winget upgrade --all --silent --accept-source-agreements --accept-package-agreements --disable-interactivity | Out-String
            
    #         # Log the output
    #         "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Winget upgrade output:" | Out-File -FilePath $logFile -Append
    #         $wingetOutput | Out-File -FilePath $logFile -Append
            
    #         "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Upgraded all applications using winget." | Out-File -FilePath $logFile -Append
    # } else {      

    $psVersion = $PSVersionTable.PSVersion.Major

    # Verify version and run appropriate for-loop
    if ($psVersion -lt 6) {
        foreach ($app in $wingetArrray) {
            Write-Log -Message "Updating: $app" -LogFilePath $logFile -Silent
            # Run winget to upgrade the applications in array
            $wingetOutput = winget upgrade --id $app --silent --accept-source-agreements --accept-package-agreements --disable-interactivity | Out-String
            Write-Log -Message "Successfully upgraded $app using winget." -LogFilePath $logFile -Silent
        }
    } else {
        $wingetArrray | ForEach-Object -Parallel {
            $app = $_
            Write-Log -Message "Updating: $app" -LogFilePath $using:logFile -Silent
            # Run winget to upgrade the application
            $wingetOutput = winget upgrade --id $app --silent --accept-source-agreements --accept-package-agreements --disable-interactivity | Out-String
            Write-Log -Message "Successfully upgraded $app using winget." -LogFilePath $using:logFile -ForegroundColor Cyan -BackgroundColor Black
        } -ThrottleLimit 4
    }

    Write-Log -Message "All applications have been upgraded." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    Write-Log -Message "================================================================================" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    # End logging
    Write-Log -Message "Completed wingetUpdater function." -LogFilePath $logFile -Silent
}

function VerifyClassicNewTeams {
    <#
    .SYNOPSIS
        Compares the installed Microsoft Teams version and updates Teams as needed.

    .DESCRIPTION
        Checks for the presence of Classic Teams by searching the winget list for the keyword "Classic".  
        If Classic Teams is detected, it stops any running Teams process and uninstalls Classic Teams via winget.  
        Then, it retrieves the installation location and version of the new Teams app, and compares it against  
        a specified target version. If the installed version is lower than the target version, it attempts to  
        install or update Microsoft Teams to the latest version.

    .PARAMETER None
        This function does not require any parameters.

    .EXAMPLE
        PS C:\> VerifyClassicNewTeams
        Checks for Classic Teams and updates Microsoft Teams as necessary.

    .NOTES
        Author:  David Tom (OTS)
        Contact: David.Tom@CSN.edu
        Dependencies:
        - winget must be available for uninstalling Classic Teams and for installing/updating Teams.
        - The function uses Get-AppxPackage and a custom Get-AppPackage (or MSTeams) method to retrieve version information.
    #>

    # Begin logging
    Write-Log -Message "Starting VerifyClassicNewTeams function." -LogFilePath $logFile -Silent

    $versionToCompare = '24000.0.0' # Replace with the version you want to compare
    $teamsPath = Get-AppxPackage -Name 'Microsoft.Teams' | Select-Object -ExpandProperty InstallLocation
    $teamsVersion = (Get-AppPackage MSTeams).Version

    Write-Log -Message "Verifying Microsoft Teams Version..." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black

    # Check if Classic Teams is installed
    try {
        $classicInstalled = winget list | Select-String -Pattern "Classic"
    } catch {
        $classicInstalled = $false
        Write-Log -Message "Error checking for Classic Teams installation: $_" -LogFilePath $logFile -ForegroundColor Red -BackgroundColor Black
    }

    # Stop and Uninstall Classic Teams
    if ($classicInstalled) {
        try {
            Get-Process "Teams" -ErrorAction SilentlyContinue | Stop-Process
            winget Uninstall --silent --accept-source-agreements --all-versions --id Microsoft.Teams.Classic
            Write-Log -Message "Uninstalled Classic Teams." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
        } catch {
            Write-Log -Message "Error uninstalling Classic Teams: $_" -LogFilePath $logFile -ForegroundColor Red -BackgroundColor Black
        }
    } else {
        Write-Log -Message "Classic Teams is not installed on the device!" -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    }

    # Compare New Teams Version
    try {
        if ([version]$teamsVersion -gt [version]$versionToCompare) {
            Write-Log -Message "New Teams version is greater than $versionToCompare!" -LogFilePath $logFile -Silent
        } else {
            try {
                # Install and load the newest version of Microsoft Teams
                winget Install --silent --accept-source-agreements --id Microsoft.Teams
                Start-Process -File "$($env:USERProfile)\AppData\Local\Microsoft\Teams\Update.exe" -ArgumentList '--processStart "Teams.exe"'
                Write-Log -Message "Microsoft Teams has been updated to the latest version." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
            } catch {
                Write-Log -Message "Error installing/updating Microsoft Teams: $_" -LogFilePath $logFile -ForegroundColor Red -BackgroundColor Black
            }
        }
    } catch {
        Write-Log -Message "Error installing/updating Microsoft Teams: $_" -LogFilePath $logFile -ForegroundColor Red -BackgroundColor Black
    }

    Write-Log -Message "================================================================================" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    # End logging
    Write-Log -Message "Completed VerifyClassicNewTeams function." -LogFilePath $logFile -Silent
}

function LenovoSystemUpdateToVantage {
    <#
    .SYNOPSIS
        Installs Lenovo System Update or Lenovo Vantage based on the device model.

    .DESCRIPTION
        Determines the device model using Get-ComputerInfo and selects the appropriate update tool.  
        For models such as ThinkBook, specific 9*0, Idea, V1, or Yoga devices, it uninstalls Lenovo Commercial Vantage  
        and installs Lenovo Vantage, then launches it. For other models, it checks for the Lenovo Vantage Service;  
        if not installed, it installs it from a network share and then launches the corresponding Lenovo companion app.  
        Actions are logged throughout the process.

    .PARAMETER None
        This function does not require any parameters.

    .EXAMPLE
        PS C:\> LenovoSystemUpdateToVantage
        Installs and launches Lenovo Vantage or the Commercial Vantage variant based on device model.

    .NOTES
        Author:  David Tom (OTS)
        Contact: David.Tom@CSN.edu
        Dependencies:
        - winget must be available for uninstalling/installing applications.
        - The script assumes that a network share (J: drive) is accessible for installation.
    #>

    # Obtain Model Name
    $modelName = (Get-ComputerInfo | Select-Object -ExpandProperty CsSystemFamily).Trim()
    
    if ($modelName -like "*ThinkBook*" -or $modelName -like "*Tablet*" -or $modelName -like "*9[^0]+0*" -or $modelName -like "*Idea*" -or $modelName -like "*V1*" -or $modelName -like "*Yoga*") {
        # Uninstall Lenovo Commercial Vantage
        Write-Log -Message "Uninstalling Lenovo Commercial Vantage..." -LogFilePath $logFile -Silent
        winget uninstall --silent --accept-source-agreements --id 9NR5B8GVVM13
        Write-Log -Message "Uninstalled Lenovo Commercial Vantage." -LogFilePath $logFile -Silent

        # Install Lenovo Vantage
        winget install --silent --accept-source-agreements --accept-package-agreements --id 9WZDNCRFJ4MV
        # Start-Process "shell:AppsFolder\E046963F.LenovoCompanion_k1h2ywk1493x8!App"
        Write-Log -Message "Installed Lenovo Vantage." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    } else {
        # Lenovo Commercial Vantage via network drive
        $registryPath = 'HKLM:\SOFTWARE\Lenovo\VantageService'

        if (Test-Path $registryPath) {
            Write-Log "Lenovo Vantage Service is installed!" -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
        } else {
            Write-Log "Lenovo Vantage Service is NOT installed. Installing via the J: Drive..." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black
            Start-Process -FilePath '\\cyapsft01\software\Vantage\setup-commercial-vantage.bat' -Verb RunAs -NoNewWindow
        }

        # Uninstall Lenovo Vantage
        winget uninstall --silent --accept-source-agreements --id 9WZDNCRFJ4MV
        Write-Log -Message "Uninstalled Lenovo Vantage." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    }

    # Uninstall Lenovo System Update
    # Write-Host "Uninstalling Lenovo System Update..." -ForegroundColor Yellow
    # winget uninstall --silent --accept-source-agreements --id Lenovo.SystemUpdate
    # "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Uninstalled Lenovo System Update." | Out-File -FilePath $logFile -Append
}

# Format for PS7
function RemoveBloat {
    <#
    .SYNOPSIS
        Removes bloatware and unnecessary applications from the device.

    .DESCRIPTION
        Uninstalls various applications including Mozilla Firefox, VLC Media Player, 7zip (if on OS 24H2),  
        Microsoft Copilot, Microsoft 365 Copilot, and Microsoft Cortana using winget and direct uninstallers.  
        Additionally, it removes user-installed and provisioned bloatware packages specified in a global array  
        ($bloatware). Each removal action is logged and feedback is provided to the user via console messages.

    .PARAMETER None
        This function does not require any parameters.

    .EXAMPLE
        PS C:\> RemoveBloat
        Uninstalls bloatware applications from the device and logs the actions taken.

    .NOTES
        Author:  David Tom (OTS)
        Contact: David.Tom@CSN.edu
        Dependencies:
        - The global variable $bloatware must be defined as an array of application package names.
        - winget must be available for uninstallation of certain apps.
    #>

    # Begin logging
    Write-Log -Message "Starting removeBloat function." -LogFilePath $logFile -Silent
    Write-Log -Message "================================================================================" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black
    Write-Log -Message "Removing bloatware... Please wait..." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black


    # How to find software to uninstall
    # Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" , "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" `
    # | Where-Object { $_.DisplayName -match "Carbon Black" } `
    # | Select-Object DisplayName, UninstallString
    # Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Carbon*" } | ForEach-Object { Start-Process msiexec.exe -ArgumentList "/x $($_.IdentifyingNumber) /qn /norestart" -Wait -NoNewWindow }

    # Uninstall Outdated Adobe products and Carbon Black
    Start-Process msiexec.exe -ArgumentList "/x {4487064C-F31E-4499-A1EF-9B8E809A0358} /qn /norestart" -Wait -NoNewWindow
    Start-Process msiexec.exe -ArgumentList "/x {B373E236-B88C-48E0-96F2-D0E6FEEBB55F} /qn /norestart" -Wait -NoNewWindow
    Start-Process msiexec.exe -ArgumentList "/x {E3ECA138-7EB5-417C-91CC-5C50E6F39F90} /qn /norestart" -Wait -NoNewWindow
    Start-Process msiexec.exe -ArgumentList "/x {F681BDD7-A359-492D-B7B6-FEED028826E8} /qn /norestart" -Wait -NoNewWindow
    Start-Process msiexec.exe -ArgumentList "/x {10E33ABF-D7FB-4F47-900A-7973854AB45A} /qn /norestart" -Wait -NoNewWindow
    Write-Log -Message "Uninstalled outdated Adobe products." -LogFilePath $logFile -Silent
    if (Test-Path "C:\Windows\CarbonBlack\uninst.exe") {  
        Start-Process -FilePath "C:\Windows\CarbonBlack\uninst.exe" -ArgumentList "/S" -Wait -NoNewWindow -Verb RunAs
        Write-Log -Message "Uninstalled Carbon Black." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    }

    $filePath = "C:\Program Files\Mozilla Firefox\uninstall\helper.exe"

    # Check if the file exists
    if (Test-Path -Path $filePath) {
        # If it exists, run it with the /S (silent) argument
        Start-Process -FilePath $filePath -ArgumentList "/S" -Verb RunAs
        Write-Log -Message "Mozilla Firefox has been uninstalled." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    } else {
        Write-Log -Message "Firefox is not installed on the device." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    }

    # Remove VLC Media Player
    $filePath = "C:\Program Files\VideoLAN\VLC\uninstall.exe"

    if (Test-Path -Path $filePath) {
        # & $filePath /S
        Start-Process -FilePath $filePath -ArgumentList "/S" -Verb RunAs
        Write-Log -Message "VLC Media Player has been uninstalled." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    } else {
        Write-Log -Message "VLC Media Player is not installed on the device." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    }

    # Remove 7zip if on 24H2
    $osVersion = (Get-ComputerInfo).OSDisplayVersion

    if ($osVersion -eq '24H2') {
        Write-Log -Message "The OS version is 24H2." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black
        winget Uninstall --silent --accept-source-agreements --all-versions --id 7zip.7zip
        Write-Log -Message "Uninstalled 7zip." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    } else {
        Write-Log -Message "The OS version is not 24H2. It is: $osVersion" -LogFilePath $logFile -ForegroundColor Red -BackgroundColor Black
    }

    # Microsoft Copilot
    winget uninstall --silent --accept-source-agreements --id 9NHT9RB2F4HD
    Write-Log -Message "Uninstalled Microsoft Copilot." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black

    # Microsoft 365 Copilot
    winget uninstall --silent --accept-source-agreements --id 9WZDNCRD29V9
    Write-Log -Message "Uninstalled Microsoft 365 Copilot." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black

    # Microsoft Cortana
    winget uninstall --silent --accept-source-agreements --id 9NFFX4SZZ23L
    Write-Log -Message "Uninstalled Microsoft Cortana." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black

    # TODO: Verify uninstallations do not conflict while running in parallel 
    # # Define the PowerShell Version
    # $psVersion = $PSVersionTable.PSVersion.Major

    # # Verify version and run appropriate for-loop
    # if ($psVersion -lt 6) {
    #     # For PowerShell 5.1 and below: Use the ForEach-Object loop
    #     foreach ($app in $bloatware) {
    #         # Get the package for the current user
    #         $package = Get-AppxPackage -Name $app -ErrorAction SilentlyContinue

    #         # Remove the package for the current user
    #         if ($package) {
    #             # Remove the package
    #             Remove-AppxPackage -Package $package.PackageFullName -ErrorAction SilentlyContinue
    #             Write-Host "Uninstalled bloatware: $app"
    #             "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Uninstalled bloatware: $app" | Out-File -FilePath $logFile -Append
    #         } else {
    #             Write-Host "Package not found or already removed: $app"
    #             "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Package not found or already removed: $app" | Out-File -FilePath $logFile -Append
    #         }
    #     }
    # } else {
    #     # For PowerShell 7 and above: Use the ForEach-Object -Parallel loop
    #     $bloatware | ForEach-Object -Parallel {
    #         # Get the package for the current user
    #         $package = Get-AppxPackage -Name $app -ErrorAction SilentlyContinue

    #         # Remove the package for the current user
    #         if ($package) {
    #             # Remove the package
    #             Remove-AppxPackage -Package $package.PackageFullName -ErrorAction SilentlyContinue
    #             Write-Host "Uninstalled bloatware: $app"
    #             "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Uninstalled bloatware: $_" | Out-File -FilePath $logFile -Append
    #         } else {
    #             Write-Host "Package not found or already removed: $_"
    #             "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Package not found or already removed: $_" | Out-File -FilePath $logFile -Append
    #         }
    #     } -ThrottleLimit 4
    # }

    # Remove bloatware in the list
    foreach ($app in $bloatware) {
        # Get the package for the current user
        $package = Get-AppxPackage -Name $app -ErrorAction SilentlyContinue

        if ($package) {
            try {
                # Remove the package for the current user
                Remove-AppxPackage -Package $package.PackageFullName -ErrorAction SilentlyContinue
                Write-Log -Message "Uninstalled bloatware: $app" -LogFilePath $logFile -Silent
            } catch {
            }
        }

        # Get the provisioned package for all users
        $provisionedPackage = Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq $app}

        # Remove provisioned package for all users
        if ($provisionedPackage) {
            try {
                # Remove the provisioned package
                Remove-AppxProvisionedPackage -Online -PackageName $provisionedPackage.PackageName -ErrorAction SilentlyContinue
                Write-Log -Message "Removed provisioned package: $app" -LogFilePath $logFile -Silent
            } catch {
            }
        }

        Write-Log -Message "Package not found or already removed: $app" -LogFilePath $logFile -Silent
    }

    # End logging
    Write-Log -Message "================================================================================" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black
    Write-Log -Message "Completed removeBloat function." -LogFilePath $logFile -Silent
    # "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Completed removeBloat function." | Out-File -FilePath $logFile -Append
}

function MaintenanceAndIntegrity {
    <#
    .SYNOPSIS
        Performs maintenance tasks and integrity checks on the device.

    .DESCRIPTION
        This function performs a series of maintenance tasks including running Disk Cleanup,  
        checking for Windows Integrity violations, and logging the results. It also provides  
        feedback to the user about the completion of these tasks.

    .PARAMETER None
        This function does not require any parameters.

    .EXAMPLE
        PS C:\> MaintenanceAndIntegrity
        Runs Disk Cleanup and checks for Windows Integrity violations.

    .NOTES
        Author:  David Tom (OTS)
        Contact: David.Tom@CSN.edu
        Dependencies:
            - Disk Cleanup (Cleanmgr.exe) must be available on the system.
            - The script assumes that the user has the necessary permissions to run these tasks.
    #>

    # Stage 9: Run Disk Cleanup
    # Example: Turn on 'all items' for SageSet ID 1
    # $VolumeCaches = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"

    # Get-ChildItem -Path $VolumeCaches | ForEach-Object {
    #     # For each cache item, set the StateFlags0001 value to 2 (enabled)
    #     Set-ItemProperty -Path $_.PsPath -Name "StateFlags0001" -Value 2 -ErrorAction SilentlyContinue
    # }

    Start-Process -FilePath "Cleanmgr.exe" -ArgumentList "/sagerun:1" -NoNewWindow
    Write-Log -Message "Disk Cleanup has been run..." -LogFilePath $logFile

    # Stage 10: Verify Windows Integrity
    Write-Log -Message "Running Windows Integrity Check via SFC & DISM, please wait roughly 5 minutes..." -LogFilePath $logFile
    sfc /scannow
    Dism /Online /Cleanup-image /ScanHealth 
    Dism /Online /Cleanup-image /CheckHealth 
    Dism /Online /Cleanup-image /RestoreHealth 
    Dism /Online /Cleanup-image /StartComponentCleanup 
}

function VerifyAndDriverUpdater {
    <#
    .SYNOPSIS
        Opens Device Manager and logs the event for manual driver inspection.

    .DESCRIPTION
        Launches the Device Manager (using the "devmgmt" command) to allow the user to manually inspect  
        and update missing or problematic drivers. Although the code for automatic driver updating is provided  
        in comments, the primary function is to prompt manual verification and log the action.

    .PARAMETER None
        This function does not require any parameters.

    .EXAMPLE
        PS C:\> VerifyAndDriverUpdater
        Opens Device Manager for the user to check and update drivers.

    .NOTES
        Author:  David Tom (OTS)
        Contact: David.Tom@CSN.edu
        The automatic driver update code is commented out; modify as needed for your environment.
    #>

    # Begin logging
    Write-Log -Message "Starting VerifyAndDriverUpdater function." -LogFilePath $logFile -Silent

    # Load device manager to manually inspect any missing drivers
    devmgmt
    Write-Log -Message "Opened Device Manager for manual inspection." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black

    # End logging
    Write-Log -Message "Completed VerifyAndDriverUpdater function." -LogFilePath $logFile -Silent
}

function Get-ADDomain {
    <#
    .SYNOPSIS
        Retrieves the Active Directory domain of the device.

    .DESCRIPTION
        Uses WMI to query the Win32_ComputerSystem class and extracts the Domain property,  
        returning the domain name as a trimmed string.

    .PARAMETER None
        This function does not accept any parameters.

    .EXAMPLE
        PS C:\> Get-ADDomain
        Returns the Active Directory domain for the device.

    .NOTES
        Author:  David Tom (OTS)
        Contact: David.Tom@CSN.edu
    #>

    $ADDomain = (Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty Domain).Trim()
    return $ADDomain
}

# Format deletion of files for PS7
function MainFunction {
    <#
    .SYNOPSIS
        Orchestrates the complete post-check process for the device image.

    .DESCRIPTION
        This function acts as the main driver for the post-checks and update process. It clears the 
        screen, initializes logging, captures the user’s selection (Quick or Full mode), and constructs 
        the log file path. It then sequentially performs several tasks, including:
        - Displaying a user acknowledgement prompt (if not run by a specific user)
        - Installing or updating Lenovo system management tools (via LenovoSystemUpdateToVantage)
        - Verifying and flashing the asset tag if needed (VerifyAndFlashAssetTag)
        - Adjusting power settings (powerSettings)
        - Displaying device information (Write-DeviceInformationHeader)
        - Removing the Windows Update cache (if in Full mode)
        - Modifying registry keys (RegistryKeyModifications)
        - Triggering Office updates silently
        - Invoking SCCM client actions (sccmModifications)
        - Forcing a Group Policy update
        - Running Windows Update via WindowsUpdaterPowerShell
        - Verifying and updating Microsoft Teams (VerifyClassicNewTeams)
        - Uninstalling VLC Media Player
        - Removing bloatware (RemoveBloat)
        - Optionally running Disk Cleanup and Windows Integrity checks (if in Full mode)
        - Launching larger applications for manual verification (VerifyLargerApps)
        - Opening Lenovo companion apps for further updates
        - Invoking driver verification/updater (VerifyAndDriverUpdater)
        - Enabling security features (Memory Integrity & Reputation Protection)
        - Verifying installed applications based on the Active Directory domain 
            (using Get-ADDomain and VerifyInstalledApps)
        - Finally, logging the completion of the script and initiating a reboot sequence

    .PARAMETER None
        This function does not accept any parameters.

    .EXAMPLE
        PS C:\> MainFunction
        Executes the complete post-check process and updates for the device image.

    .NOTES
        Author:  David Tom (OTS)
        Contact: David.Tom@CSN.edu
        DEPENDENCIES:
        - Other functions must be defined and available: Initialize-Logging, UserSelection, 
            UserAcknowledgement, LenovoSystemUpdateToVantage, VerifyAndFlashAssetTag, powerSettings, 
            Write-DeviceInformationHeader, RegistryKeyModifications, sccmModifications, WindowsUpdaterPowerShell, 
            VerifyClassicNewTeams, RemoveBloat, VerifyLargerApps, VerifyAndDriverUpdater, Get-ADDomain, VerifyInstalledApps, wingetUpdater.
        - Global variables such as $logFile, $studentAppArray, $facultyAppArray, etc., must be pre-defined.
    #>

    # Clear the screen and prep the device for post checks
    clear

    # Initializes the logging function
    Initialize-Logging

    # Store the user's choice as Quick or Full
    $userChoice = UserSelection

    # Log File Path
    $hostname = hostname
    # Deprecated: $serialNumber = (wmic bios get serialnumber | Select-Object -Skip 1 | Where-Object { $_ -ne "" }).Trim()
    $serialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
    $logFile = "\\cyapsft01\software\postChecks\logs\$hostname $serialNumber\postChecks-log_$([Environment]::UserName)_$(Get-Date -Format 'yyyyMMdd_HHmmss')_$serialNumber_$hostname.log"
    $loggedInUser = whoami
    $psVersion = $PSVersionTable.PSVersion.Major

    # Ensure the Logs directory exists
    $logDir = Split-Path -Parent $logFile
    if (!(Test-Path -Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force
    }

    # Start logging
    $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Log -Message "Script started at $stamp by $loggedInUser for SN: $serialNumber, $hostname. PowerShell: $psVersion" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    # Stage 1: Start Post Checks
    # If user is "me" then ignore acknowledgement
    if ($loggedInUser -ne "csn\david.tom") {
        UserAcknowledgement
    } else {
        Write-Log -Message "Post Checks loading..." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black
    }

    # Begin installing Lenovo Commercial Vantage
    LenovoSystemUpdateToVantage

    # Remove Bloatware
    RemoveBloat

    # Function to get the asset tag
    $assetTag = (Get-WmiObject -Class Win32_SystemEnclosure | Select-Object -ExpandProperty SMBiosAssetTag).Trim()

    # Experimental: Verify Asset Tag is Valid
    # Do not use except on test machines
    if ($loggedInUser -eq "csn\david.tom" -or $loggedInUser -eq "csn\alexis.winn" -and $assetTag -eq "") {
        VerifyAndFlashAssetTag
        Write-Log -Message "Called VerifyAndFlashAssetTag function." -LogFilePath $logFile -Silent
    } else {
        Write-Log -Message "Manually verify and flash asset tag..." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black
    }

    # Verify Power Settings
    powerSettings

    # Verify Device Information
    Write-Log -Message "Starting Post Checks for Device: " -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black
    Write-DeviceInformationHeader

    # If the user selects Quick, skip the Windows Update Cache removal
    if ($userChoice -eq "Full") {
        # Remove Windows Update Cache
        Write-Log -Message "Removing Windows Update Cache... Please wait ~3 minutes." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black

        # Stop the Windows Update service to prevent the directory from being locked
        net stop wuauserv
        net stop bits
        Write-Log -Message "Stopped Windows Update service." -LogFilePath $logFile -Silent

        # Take ownership of the SoftwareDistribution folder
        takeown /f "C:\Windows\SoftwareDistribution\Download" /r /d y | Out-Null
        icacls "C:\Windows\SoftwareDistribution\Download" /reset /T | Out-Null
        icacls "C:\Windows\SoftwareDistribution\Download" /grant Administrators:F /T | Out-Null
        Write-Log -Message "Took ownership of the SoftwareDistribution folder." -LogFilePath $logFile -Silent

        # Remove the contents of the SoftwareDistribution folder
        Remove-Item -Path "C:\Windows\SoftwareDistribution\Download\" -Recurse -Include *.* -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Removed contents of the SoftwareDistribution folder." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black

        # Start the Windows Update service
        net start wuauserv
        net start bits
        Write-Log -Message "Started Windows Update service." -LogFilePath $logFile -Silent

        # Additional logging for main function
        Write-Log -Message "Initiated device information header." -LogFilePath $logFile -Silent
    } else {
        Write-Log -Message "Skipping Windows Update Cache removal..." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black
    }

    ######################### Registry Key Modifications ##########################

    # Stage 2: Modify the Registry Keys
    # Notes: If Automation fails - Manually Disable Copilot for Local Users on Local Group Policy
    # Group Policy - User Configurations - Administrative Templates - Windows Components - Windows Copilot - Edit and Enable to Stop
    RegistryKeyModifications

    ################################ Major Updates ################################

    # Stage 3: Microsoft Word Update Automation
    # Silent Automation: /update user displaylevel=false forceappshutdown=true
    try {
        & "C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe" /update user
    } catch {
        Write-Log -Message "Error: Office Updater failed!" -LogFilePath $logFile -ForegroundColor Red -BackgroundColor Black
        Write-Log -Message "Error: $_" -LogFilePath $logFile -ForegroundColor Red -BackgroundColor Black
    }

    ####################### Verification and Policy Updates #######################

    # Stage 4: Open Control Panel Actions
    # Notes: If Automation Fails - Manually Open Control Panel - 
    #                            - Large Buttons - Configuration Manager - Actions
    sccmModifications

    # Stage 5: Run Group Policy and Windows Update
    gpupdate /force
    Write-Log -Message "================================================================================" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    # Stage 6: Run Windows Update
    # https://learn.microsoft.com/en-us/answers/questions/1613848/update-and-restart-from-powershell-or-command-line
    # if ($userChoice -eq "Full") {
        WindowsUpdaterPowerShell
    # } else {
    #    Write-Host "Skipping Windows Update..." -ForegroundColor Green
    #    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Skipping Windows Update." | Out-File -FilePath $logFile -Append
    # }

    ############################### Browser Updates ###############################

    # Stage 7: Open all browsers to verify and update as needed
    # VerifyBrowserVersions

    # Stage 8: Verify Teams Version and Update as Needed
    VerifyClassicNewTeams

    if ($userChoice -eq "Full") {
        # Stage 9: Run Disk Cleanup and Windows Integrity Check
        MaintenanceAndIntegrity
    } else {
        Write-Log -Message "Skipping Disk Cleanup and Windows Integrity Check..." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    }

    # Stage 11: Open Windows Update - Manually inspect as needed
    # start ms-settings:windowsupdate

    Write-Log -Message "================================================================================" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    # Stage 12: Load Large Programs (ie. Creative Cloud & System Updater)
    VerifyLargerApps
    
    # Attempt to open Lenovo Vantage or Lenovo Commercial Vantage
    try {
        Start-Process "shell:AppsFolder\E046963F.LenovoCompanion_k1h2ywk1493x8!App"
    } catch {
        Write-Log -Message "Lenovo Vantage not found!" -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    }
    
    try {
        Start-Process "shell:AppsFolder\E046963F.LenovoSettingsforEnterprise_k1h2ywk1493x8!App"
    } catch {
        Write-Log -Message "Lenovo Commercial Vantage not found!" -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    }

    Write-Log -Message "================================================================================" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    # Stage 13: Open Device Manager - Visually Verify Drivers & Apps and Update as Needed
    VerifyAndDriverUpdater
    Write-Log -Message "================================================================================" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    # Stage 14: Redundantly Enables Memory Integrity & Reputation Protection
    # https://chatgpt.com/c/67338fdc-113c-8010-9f10-6c6185178723
    # Get-MpPreference | Select-Object -Property PUAProtection
    Write-Log -Message "Enabling Memory Integrity & Reputation Protection..." -LogFilePath $logFile -Silent
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\' -Name 'Enabled' -Value 1 -Force   # 0 Disables, 1 Enables 
    Set-MpPreference -PUAProtection Enabled

    Write-Log -Message "Finalized Post Checks for: " -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black
    Write-DeviceInformationHeader
        
    $ADDomain = Get-ADDomain

    Write-Log -Message "================================================================================" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black

    # Compare Apps to student or faculty device
    if ($ADDomain -like '*Student*') {
        Write-Log -Message "Verifying Student Apps..." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black
        VerifyInstalledApps -appArray $studentAppArray
        winget uninstall --silent --accept-source-agreements --id 9WZDNCRDJ8LH    # Cisco Secure Client - AnyConnect
        winget uninstall --silent --accept-source-agreements --id 9NBLGGH16P7H    # Hyland OnBase
    } else {
        Write-Log -Message "Verifying Faculty Apps..." -LogFilePath $logFile -ForegroundColor Yellow -BackgroundColor Black
        VerifyInstalledApps -appArray $facultyAppArray
    }

    # Final logging
    Write-Log -Message "Post Checks completed for: $hostname" -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    Write-Log -Message "All Updates are completed. Please restart and re-run to verify everything was installed." -LogFilePath $logFile -ForegroundColor Green -BackgroundColor Black
    Write-Log -Message "================================================================================" -LogFilePath $logFile -ForegroundColor White -BackgroundColor Black
}

######################## Variable & Array Declarations ########################

# Brief: List of programs that require a long time and must manually be updated
$majorArray = @(
    'C:\Program Files\Adobe\Adobe Creative Cloud\ACC\Creative Cloud.exe'
    'C:\Program Files (x86)\Lenovo\System Update\tvsu.exe'
)

# Brief: List of browsers that must be manually updated.
$browserArray = @(
    'C:\Program Files\Google\Chrome\Application\chrome.exe'
    'C:\Program Files\Mozilla Firefox\firefox.exe'
    'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
)

# Brief: List of registery keys that must be modified.
$registryArray = @(
    'HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot'
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'
)

# Brief: Dependent on registeryArray - List of values to update as needed.
$registryModifications = @(
    @{ Path = $registryArray[0]; Name = "TurnOffWindowsCopilot"; Value = 0 },      # Disable Copilot
    @{ Path = $registryArray[1]; Name = "TaskbarAl"; Value = 0 },                  # Left Align Taskbar
    @{ Path = $registryArray[1]; Name = "ShowCopilotButton"; Value = 0 },          # Remove Copilot Button
    @{ Path = $registryArray[1]; Name = "ShowTaskViewButton"; Value = 0 },         # Remove Task View
    # @{ Path = $registryArray[1]; Name = "TaskbarDa"; Value = 0 },                  # Remove Widgets
    @{ Path = $registryArray[2]; Name = "IsDynamicSearchBoxEnabled"; Value = 0 }   # Remove Highlights
)

# Brief: List of SCCM Actions that must be run.
$SCCMActions = @(   
    "{00000000-0000-0000-0000-000000000121}",  # Application Deployment Evaluation Cycle
    "{00000000-0000-0000-0000-000000000003}",  # Discovery Data Collection Cycle
    "{00000000-0000-0000-0000-000000000010}",  # File Collection Cycle
    "{00000000-0000-0000-0000-000000000001}",  # Hardware Inventory Cycle
    "{00000000-0000-0000-0000-000000000021}",  # Machine Policy Retrieval & Evaluation Cycle
    "{00000000-0000-0000-0000-000000000002}",  # Software Inventory Cycle
    "{00000000-0000-0000-0000-000000000031}",  # Software Metering Usage Report Cycle
    # "{00000000-0000-0000-0000-000000000026}",  # User Policy Retrieval
    # "{00000000-0000-0000-0000-000000000027}",  # User Policy Retrieval & Evaluation Cycle
    "{00000000-0000-0000-0000-000000000032}"   # Windows Installer Source List Update Cycle
)

# Brief: List of applications to have winget update
$wingetArrray = @(
    '7zip.7zip',
    'Adobe.Acrobat.Reader.32-bit',
    'Adobe.CreativeCloud',
    'Cisco.Webex',
    'Google.Chrome',
    # 'Lenovo.SystemUpdate',
    'Microsoft.Edge',
    'Microsoft.OneDrive',
    # 'Microsoft.Office',
    'Microsoft.Teams',
    'Microsoft.Teams.Classic',
    'Microsoft.UI.Xaml.2.7',
    'Microsoft.VCRedist2015+.x64',
    'Microsoft.VCRedist2015+.x86',
    'Microsoft.WindowsTerminal',
    'Mozilla.Firefox'
    # 'Oracle.JavaRuntimeEnvironment',
    # 'VideoLAN.VLC'
)

# List of bloatware to remove from the device
$bloatware = @(
    'Microsoft.549981C3F5F10',
    'Microsoft.3DBuilder',
    'Microsoft.BingWeather',
    # 'Microsoft.DesktopAppInstaller',
    # 'Microsoft.GetHelp',
    # 'Microsoft.Getstarted',
    'Microsoft.Messaging',
    'Microsoft.Microsoft3DViewer',
    # 'Microsoft.MicrosoftOfficeHub',
    'Microsoft.MicrosoftSolitaireCollection',
    # 'Microsoft.MicrosoftStickyNotes',
    # 'Microsoft.MicrosoftTo-Do',
    # 'Microsoft.MSPaint',
    # 'Microsoft.Office.OneNote',
    'Microsoft.OneConnect',
    'Microsoft.People',
    'Microsoft.Print3D',
    # 'Microsoft.SkypeApp',
    'Microsoft.StorePurchaseApp',
    'Microsoft.Wallet',
    # 'Microsoft.Windows.Photos',
    'Microsoft.WindowsAlarms',
    # 'Microsoft.WindowsCalculator',
    # 'Microsoft.WindowsCamera',
    # 'Microsoft.WindowsMaps',
    # 'Microsoft.WindowsSoundRecorder',
    # 'Microsoft.WindowsStore',
    'Microsoft.WindowsFeedbackHub',        # Feedback Hub
    'Microsoft.WindowsMaps',               # Maps
    'Clipchamp.Clipchamp',                 # Clipchamp
    'Microsoft.BingNews',                  # Microsoft News
    'Microsoft.BingSearch',                # Bing Search
    'Microsoft.BingSports',                # Microsoft Sports
    'Microsoft.BingFinance',               # Microsoft Finance
    'Microsoft.BingTravel',                # Microsoft Travel
    'Microsoft.BingFoodAndDrink',          # Microsoft Food & Drink
    'Microsoft.BingHealthAndFitness',      # Microsoft Health & Fitness
    'Microsoft.BingWeather',               # Microsoft Weather
    'Microsoft.BingMaps',                  # Microsoft Maps
    # 'MicrosoftWindows.Client.WebExperience', # Widgets Platform Runtime
    'Microsoft.GamingApp',                 # Xbox Game Bar
    'Microsoft.GamingServices',            # Additional Xbox-related packages
    'Microsoft.Xbox.TCUI',
    'Microsoft.XboxApp',
    'Microsoft.XboxGameCallableUI',
    'Microsoft.XboxGameOverlay',
    'Microsoft.XboxGamingOverlay',
    'Microsoft.XboxIdentityProvider',
    'Microsoft.XboxSpeechToTextOverlay',
    'Microsoft.YourPhone',
    'Microsoft.ZuneMusic',
    'Microsoft.ZuneVideo'
)

# Brief: List of student apps that are checked at the end of the program.
$studentAppArray = @(
    "Acrobat"
    "7-Zip"
    "VLC"
    "Teams"
    "AgentSetup"
    "Alertus"
    "Sassafras"
    "Office"
    "LanSchool"
)

# Brief: List of faculty apps that are checked at the end of the program.
$facultyAppArray = @(
    "Acrobat"
    "7-Zip"
    "Cisco"
    "Teams"
    "AgentSetup"
    "Alertus"
    "PaperCut"
    "Sassafras"
    "Hyland"
    "Office"
)

###############################################################################
################################ Main Function ################################
###############################################################################
# Brief: Main function that will run all the post checks and updates.
# Notes: If the user is "me" then the script will automatically run without any prompts.

$loggedinUser = whoami

# Run the Main Function
if ($loggedInUser -eq "csn\david.tom") {
    # Time the length it takes to run the Main Function (Testing/Debugging)
    Measure-Command { MainFunction } | Select-Object -Property TotalSeconds
} else {
    MainFunction
}

# Reboot the device after all checks have been completed
Write-Host -Message "Device will automatically reboot in 10 minutes..." -ForegroundColor Green
Start-Sleep -Seconds 600
Restart-Computer -Force

# EOF: postChecks.ps1
