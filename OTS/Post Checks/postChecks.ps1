###############################################################################
# Author: David Tom                                                           #
# Date:   July 3, 2024                                                        #
# File:   postChecks.ps1                                                      #
###############################################################################
# Brief:  This Windows 11 PowerShell script will attempt to update all the    #
#         required software, settings, and registry keys during a device's    #
#         post checks as per CSN's OTS imaging requirements with little to    #
#         no user intervention. The script also verifies Windows 11 License   #
#         and updates the Enterprise License as needed.                       #
###############################################################################
# How To: Run the program in PowerShell by either copying/pasting into the    #
#         shell and running as Administrator. The program will automatically  #
#         perform a majority of the device's post checks.                     #
#         Some post checks must still be performed manually such as updating  #
#         Creative Cloud and flashing Asset Tags.                             #
###############################################################################
# TODO:   1. Test Updater Versions of Creative Cloud & Browsers.              #
#         2. Test Lenovo System Updater in Production Env.                    #
#         3. Obtain and test Intune Recovery Key.                             #
###############################################################################



################################## Functions ##################################

<# Brief:  Function is used to advise the user on how to run the script and
        provides contact information if any questions, comments, or concerns.
    param:  N/A
    return: N/A
    Note: Questions, comments, or concerns, please contact David Tom (OTS)
#>
function UserAcknowledgement {
    # Load Windows Forms Assembly
    Add-Type -AssemblyName System.Windows.Forms

    # Display the popup message box
    $result = [System.Windows.Forms.MessageBox]::Show("Note:

    The program will automatically perform a majority of the required post checks but manual verification is needed for the below processes:

    1. Manually update:
        - Lenovo System Updater
        - Creative Cloud

    2. Manually verify:
        - SCCM Actions are available
        - Run Action [User Policy Retrieval & Evaluation Cycle]

    3. Manually verify and flash Asset Tag as needed.

    4. Manually install any missing Apps & Programs.
        - Automation for browser updates & Teams may require Windows Update to finish alongside a reboot.
        - Run the program multiple times after a reboot to verify all updates are installed.

    5. Run the following after you reboot!
        - Window's Update
        - Lenovo System Update

    Any questions, comments, or concerns please contact:
    David Tom (David.Tom@CSN.edu)", "Post Checks - Acknowledgement", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)

    # Optional: Handle the user's response (if needed)
    $acknowledgedUser = whoami

    switch ($result) {
        'OK' {
            Write-Host "$acknowledgedUser has acknowledged the notice."
            
            # Log the user acknowledgement
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $acknowledgedUser has acknowledged the notice." | Out-File -FilePath $logFile -Append
        }
        Default {
            Write-Host "User response: $result"

            # Log the user response
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] User response: $result" | Out-File -FilePath $logFile -Append        }
    }
}

<#  Brief:  Function will prompt the user to select either Quick or Full Post Checks.
    param:  N/A
    return: The user's selection (Quick or Full)
    Note:   Questions, comments, or concerns, please contact David Tom (OTS)
#>
function UserSelection {
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

<# Brief: Get the BitLocker recovery key for a computer from Active Directory
    param: $computerName - The name of the computer to retrieve the recovery key for
    return: The BitLocker recovery key for the specified computer
    Note: This function requires the Active Directory module to be installed alongside RSAT Tools
#>
function Get-ADRecoveryKey {
    param (
        [string]$computerName
    )

    # Import the Active Directory module 
    Import-Module ActiveDirectory

    # Get the computer object from Active Directory
    $objComputer = Get-ADComputer -Identity $computerName

    # Retrieve BitLocker recovery information from the computer object
    $Bitlocker_Object = Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $objComputer.DistinguishedName -Properties 'msFVE-RecoveryPassword'

    # Display the BitLocker recovery key
    return $Bitlocker_Object.'msFVE-RecoveryPassword'
} # End of Get-ADRecoveryKey function

<# Brief:  Function will obtain and output the Device & User Information.
    param:  N/A
    return: N/A
    Note: Questions, comments, or concerns, please contact David Tom (OTS)
#>
function Write-DeviceInformationHeader {
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
        $loggedInUser = whoami  # (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName).Trim()
        return $loggedInUser
    }

    function Get-ADDomain {
        $ADDomain = (Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty Domain).Trim()
        return $ADDomain
    }

    # Gather device information
    # Begin logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting Write-DeviceInformationHeader function." | Out-File -FilePath $logFile -Append

    # Gather device information
    $hostname = Get-Hostname
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Hostname: $hostname" | Out-File -FilePath $logFile -Append

    $serialNumber = Get-SerialNumber
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Serial Number: $serialNumber" | Out-File -FilePath $logFile -Append

    $assetTag = Get-AssetTag
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Asset Tag: $assetTag" | Out-File -FilePath $logFile -Append

    $loggedInUser = Get-LoggedInUser
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Logged-In User: $loggedInUser" | Out-File -FilePath $logFile -Append

    $ADDomain = Get-ADDomain
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Windows Domain: $ADDomain" | Out-File -FilePath $logFile -Append

    # $recoveryKey = Get-ADRecoveryKey -computerName $hostname
    # "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Active Directory Recovery Key: $recoveryKey" | Out-File -FilePath $logFile -Append

    # Write Header - Device Information
    Write-Host "============================== Device Information =============================="
    Write-Host "Hostname:         $hostname"
    Write-Host "Serial Number:    $serialNumber"
    Write-Host "Asset Tag:        $assetTag"
    Write-Host "Logged-In User:   $loggedInUser"
    Write-Host "Windows Domain:   $ADDomain"
    # Write-Host "Recovery Key:     $recoveryKey"
    Write-Host "================================================================================"

    # Write Detailed Device Information
    Get-ComputerInfo | Select-Object CsSystemFamily, WindowsProductName, OsName, WindowsVersion, OsHardwareAbstractionLayer, WindowsRegisteredOrganization, WindowsRegisteredOwner
    Write-Host "================================================================================"

    # Log the detailed device information
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Detailed Device Information:" | Out-File -FilePath $logFile -Append
    $computerInfo = Get-ComputerInfo | Select-Object CsSystemFamily, WindowsProductName, OsName, WindowsVersion, OsHardwareAbstractionLayer, WindowsRegisteredOrganization, WindowsRegisteredOwner
    $computerInfo | Format-List | Out-String | Out-File -FilePath $logFile -Append

    # Verify Windows License is Enterprise
    VerifyAndApplyWindowsLicense
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Called VerifyAndApplyWindowsLicense function." | Out-File -FilePath $logFile -Append

}

<# Brief: Function will verify Windows OS is Enterprise or Pro & Apply License
        and Reboot as needed.
    param: string $licenseKey (Encoded License Key)
    return: N/A
    Note: Questions, comments, or concerns, please contact David Tom (OTS)
        [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("NPPR9-FWDCX-D2C8J-H872K-2YT43"))
        [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TlBQUjktRldEQ1gtRDJDOEotSDg3MkstMllUNDM="))
#>
function VerifyAndApplyWindowsLicense {
    param(
        # Base64 Encoded License Key for Windows 11 Enterprise
        [string]$licenseKey = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TlBQUjktRldEQ1gtRDJDOEotSDg3MkstMllUNDM="))
    )

    # Begin logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting VerifyAndApplyWindowsLicense function." | Out-File -FilePath $logFile -Append

    # Get Windows OS Edition
    $windowsEdition = (Get-WmiObject -Query "SELECT * FROM Win32_OperatingSystem").Caption
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Detected Windows Edition: $windowsEdition" | Out-File -FilePath $logFile -Append

    # Check if Windows is Enterprise
    if ($windowsEdition -like "*Enterprise*") {
        Write-Host "This IS Windows ENTERPRISE" -ForegroundColor Green
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Windows is already Enterprise edition. No action needed." | Out-File -FilePath $logFile -Append
    } elseif ($windowsEdition -like "*Pro*") {
    # Check if Windows is a Pro License and apply license, then reboot
        Write-Host "This is Windows Pro -- NOT ENTERPRISE" -ForegroundColor Red
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Windows is Pro edition. Attempting to upgrade to Enterprise." | Out-File -FilePath $logFile -Append

        # Apply license, then reboot
        slmgr /ipk $licenseKey
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Applied Enterprise license key successfully and rebooting." | Out-File -FilePath $logFile -Append        
        
        Write-Host "Restarting in 10 seconds..."
        Start-Sleep -Seconds 10
        Restart-Computer
    } else {
    # Apply license, then reboot
        Write-Host "This is NOT Windows ENTERPRISE" -ForegroundColor Red
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Windows edition is neither Enterprise nor Pro. Attempting to apply Enterprise license." | Out-File -FilePath $logFile -Append

        # Apply license, then reboot
        slmgr /ipk $licenseKey
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Applied Enterprise license key successfully." | Out-File -FilePath $logFile -Append

        Write-Host "Restarting in 10 seconds..."
        Start-Sleep -Seconds 10
        Restart-Computer
    }

    # End logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Completed VerifyAndApplyWindowsLicense function." | Out-File -FilePath $logFile -Append
}

<# Brief:  Function will disable sleep and display timeout settings.
    param:  N/A
    return: N/A
    Note: Questions, comments, or concerns, please contact David Tom (OTS)
#>
function powerSettings {
    # Disable sleep and display timeout when plugged in (AC power)
    powercfg /change standby-timeout-ac 0
    powercfg /change monitor-timeout-ac 0

    # Disable sleep and display timeout when on battery (DC power)
    powercfg /change standby-timeout-dc 0
    powercfg /change monitor-timeout-dc 0

    Write-Host "Sleep and display timeouts have been disabled."
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Completed modifying power and sleep settings." | Out-File -FilePath $logFile -Append
}

<# Brief:  Function will identify and verify AssetTag of the device and navigate
        to the appropriate directory in the J: drive to flash the device.
    param:  N/A
    return: N/A
    Note: Questions, comments, or concerns, please contact David Tom (OTS)
        Currently supports: 
        T14, X13, M90q
#>
function VerifyAndFlashAssetTag {
    # Begin logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting VerifyAndFlashAssetTag function." | Out-File -FilePath $logFile -Append

    # Function to check and disable Memory Integrity
    function DisableMemoryIntegrity {
        $hvciKeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\'
        $hvciEnabled = Get-ItemProperty -Path $hvciKeyPath -Name 'Enabled' -ErrorAction SilentlyContinue

        if ($hvciEnabled.Enabled -eq 1) {
            Write-Host "Memory Integrity is currently ON. Disabling and restarting..." -ForegroundColor Yellow

            # Log that Memory Integrity is being disabled
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Memory Integrity is ON. Disabling and restarting..." | Out-File -FilePath $logFile -Append

            Set-ItemProperty -Path $hvciKeyPath -Name 'Enabled' -Value 0 -Force
            Write-Host "Computer will restart in 10 seconds..."
            Start-Sleep -Seconds (10)
            Restart-Computer
        } else {
            Write-Host "Memory Integrity is already OFF." -ForegroundColor Green

            # Log that Memory Integrity is already OFF
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Memory Integrity is already OFF." | Out-File -FilePath $logFile -Append
        }
    }

    # Obtains device information
    $modelName = (Get-ComputerInfo | Select-Object -ExpandProperty CsSystemFamily).Trim()
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Device model name: $modelName" | Out-File -FilePath $logFile -Append

    # Check if the device is a Yoga
    if ($modelName -like "*Yoga*" -or $modelName -like "*9[^0]+0*") {
        Write-Host "Device is not currently supported.  Skipping asset tag flashing." -ForegroundColor Red
        
        # Log that asset tag flashing is skipped
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Device is not currently supported. Skipping asset tag flashing." | Out-File -FilePath $logFile -Append
    } else {
        # Check if asset tag is missing or invalid
        if (-not $assetTag -or $assetTag -notmatch '^\d+$') {
            # Log that no valid asset tag is found
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] No valid Asset Tag found." | Out-File -FilePath $logFile -Append

            $tmpAnswer = Read-Host "Error: No valid Asset Tag found... Would you like to flash the asset tag now? (Y for yes, N for no)"
            
            # Convert user input to upper
            if ($tmpAnswer.ToUpper() -eq 'Y') {
                # Obtain a valid AssetTag
                $tmpAsset = Read-Host "Enter an asset tag for the device"
                "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] User chose to flash asset tag with value: $tmpAsset" | Out-File -FilePath $logFile -Append

                # Verify if device is a laptop
                if ($modelName -like "*ThinkPad*" -or $modelName -like "*T14*" -or $modelName -like "*X13*") {
                    $sourcePath = "\\cyapsft01\software\Lenovo\Laptops\"
                    Copy-Item -Recurse -Path $sourcePath -Destination "C:\"
                    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Copied files from $sourcePath to $destinationPath" | Out-File -FilePath $logFile -Append
                    
                    # Run the Asset Tag Flashing program
                    & "C:\Laptops\WinAIA.exe" -set "USERASSETDATA.ASSET_NUMBER=$tmpAsset"
                    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Flashed asset tag on laptop with WinAIA.exe" | Out-File -FilePath $logFile -Append
                }
                elseif ($modelName -like "*90q*") {
                    $sourcePath = "\\cyapsft01\software\ASSETTAG\LENOVO\M90\"
                    Copy-Item -Recurse -Path $sourcePath -Destination "C:\"
                    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Copied files from $sourcePath to $destinationPath" | Out-File -FilePath $logFile -Append

                    # Run the Asset Tag Flashing program
                    & "C:\M90\AMIDEWIN.exe" /CA $tmpAsset
                    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Flashed asset tag on laptop with AMIDEWIN.exe" | Out-File -FilePath $logFile -Append
                }
                elseif ($modelName -like "*ThinkCentre*") {
                    # Verify if device is a desktop
                    $model = $modelName -replace "ThinkCentre ", "" -replace "[a-zA-Z]+$", ""
                    $sourcePath = "\\cyapsft01\software\ASSETTAG\LENOVO\$model\"
                    Copy-Item -Recurse -Path $sourcePath -Destination "C:\LENOVO\$model\"
                    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Copied files from $sourcePath to $destinationPath" | Out-File -FilePath $logFile -Append
                    
                    # Run the Asset Tag Flashing program
                    & "C:\LENOVO\$model\wflash2.exe" -set "/tag:$tmpAsset"
                    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Flashed asset tag on desktop with wflash2.exe" | Out-File -FilePath $logFile -Append
                }
                else {
                    # Log that the model is invalid
                    Write-Host "Invalid Model: $modelName."
                    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Invalid model for asset tag flashing: $modelName" | Out-File -FilePath $logFile -Append
                    return
                }
            } else {
                # Log that the user chose not to flash the asset tag
                Write-Host "Continuing with program without changing Asset Tag..."
                "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] User chose not to flash asset tag." | Out-File -FilePath $logFile -Append
            }
        } else {
            # Log that a valid asset tag is found
            Write-Host "Valid asset tag found: $assetTag" -foregroundcolor Green
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Valid asset tag found: $assetTag" | Out-File -FilePath $logFile -Append
        }
    }

    # End logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Completed VerifyAndFlashAssetTag function." | Out-File -FilePath $logFile -Append
}

<# Brief:  Function will modify registery keys based on the registry array.
    param:  N/A
    return: N/A
    Note: Questions, comments, or concerns, please contact David Tom (OTS)
#>
function RegistryKeyModifications {
    # Begin logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting RegistryKeyModifications function." | Out-File -FilePath $logFile -Append

    # Loop through the registry array and modify the keys
    foreach ($modification in $registryModifications) {
        if (Test-Path $modification.Path) {
            try {
                Set-ItemProperty -Path $modification.Path -Name $modification.Name -Value $modification.Value -Force | Out-Null

                #Write-Host "Registry Key `($($modification.Name))` at `($($modification.Path))` modified successfully."
                "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Modified registry key '$($modification.Name)' at '$($modification.Path)' with value '$($modification.Value)'." | Out-File -FilePath $logFile -Append
            } catch {
                #Write-Host "Error: Registry Key `($($modification.Name))` at `($($modification.Path))` could not be modified. Error: $_"
                "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Error modifying registry key '$($modification.Name)' at '$($modification.Path)': $errorMessage" | Out-File -FilePath $logFile -Append
            }
        } else {
            #Write-Host "Registry Key `($($modification.Name))` at `($($modification.Path))` $modification.Path does not exist"
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Registry path does not exist: '$($modification.Path)'. Cannot modify key '$($modification.Name)'." | Out-File -FilePath $logFile -Append
        }
    }
    Write-Host "================================================================================"
    
    # End logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Completed RegistryKeyModifications function." | Out-File -FilePath $logFile -Append
}

<# Brief:  Function will verify and output all installed applications.
    param:  N/A
    return: N/A
    Note: Questions, comments, or concerns, please contact David Tom (OTS)
#>
function VerifyInstalledApps {
    param (
        [Parameter(Mandatory=$true)]
        [string[]]$appArray
    )

    # Begin logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting VerifyInstalledApps function." | Out-File -FilePath $logFile -Append

    # Get a list of installed applications from the registry
    $installedApps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                       HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* `
                      | Where-Object { $_.DisplayName -ne $null } `
                      | Select-Object DisplayName

    # Print all discovered application names for debugging
    Write-Host "Installed Applications:"
    # $installedApps | ForEach-Object { Write-Host $_.DisplayName }

    # Log the total number of installed applications found
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Found $($installedApps.Count) installed applications." | Out-File -FilePath $logFile -Append

    # Loop through the apps we need to check
    foreach ($app in $appArray) {
        $appFound = $installedApps | Where-Object { $_.DisplayName -like "*$app*" }

        if ($appFound) {
            Write-Host "Success: $app is installed on the device..."
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Verified that '$app' is installed." | Out-File -FilePath $logFile -Append
        } else {
            Write-Host "WARNING: $app cannot be found!" -ForegroundColor Red
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] WARNING: '$app' is not installed on the device." | Out-File -FilePath $logFile -Append
        }
    }

    Write-Host "================================================================================"

    # End logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Completed VerifyInstalledApps function." | Out-File -FilePath $logFile -Append
}

<# Brief:  Function will attempt to load apps in array list in order to manually
        verify and allow a user to update.
    param:  N/A
    return: N/A
    Note: Questions, comments, or concerns, please contact David Tom (OTS)
#>
function VerifyLargerApps {
    # Begin logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting VerifyLargerApps function." | Out-File -FilePath $logFile -Append

    # Iterate through array and load apps
    foreach ($node in $majorArray) {
        if (Test-Path $node) {
            try {
                Start-Process -FilePath $node
                Write-Host "[$node] is attempting to load..."
                "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Launched application: $node" | Out-File -FilePath $logFile -Append
            } catch {
                Write-Host "Error: Issue found with loading [$node]! Error: $_"
                "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Error launching application ${node}: $errorMessage" | Out-File -FilePath $logFile -Append
            }
        } else {
            Write-Host "Failure - [$node] was not found!"
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Application not found: $node" | Out-File -FilePath $logFile -Append
        }
    }

    # End logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Completed VerifyLargerApps function." | Out-File -FilePath $logFile -Append
}

<# Brief:  Function will load the browsers in the array to perform post checks.
    param:  N/A
    return: N/A
    Note: Questions, comments, or concerns, please contact David Tom (OTS)
#>
function VerifyBrowserVersions {
    # Begin logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting VerifyBrowserVersions function." | Out-File -FilePath $logFile -Append
    
    # Manually Verify Browsers have been updated
    foreach ( $node in $browserArray ) {
        if (Test-Path $node) {
            Start-Process -FilePath $node

            Write-Host "$node is attempting to load..."
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Launched browser: $node" | Out-File -FilePath $logFile -Append
        } else {
            Write-Host "Failure - $node was not found!"
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Browser not found: $node" | Out-File -FilePath $logFile -Append
        }
    }
    Write-Host "================================================================================"

    # End logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Completed VerifyBrowserVersions function." | Out-File -FilePath $logFile -Append
}

<# Brief:  Function will load SCCM Actions in Control panel and run the actions.
        User must manually invoke any that failed.
    param:  N/A
    return: N/A
    Note: Questions, comments, or concerns, please contact David Tom (OTS)
#>
function sccmModifications {
    # Begin logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting sccmModifications function." | Out-File -FilePath $logFile -Append

    Write-Host "Manually run User Policy Retrieval & Evaluation Cycle AND Visually inspect all the SCCM Actions are available..." -ForegroundColor Yellow
    control smscfgrc

    # SCCM Actions Automation
    # https://www.anoopcnair.com/trigger-sccm-client-agent-actions-powershell/
    foreach ($action in $SCCMActions) {
        try {
            # Write-Host "Invoking SCCM Action: $action"
            Invoke-WmiMethod -Namespace "root\ccm" -Class "SMS_Client" -Name "TriggerSchedule" -ArgumentList $action
            $result = Invoke-WmiMethod -Namespace "root\ccm" -Class "SMS_Client" -Name "TriggerSchedule" -ArgumentList $action

            # Optional: Check the return value if necessary
            if ($result) {
                # Write-Host "SCCM Action $action invoked successfully."
                "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Successfully invoked SCCM Action: $action" | Out-File -FilePath $logFile -Append
            } else {
                # Write-Host "SCCM Action $action returned a non-success status: $($result.ReturnValue)"
                "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] SCCM Action $action returned a non-success status: $($result.ReturnValue)" | Out-File -FilePath $logFile -Append
            }

            # Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule $action
        } catch {
            Write-Host "Error: $action could not be run! Error: $_"
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Error invoking SCCM Action ${action}: $errorMessage" | Out-File -FilePath $logFile -Append
        }
    }
    Write-Host "================================================================================"

    # End logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Completed sccmModifications function." | Out-File -FilePath $logFile -Append
}

<# Brief:  Function will load Windows Updater to install all available updates.
    param:  N/A
    return: N/A
    Note: Questions, comments, or concerns, please contact David Tom (OTS)
#>
function WindowsUpdaterPowerShell {
    # Begin logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting WindowsUpdaterPowerShell function." | Out-File -FilePath $logFile -Append

    Write-Host "Verifying and Installing Windows Updates..." -ForegroundColor Yellow
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Initiating Windows Updates installation." | Out-File -FilePath $logFile -Append

    # Install Dependencies
    # Note: Out-Null removes all text to screen *Bug causes it to skip on some lines
    # Check if NuGet package provider (>= 2.8.5.201) is installed
    $nugetProvider = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue -Force
    if (
        -not $nugetProvider -or
        $nugetProvider.Version -lt [Version]'2.8.5.201'
    ) {
        Write-Host "NuGet package provider not found or too old. Installing..." -ForegroundColor Yellow
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -ForceBootstrap -Force -Confirm:$false | Out-Null
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Installed NuGet package provider." | Out-File -FilePath $logFile -Append
    } else {
        Write-Host "NuGet package provider is already installed and up to date." -ForegroundColor Green
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] NuGet package provider is already installed and up to date." | Out-File -FilePath $logFile -Append
    }

    # Check if PSWindowsUpdate is installed
    if (-not (Get-Module PSWindowsUpdate -ListAvailable)) {
        Write-Host "PSWindowsUpdate module not found. Installing..." -ForegroundColor Yellow
        Install-Module -Name PSWindowsUpdate -Force -Confirm:$false | Out-Null
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Installed PSWindowsUpdate module." | Out-File -FilePath $logFile -Append
    } else {
        Write-Host "PSWindowsUpdate module already installed." -ForegroundColor Green
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] PSWindowsUpdate module already installed." | Out-File -FilePath $logFile -Append
    }

    # Import PSWindowsUpdate
    Import-Module PSWindowsUpdate
    Write-Host "PSWindowsUpdate module imported successfully." -ForegroundColor Green
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] PSWindowsUpdate module imported successfully." | Out-File -FilePath $logFile -Append

    # Check for Windows Updates
    Write-Host "Checking for Windows Updates..." -ForegroundColor Yellow
    $updates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot # | Out-Null
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Found $updateCount updates." | Out-File -FilePath $logFile -Append
    
    # Log the available updates
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] List of available Windows Updates:" | Out-File -FilePath $logFile -Append
    foreach ($update in $updates) {
        "Title: $($update.Title), KB: $($update.KBArticleID), Size: $([math]::Round($update.Size/1MB, 2)) MB" | Out-File -FilePath $logFile -Append
    }

    # Install any available updates
    if ($updates.Count -gt 0) {
        Write-Host "Installing Windows Updates..." -ForegroundColor Yellow
        # Runs updater to install all available Windows updates
        Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -NotTitle 'Windows 11, version 24H*' -Confirm:$false | Out-Null  # -AutoReboot
        Write-Host "All Windows Updates are completed." -ForegroundColor Green
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Successfully installed Windows Updates." | Out-File -FilePath $logFile -Append
        Write-Host "================================================================================"
    } else {
        Write-Host "No updates available." -ForegroundColor Green
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] No updates available." | Out-File -FilePath $logFile -Append
    }

    # Runs winget updater to install all available updates
    wingetUpdater

    Write-Host "All Updates are completed. Please restart and re-run to verify everything was installed." -ForegroundColor Green
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Completed Windows Updates installation." | Out-File -FilePath $logFile -Append

    Write-Host "================================================================================"

    # End logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Completed WindowsUpdaterPowerShell function." | Out-File -FilePath $logFile -Append
}

<# Brief:  Function will load winget to install all available updates.
    param:  N/A
    return: N/A
    Note: Questions, comments, or concerns, please contact David Tom (OTS)
#>
function wingetUpdater {
    # Begin logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting wingetUpdater function." | Out-File -FilePath $logFile -Append

    Write-Host "================================================================================"

    Write-Host "Running winget to update available applications..." -ForegroundColor Yellow
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Initiating winget updates." | Out-File -FilePath $logFile -Append

    $loggedInUser = whoami

    # Runs winget (Microsoft Store) to install all available updates (ie. Browsers)
    # Verify winget is updated and installed to a stable version
    $progressPreference = 'silentlyContinue'
    Write-Host "Verifying WinGet and its dependencies..." -ForegroundColor Yellow

    # Install winget and dependencies
    # Invoke-WebRequest -Uri https://aka.ms/getwinget -OutFile Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle | Out-Null
    # Invoke-WebRequest -Uri https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -OutFile Microsoft.VCLibs.x64.14.00.Desktop.appx | Out-Null
    # Invoke-WebRequest -Uri https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx -OutFile Microsoft.UI.Xaml.2.8.x64.appx | Out-Null
    # Add-AppxPackage Microsoft.VCLibs.x64.14.00.Desktop.appx -ErrorAction SilentlyContinue | Out-Null
    # Add-AppxPackage Microsoft.UI.Xaml.2.8.x64.appx -ErrorAction SilentlyContinue | Out-Null
    # Add-AppxPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle -ErrorAction SilentlyContinue | Out-Null
    
# Check if winget (Microsoft.DesktopAppInstaller) is installed for any user:
if (-not (Get-AppxPackage -Name "Microsoft.DesktopAppInstaller" -AllUsers)) {
    Write-Host "WinGet not installed. Installing now..." -ForegroundColor Yellow

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

    Write-Host "WinGet and its dependencies have been installed." -ForegroundColor Green
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Installed winget and dependencies." | Out-File -FilePath $logFile -Append
} else {
    Write-Host "WinGet is already installed." -ForegroundColor Green
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] winget is already installed." | Out-File -FilePath $logFile -Append
}

    # Log the output
    Write-Host "Successfully installed WinGet and dependencies." -ForegroundColor Green
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Successfully updated winget and dependencies." | Out-File -FilePath $logFile -Append

    # Update winget respositories
    winget source reset --force
    winget source update

    # Obtain a list of the available upgrades
    $upgradeListOutput = winget upgrade --silent --accept-source-agreements --accept-package-agreements --disable-interactivity | Out-String
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Applications available for upgrade via winget:" | Out-File -FilePath $logFile -Append
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
        foreach ($app in $wingetArrray) {
            Write-Host "Updating: $app"

            # Run winget to upgrade the applications in array
            $wingetOutput = winget upgrade --id $app --silent --accept-source-agreements --accept-package-agreements --disable-interactivity | Out-String
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Successfully upgraded $app using winget." | Out-File -FilePath $logFile -Append
        }
    # }

    Write-Host "================================================================================"

    # End logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Completed wingetUpdater function." | Out-File -FilePath $logFile -Append
}

<# Brief:  Function will compare the version of Microsoft Teams and update as needed.
    param:  N/A
    return: N/A
    Note: Questions, comments, or concerns, please contact David Tom (OTS)
#>
function VerifyClassicNewTeams {
    # Begin logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting VerifyClassicNewTeams function." | Out-File -FilePath $logFile -Append

    $versionToCompare = '24000.0.0' # Replace with the version you want to compare
    $teamsPath = Get-AppxPackage -Name 'Microsoft.Teams' | Select-Object -ExpandProperty InstallLocation
    $teamsVersion = (Get-AppPackage MSTeams).Version

    Write-Host "Verifying Microsoft Teams Version"

    # Check if Classic Teams is installed
    try {
        $classicInstalled = winget list | Select-String -Pattern "Classic"
    } catch {
        $classicInstalled = $false
        Write-Host "Error checking for Classic Teams installation: $_" -ForegroundColor Red
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Error checking for Classic Teams installation: $_" | Out-File -FilePath $logFile -Append
    }

    # Stop and Uninstall Classic Teams
    if ($classicInstalled) {
        try {
            Get-Process "Teams" -ErrorAction SilentlyContinue | Stop-Process
            winget Uninstall --silent --accept-source-agreements --all-versions --id Microsoft.Teams.Classic
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Uninstalled Classic Teams." | Out-File -FilePath $logFile -Append
        } catch {
            Write-Host "Error uninstalling Classic Teams: $_" -ForegroundColor Red
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Error uninstalling Classic Teams: $_" | Out-File -FilePath $logFile -Append
        }
    } else {
        Write-Host "Classic Teams is not installed on the device!" -ForegroundColor Green
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Classic Teams is not installed." | Out-File -FilePath $logFile -Append
    }

    # Compare New Teams Version
    try {
        if ([version]$teamsVersion -gt [version]$versionToCompare) {
            Write-Host "New Teams version is greater than $versionToCompare!" -ForegroundColor Green
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Microsoft Teams is up-to-date (version: $teamsVersion)." | Out-File -FilePath $logFile -Append
        } else {
            try {
                # Install and load the newest version of Microsoft Teams
                winget Install --silent --accept-source-agreements --id Microsoft.Teams
                Start-Process -File "$($env:USERProfile)\AppData\Local\Microsoft\Teams\Update.exe" -ArgumentList '--processStart "Teams.exe"'

                # Assign a shortcut to the desktop
                # $desktopPath = [System.IO.Path]::Combine($env:PUBLIC, 'Desktop')
                # $shortcutPath = [System.IO.Path]::Combine($desktopPath, 'Microsoft Teams.lnk')
                # $targetPath = 'C:\Users\david.tom\AppData\Local\Microsoft\Teams\current\Teams.exe'

                # $shell = New-Object -ComObject WScript.Shell
                # $shortcut = $shell.CreateShortcut($shortcutPath)
                # $shortcut.TargetPath = $targetPath
                # $shortcut.Save()

                Write-Host "Microsoft Teams has been updated to the latest version."
                "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Installed/Updated Microsoft Teams to the latest version." | Out-File -FilePath $logFile -Append
            } catch {
                Write-Host "Error installing/updating Microsoft Teams: $_" -ForegroundColor Red
                "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Error installing/updating Microsoft Teams: $_" | Out-File -FilePath $logFile -Append
            }
        }
    } catch {
        Write-Host "Error installing/updating Microsoft Teams: $_" -ForegroundColor Red
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Error installing/updating Microsoft Teams: $_" | Out-File -FilePath $logFile -Append
    }

    Write-Host "================================================================================"

    # End logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Completed VerifyClassicNewTeams function." | Out-File -FilePath $logFile -Append
}

<# Brief: Function will install Lenovo System Update or Lenovo Vantage based on the device model.
    param: N/A
    return: N/A
    Note: Questions, comments, or concerns, please contact David Tom (OTS)
#>
function LenovoSystemUpdateToVantage {
    # Obtain Model Name
    $modelName = (Get-ComputerInfo | Select-Object -ExpandProperty CsSystemFamily).Trim()
    
    if ($modelName -like "*ThinkBook*" -or $modelName -like "*9[^0]+0*" -or $modelName -like "*Idea*" -or $modelName -like "*V1*" -or $modelName -like "*Yoga*") {
        # Lenovo Commercial Vantage
        Write-Host "Uninstalling Lenovo Commercial Vantage..." -ForegroundColor Yellow
        winget uninstall --silent --accept-source-agreements --id 9NR5B8GVVM13
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Uninstalled Lenovo Commercial Vantage." | Out-File -FilePath $logFile -Append

        # Lenovo Vantage
        Write-Host "Installing Lenovo Vantage..." -ForegroundColor Yellow
        winget install --silent --accept-source-agreements --accept-package-agreements --id 9WZDNCRFJ4MV
        Start-Process "shell:AppsFolder\E046963F.LenovoCompanion_k1h2ywk1493x8!App"
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Installed Lenovo System Update." | Out-File -FilePath $logFile -Append
    } else {
        # Lenovo Commercial Vantage
        Write-Host "Installing Lenovo Commercial Vantage..." -ForegroundColor Yellow
        winget install --silent --accept-source-agreements --accept-package-agreements --id 9NR5B8GVVM13
        Start-Process "shell:AppsFolder\E046963F.LenovoSettingsforEnterprise_k1h2ywk1493x8!App"
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Installed Lenovo Commercial Vantage." | Out-File -FilePath $logFile -Append

        # Lenovo Vantage
        Write-Host "Uninstalling Lenovo Vantage..." -ForegroundColor Yellow
        winget uninstall --silent --accept-source-agreements --id 9WZDNCRFJ4MV
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Uninstalled Lenovo Vantage." | Out-File -FilePath $logFile -Append
        # Start-Process "shell:AppsFolder\E046963F.LenovoCompanion_k1h2ywk1493x8!App"
    }

    # Lenovo System Update
    # Write-Host "Uninstalling Lenovo System Update..." -ForegroundColor Yellow
    # winget uninstall --silent --accept-source-agreements --id Lenovo.SystemUpdate
    # "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Uninstalled Lenovo System Update." | Out-File -FilePath $logFile -Append
}

<# Brief:  Function will remove bloatware from the device.
    param:  N/A
    return: N/A
    Note: Questions, comments, or concerns, please contact David Tom (OTS)
#>
function RemoveBloat {
    # Begin logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting removeBloat function." | Out-File -FilePath $logFile -Append

    Write-Host "Removing bloatware..."

    $ADDomain = Get-ADDomain

    # Compare Apps to student or faculty device
#    if ($ADDomain -like '*Student*') {
#        Write-Host "Testing Firefox removal and PrintWise modification..." -ForegroundColor Yellow
#    } else {
        # Get-Process "Firefox" -ErrorAction SilentlyContinue | Stop-Process
        # winget Uninstall --silent --accept-source-agreements --all-versions --id Mozilla.Firefox
        
        # & "C:\Program Files\Mozilla Firefox\uninstall\helper.exe" /S
        # Define the path to the helper.exe
        $filePath = "C:\Program Files\Mozilla Firefox\uninstall\helper.exe"

        # Check if the file exists
        if (Test-Path -Path $filePath) {
            # If it exists, run it with the /S (silent) argument
            & $filePath /S
        } else {
            Write-Host "Firefox not installed on the device." -ForegroundColor Green
        }
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Firefox has been uninstalled on the device." | Out-File -FilePath $logFile -Append
#    }

    # Remove VLC Media Player
    $filePath = "C:\Program Files\VideoLAN\VLC\uninstall.exe"

    if (Test-Path -Path $filePath) {
        & $filePath /S
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] VLC Media Player has been uninstalled on the device." | Out-File -FilePath $logFile -Append
    } else {
        Write-Host "VLC Media Player not installed on the device." -ForegroundColor Green
    }

    # Remove 7zip if on 24H2
    # Get the version as a string directly
    $osVersion = (Get-ComputerInfo).OSDisplayVersion

    if ($osVersion -eq '24H2') {
        Write-Host "The OS version is 24H2. Uninstalling 7zip." -ForegroundColor Yellow
        winget Uninstall --silent --accept-source-agreements --all-versions --id 7zip.7zip
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] 7zip has been uninstalled on the 24H2 device." | Out-File -FilePath $logFile -Append
    } else {
        Write-Host "The OS version is not 24H2. It is: $osVersion"
    }

    # Microsoft Copilot
    Write-Host "Uninstalling Microsoft Copilot..." -ForegroundColor Yellow
    winget uninstall --silent --accept-source-agreements --id 9NHT9RB2F4HD
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Microsoft Copilot has been uninstalled on the device." | Out-File -FilePath $logFile -Append

    # Microsoft 365 Copilot
    Write-Host "Uninstalling Microsoft 365 Copilot..." -ForegroundColor Yellow
    winget uninstall --silent --accept-source-agreements --id 9WZDNCRD29V9
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Microsoft 365 Copilot has been uninstalled on the device." | Out-File -FilePath $logFile -Append

    # Microsoft Cortana
    Write-Host "Uninstalling Microsoft Cortana..." -ForegroundColor Yellow
    winget uninstall --silent --accept-source-agreements --id 9NFFX4SZZ23L
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Microsoft Cortana has been uninstalled on the device." | Out-File -FilePath $logFile -Append

    # Remove bloatware in the list
    foreach ($app in $bloatware) {
        # Get the package for the current user
        $package = Get-AppxPackage -Name $app -ErrorAction SilentlyContinue

        # Remove the package for the current user
        if ($package) {
            # Remove the package
            Remove-AppxPackage -Package $package.PackageFullName -ErrorAction SilentlyContinue
            Write-Host "Uninstalled bloatware: $app"
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Uninstalled bloatware: $app" | Out-File -FilePath $logFile -Append
        } else {
            Write-Host "Package not found or already removed: $app"
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Package not found or already removed: $app" | Out-File -FilePath $logFile -Append
        }

        # Get the provisioned package for all users
        $provisionedPackage = Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq $app}

        # Remove provisioned package for all users
        if ($provisionedPackage) {
            Write-Host "Removing provisioned package: $app"
            Remove-AppxProvisionedPackage -Online -PackageName $provisionedPackage.PackageName -ErrorAction SilentlyContinue
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Removed provisioned package: $app" | Out-File -FilePath $logFile -Append
        }
    }

    # End logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Completed removeBloat function." | Out-File -FilePath $logFile -Append
}

<# Brief:  Function will open device manager and install any missing drivers.
    param:  N/A
    return: N/A
    Note: Questions, comments, or concerns, please contact David Tom (OTS)
#>
function VerifyAndDriverUpdater {
    # Begin logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting VerifyAndDriverUpdater function." | Out-File -FilePath $logFile -Append

    # Load device manager to manually inspect any missing drivers
    devmgmt
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Opened Device Manager for manual inspection." | Out-File -FilePath $logFile -Append

    # Attempt to update drivers for devices with issues
    # Get-PnpDevice | Where-Object { $_.Status -eq 'Error' } | ForEach-Object {
    #     try {
    #         $_ | Update-PnpDeviceDriver -Confirm:$false
    #         Write-Host "Successfully updated driver for device:"
    #         "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Successfully updated driver for device: $($device.Name)" | Out-File -FilePath $logFile -Append
    #     } catch {
    #         $errorMessage = $_.Exception.Message
    #         Write-Host "Failed to update driver for device: $($device.Name). Error: $errorMessage" -ForegroundColor Red
    #         "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Failed to update driver for device: $($device.Name). Error: $errorMessage" | Out-File -FilePath $logFile -Append
    #     }

    # Write-Host "Device ID: $($_.DeviceID)"
    # Write-Host "Status: $($_.Status)"
    # Write-Host "Name: $($_.Name)"
    # Write-Host "Class: $($_.Class)"
    # }

    # End logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Completed VerifyAndDriverUpdater function." | Out-File -FilePath $logFile -Append
}

# Verify Apps are installed on the device
function Get-ADDomain {
    $ADDomain = (Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty Domain).Trim()
    return $ADDomain
}

<# Brief:  Function will call the appropriate functions to verify the device image.
    param:  N/A
    return: N/A
    Note: Questions, comments, or concerns, please contact David Tom (OTS)
#>
function MainFunction {
    # Clear the screen and prep the device for post checks
    clear

    # Store the user's choice as Quick or Full
    $userChoice = UserSelection

    # Log File Path
    $hostname = hostname
    # Deprecated: $serialNumber = (wmic bios get serialnumber | Select-Object -Skip 1 | Where-Object { $_ -ne "" }).Trim()
    $serialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
    $logFile = "\\cyapsft01\software\postChecks\logs\$hostname $serialNumber\postChecks-log_$([Environment]::UserName)_$(Get-Date -Format 'yyyyMMdd_HHmmss')_$serialNumber_$hostname.log"
    $loggedInUser = whoami

    # Ensure the Logs directory exists
    $logDir = Split-Path -Parent $logFile
    if (!(Test-Path -Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force
    }

    # Start logging
    $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "Script started at $stamp by $loggedInUser for SN: $serialNumber DN: $hostname." | Out-File -FilePath $logFile -Append

    # Stage 1: Start Post Checks
    # If user is "me" then ignore acknowledgement
    if ($loggedInUser -ne "csn\david.tom") {
        UserAcknowledgement
    } else {
        Write-Host "Post Checks loading..."
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Post Checks loading..." | Out-File -FilePath $logFile -Append
    }

    # Function to get the asset tag
    $assetTag = (Get-WmiObject -Class Win32_SystemEnclosure | Select-Object -ExpandProperty SMBiosAssetTag).Trim()

    # Experimental: Verify Asset Tag is Valid
    # Do not use except on test machines
    if ($loggedInUser -eq "csn\david.tom" -or $loggedInUser -eq "csn\alexis.winn" -and $assetTag -eq "") {
        VerifyAndFlashAssetTag
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Called VerifyAndFlashAssetTag function." | Out-File -FilePath $logFile -Append
    } else {
        Write-Host "Manually verify and flash asset tag..."
    }

    # Verify Power Settings
    powerSettings

    # Verify Device Information
    Write-Host "Starting Post Checks for: "
    Write-DeviceInformationHeader

    # If the user selects Quick, skip the Windows Update Cache removal
    if ($userChoice -eq "Full") {
        # Remove Windows Update Cache
        Write-Host "Removing Windows Update Cache... Please wait ~3 minutes." -ForegroundColor Yellow
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Removing Windows Update Cache..." | Out-File -FilePath $logFile -Append

        # Stop the Windows Update service to prevent the directory from being locked
        net stop wuauserv
        net stop bits
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Stopped Windows Update service." | Out-File -FilePath $logFile -Append

        # Take ownership of the SoftwareDistribution folder
        takeown /f "C:\Windows\SoftwareDistribution\Download" /r /d y | Out-Null
        icacls "C:\Windows\SoftwareDistribution\Download" /reset /T | Out-Null
        icacls "C:\Windows\SoftwareDistribution\Download" /grant Administrators:F /T | Out-Null
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Took ownership of the SoftwareDistribution folder." | Out-File -FilePath $logFile -Append

        # Remove the contents of the SoftwareDistribution folder
        Remove-Item -Path "C:\Windows\SoftwareDistribution\Download\" -Recurse -Include *.* -Force -ErrorAction SilentlyContinue
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Removed contents of the SoftwareDistribution folder." | Out-File -FilePath $logFile -Append

        # Start the Windows Update service
        net start wuauserv
        net start bits
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Started Windows Update service." | Out-File -FilePath $logFile -Append

        # Additional logging for main function
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Initiated device information header." | Out-File -FilePath $logFile -Append
    } else {
        Write-Host "Skipping Windows Update Cache removal..." -ForegroundColor Green
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Skipping Windows Update Cache removal." | Out-File -FilePath $logFile -Append
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
        Write-Host "Error: Office Updater failed!"
    }

    ####################### Verification and Policy Updates #######################

    # Stage 4: Open Control Panel Actions
    # Notes: If Automation Fails - Manually Open Control Panel - 
    #                            - Large Buttons - Configuration Manager - Actions
    sccmModifications

    # Stage 5: Run Group Policy and Windows Update
    gpupdate /force
    Write-Host "================================================================================"

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

    LenovoSystemUpdateToVantage

    Write-Host "Uninstalling VLC Media Player..." -ForegroundColor Yellow
    winget uninstall --silent --accept-source-agreements --id VideoLAN.VLC
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Uninstalled VLC Media Player." | Out-File -FilePath $logFile -Append

    # Remove Bloatware
    RemoveBloat

    Write-Host "================================================================================"

    if ($userChoice -eq "Full") {
        # Stage 9: Run Disk Cleanup
        # Example: Turn on 'all items' for SageSet ID 1
        $VolumeCaches = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"

        Get-ChildItem -Path $VolumeCaches | ForEach-Object {
            # For each cache item, set the StateFlags0001 value to 2 (enabled)
            Set-ItemProperty -Path $_.PsPath -Name "StateFlags0001" -Value 2 -ErrorAction SilentlyContinue
        }

        Start-Process -FilePath "Cleanmgr.exe" -ArgumentList "/sagerun:1" -NoNewWindow
        Write-Host "Disk Cleanup has been run..." -ForegroundColor Green

        # Stage 10: Verify Windows Integrity
        Write-Host "Running Windows Integrity Check via SFC & DISM, please wait roughly 5 minutes..." -ForegroundColor Yellow
        sfc /scannow
        Dism /Online /Cleanup-image /ScanHealth 
        Dism /Online /Cleanup-image /CheckHealth 
        Dism /Online /Cleanup-image /RestoreHealth 
        Dism /Online /Cleanup-image /StartComponentCleanup 
    } else {
        Write-Host "Skipping Disk Cleanup and Windows Integrity Check..." -ForegroundColor Green
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Skipping Disk Cleanup and Windows Integrity Check." | Out-File -FilePath $logFile -Append
    }

    # Stage 11: Open Windows Update - Manually inspect as needed
    # start ms-settings:windowsupdate

    Write-Host "================================================================================"

    # Stage 12: Load Large Programs (ie. Creative Cloud & System Updater)
    VerifyLargerApps

    Write-Host "================================================================================"

    # Stage 13: Open Device Manager - Visually Verify Drivers & Apps and Update as Needed
    VerifyAndDriverUpdater
    Write-Host "================================================================================"

    # Stage 14: Redundantly Enables Memory Integrity & Reputation Protection
    # https://chatgpt.com/c/67338fdc-113c-8010-9f10-6c6185178723
    # Get-MpPreference | Select-Object -Property PUAProtection
    Write-Host "Enabling Memory Integrity & Reputation Protection..." -ForegroundColor Yellow
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\' -Name 'Enabled' -Value 1 -Force   # 0 Disables, 1 Enables 
    Set-MpPreference -PUAProtection Enabled

    Write-Host "Finalized Post Checks for: "
    Write-DeviceInformationHeader
        
    $ADDomain = Get-ADDomain

    Write-Host "================================================================================"

    # Compare Apps to student or faculty device
    if ($ADDomain -like '*Student*') {
        Write-Host "Verifying Student Apps..." -ForegroundColor Yellow
        VerifyInstalledApps -appArray $studentAppArray
        winget uninstall --silent --accept-source-agreements --id 9WZDNCRDJ8LH    # Cisco Secure Client - AnyConnect
        winget uninstall --silent --accept-source-agreements --id 9NBLGGH16P7H    # Hyland OnBase
    } else {
            Write-Host "Verifying Faculty Apps..." -ForegroundColor Yellow
        VerifyInstalledApps -appArray $facultyAppArray
    }

    # Final logging
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Script execution completed. Starting reboot sequence." | Out-File -FilePath $logFile -Append

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
    @{ Path = $registryArray[1]; Name = "TaskbarDa"; Value = 0 },                  # Remove Widgets
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
Write-Host "Device will automatically reboot in 5 minutes..." -ForegroundColor Green
Start-Sleep -Seconds 300
Restart-Computer -Force

# EOF: postChecks.ps1
