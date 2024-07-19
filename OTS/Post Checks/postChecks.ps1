###############################################################################
# Author: David Tom                                                           #
# Date:   July 3, 2024                                                        #
# Edit:   July 5, 2024  - Reformatted for readability                         #
# Edit:   July 10, 2024 - Added if-else statements                            #
# Edit:   July 16, 2024 - Added snippet to obtain serial number               #
# Edit:   July 19, 2024 - Modified try-catch and automation                   #
# File:   postChecks.ps1                                                      #
# Brief:  This Windows 11 PowerShell script will open the programs needed to  #
#         update during a device's post checks. It will also attempt to       #
#         modify any applicable settings and registry keys as per CSN's OTS   #
#         imaging requirements.                                               #
###############################################################################
# TODO:   1. Modify if-else statements with variables/lists to store success  #
#         and failures to be output at the end of the program execution.      #
#         2. Receive updates for other Microsoft products.                    #
###############################################################################

######################## Variable & Array Declarations ########################

$majorArray = @(
    'C:\Program Files\Adobe\Adobe Creative Cloud\ACC\Creative Cloud.exe'
    # Manual (if required): 'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE'
    # Automated: 'C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe'
    # Automation: https://jantari.github.io/LSUClient-docs/
    'C:\Program Files (x86)\Lenovo\System Update\tvsu.exe'
)

$browserArray = @(
    'C:\Program Files\Google\Chrome\Application\chrome.exe'
    'C:\Program Files\Mozilla Firefox\firefox.exe'
    'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
)

$registryArray = @(
    'HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot'
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'
)

$SCCMActions = @(   "{00000000-0000-0000-0000-000000000121}",  # Application Deployment Evaluation Cycle
                    "{00000000-0000-0000-0000-000000000003}",  # Discovery Data Collection Cycle
                    "{00000000-0000-0000-0000-000000000010}",  # File Collection Cycle
                    "{00000000-0000-0000-0000-000000000001}",  # Hardware Inventory Cycle
                    "{00000000-0000-0000-0000-000000000021}",  # Machine Policy Retrieval & Evaluation Cycle
                    "{00000000-0000-0000-0000-000000000002}",  # Software Inventory Cycle
                    "{00000000-0000-0000-0000-000000000031}",  # Software Metering Usage Report Cycle
                    "{00000000-0000-0000-0000-000000000027}",  # User Policy Retrieval & Evaluation Cycle
                    "{00000000-0000-0000-0000-000000000032}"   # Windows Installer Source List Update Cycle
)

############################ Initialize and Setup #############################

# Stage 1: Disable Copilot
# Registry Key: Computer\HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsCopilot set to 0 for off, 1 for on
Set-ItemProperty -Path $registryArray[0] -Name TurnOffWindowsCopilot -Value 0 -Force

# Stage 2: Modify Taskbar Settings
# Notes: If Automation fails - Manually Disable Copilot for Local Users on Local Group Policy
# Group Policy - User Configurations - Administrative Templates - Windows Components - Windows Copilot - Edit and Enable to Stop
# gpedit:Administrative Templates
# https://github.com/Ccmexec/PowerShell/blob/master/Customize%20TaskBar%20and%20Start%20Windows%2011/CustomizeTaskbar.ps1
# Registry Key: Computer\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced

#   Stage 2.1: Left Align Menu       - Set to 0 for left, 1 for middle
Set-ItemProperty -Path $registryArray[1] -Name TaskbarAl -Value 0 -Force

#   Stage 2.2: Remove Copilot Button - Set to 0 for off, 1 for on
Set-ItemProperty -Path $registryArray[1] -Name ShowCopilotButton -Value 0 -Force

#   Stage 2.3: Remove Task View      - Set to 0 for off, 1 for on
Set-ItemProperty -Path $registryArray[1] -Name ShowTaskViewButton -Value 0 -Force

#   Stage 2.4: Remove Widgets        - Set to 0 for off, 1 for on
Set-ItemProperty -Path $registryArray[1] -Name TaskbarDa -Value 0 -Force

#   Stage 2.5: Remove Search Highlights - Set to 0 for off, 1 for on
# Computer\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SearchSettings
Set-ItemProperty -Path $registryArray[2] -Name IsDynamicSearchBoxEnabled -Value 0 -Force

################################ Major Updates ################################

# Stage 3: Load any programs or settings that have a long update time
foreach ( $node in $majorArray) {
    if (Test-Path $node) {
        try {
            Start-Process -FilePath $node
            Write-Host "[$node] is attempting to load..."
        } catch {
            Write-Host "Error: Issue found with loading [$node]!"
        }
    } else {
        "Failure - [$node] was not found!"
    }
}

# Stage 3.1: Microsoft Word Update Automation
# Silent Automation: /update user displaylevel=false forceappshutdown=true
& "C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe" /update user

# Stage 4: Open Windows Update
start ms-settings:windowsupdate

# Experimental: Requires Tools to Automate (PSWindowsUpdate)
# Install-Module -Name PSSWindowsUpdate -Force
# Import-Module PSWindowsUpdate
# Get-WindowsUpdate
# Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot

############################### Browser Updates ###############################

# Stage 5: Open all browsers to verify and update as needed
foreach ( $node in $browserArray ) {
    if (Test-Path $node) {
        Start-Process -FilePath $node
        Write-Host "$node is attempting to load..."
    } else {
        "Failure - $node was not found!"
    }
}

####################### Verification and Policy Updates #######################

# Stage 6: Open Control Panel Actions
# Notes: If Automation Fails - Manually Open Control Panel - 
#                            - Large Buttons - Configuration Manager - Actions
# Start-Process 'control'
control smscfgrc

# Experimental: SCCM Actions - Verify visually that all actions exist on Control Panel
# https://www.anoopcnair.com/trigger-sccm-client-agent-actions-powershell/
foreach ($action in $SCCMActions) {
    try {
        Write-Host "Invoking SCCM Action: $action"
        Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule $action
    } catch {
        Write-Host "Error: $action could not be found!"
    }
}

# Stage 7: Run Group Policy Update
gpupdate /force

# Stage 8: Open Device Manager - Drivers
devmgmt

# # List all devices with missing drivers
#Get-PnpDevice | Where-Object { $_.Status -eq 'Error' }
# Attempt to update drivers for devices with issues
#Get-PnpDevice | Where-Object { $_.Status -eq 'Error' } | ForEach-Object {
#    $_ | Update-PnpDeviceDriver -Confirm:$false
#}


# Stage 9: Obtain Serial Number
wmic bios get serialnumber

# Stage 10: Obtain Hostname
Write-Host "Hostname"
Invoke-Expression -Command 'hostname'

# Stage 11: Obtain Asset Tag - https://www.reddit.com/r/AskGreg/comments/2yu0dq/powershell_get_asset_tag_from_bios/
Write-Host "Asset Tag"
(Get-WmiObject -Class Win32_SystemEnclosure | Select-Object SMBiosAssetTag).SMBiosAssetTag

################################## REMINDERS ##################################
# 1. Flash Asset Tags as needed
# 2. Verify RMM Datto Client
# 3. Verify Apps Installed for Faculty/Staff & Student Devices
# 4. Pin File Explorer to Task Bar
# 5. Win+X Task Manager/Terminal Admin
###############################################################################

# Stage 10: Exit the terminal
# Uncomment to run the script and exit the terminal
# exit

# EOF: postChecks.ps1