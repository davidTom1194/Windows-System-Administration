###############################################################################
# Author: David Tom                                                           #
# Date:   July 17, 2024                                                       #
# File:   bulkLogin.ps1                                                       #
# Brief:  This Windows 11 PowerShell script will attempt to load the Remote   #
#         Desktop for each computer in a bulk location such as a classroom.   #
###############################################################################
# TODO:   1.                                                                  #
###############################################################################

# Prompt the user for the computer name prefix
$prefix = Read-Host -Prompt "Enter the computer name prefix (ie. LHNC202-): "

# Prompt the user for the number of computers
$numComputers = Read-Host -Prompt "Enter the range of the computers (ie. 4-12): "
$range = $numComputers -split '-'
$startNumber = [int]$range[0]
$endNumber = [int]$range[1]

# Prompt the user for remote PowerShell credentials
# $credential = Get-Credential -Message "Enter your credentials for remote PowerShell session: "

# Path to the PowerShell script you want to run remotely
$scriptPath = "C:\Users\david.tom\OneDrive - College of Southern Nevada\OTS\Post Checks Scripts\postChecks.ps1"

# Loop through the number of computers and load Remote Desktop for login
for ($i = $startNumber; $i -le $endNumber; $i++) {
    # Format the computer name with the leading zeros as needed
    $computerName = "{0}{1:D2}" -f $prefix, $i

    # Load the remote device with Remote Desktop on the host computer
    Start-Process -FilePath "C:\WINDOWS\system32\mstsc.exe" -ArgumentList "/v:$computerName"
    Write-Host "Attempting to connect to $computerName via Remote Desktop"

    # TODO: Run the Post Checks script on the remote device
    # try {
    #     $session = New-PSSession -ComputerName $computerName -Credential $credential
    #     Invoke-Command -Session $session -FilePath $scriptPath
    #     Write-Host "Attempting to run postChecks.ps1 on $computerName..."
    #     Remove-PSSession -Session $session
    # } catch {
    #     Write-Host "Failed to run postChecks.ps1 on $computerName!"
    # }
}

# Exit the terminal
# Uncomment to run the script and exit the terminal
# exit

# EOF: bulkLogin.ps1