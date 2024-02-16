# Define the URL and the local file path
$url = "https://go.microsoft.com/fwlink/?linkid=2120843"
$filePath = "C:\temp\winsdksetup.exe"
$sdkDirectory = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64"

Write-Host "Checking for existing Windows SDK installation..."

# Check if the SDK is already installed
if(Test-Path -Path $sdkDirectory) {
    Write-Host "Windows SDK is already installed, no action required."
} else {
    Write-Host "Windows SDK not found, initiating download and installation..."

    # Create the download directory if it doesn't exist
    if(!(Test-Path -Path "C:\temp")) {
        Write-Host "Creating directory..."
        New-Item -ItemType Directory -Path "C:\temp"
    }

    Write-Host "Downloading the file..."

    # Download the file
    Invoke-WebRequest -Uri $url -OutFile $filePath

    Write-Host "Running the installer..."

    # Run the installer
    Start-Process -FilePath $filePath -ArgumentList "/features OptionId.SigningTools OptionId.UWPManaged OptionId.UWPCPP OptionId.DesktopCPPx86 OptionId.DesktopCPPx64 /quiet" -Wait -NoNewWindow

    Write-Host "Checking and updating the System PATH environment variable..."

    # Add the new path to the System PATH environment variable
    $envPath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    $newPath = $sdkDirectory

    if(!$envPath.Contains($newPath)) {
        Write-Host "Adding new path to the System PATH environment variable..."
        [System.Environment]::SetEnvironmentVariable("Path", $envPath + ";" + $newPath, "Machine")
    }

    Write-Host "Removing the temp directory..."
    Remove-Item -Path "C:\temp" -Force -Recurse

    Write-Host "Rebooting the computer..."

    # Restart the computer
    Restart-Computer -Force
}
