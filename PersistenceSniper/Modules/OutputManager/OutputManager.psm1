function Write-Log {

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("CSV", "JSON", "EVENT")]
        [string]$LogType,
  
        [Parameter(Mandatory = $true)]
        [string]$Destination,
  
        [Parameter(Mandatory = $true)]
        [Collections.ArrayList]$Results
    ) 
    
  
    Begin {
        $EventIDMapping = @{
            'Registry Run Key'                                          = $null
            'Registry RunOnce Key'                                      = $null
            'Image File Execution Options'                              = $null
            'Natural Language Development Platform 6 DLL Override Path' = $null
            'AEDebug Custom Debugger'                                   = $null
            'Wow6432Node AEDebug Custom Debugger'                       = $null
            'Windows Error Reporting Debugger'                          = $null
            'Windows Error Reporting ReflectDebugger'                   = $null
            'Command Processor AutoRun key'                             = $null
            'Explorer Load Property'                                    = $null
            'Winlogon Userinit Property'                                = $null
            'Winlogon Shell Property'                                   = $null
            'Windows Terminal startOnUserLogin'                         = $null
            'AppCertDlls'                                               = $null
            'App Paths'                                                 = $null
            'ServiceDll Hijacking'                                      = $null
            'Group Policy Extension DLL'                                = $null
            'Winlogon MPNotify Executable'                              = $null
            'CHM Helper DLL'                                            = $null
            'Hijacking of hhctrl.ocx'                                   = $null
            'Startup Folder'                                            = $null
            'User Init Mpr Logon Script'                                = $null
            'AutodialDLL Winsock Injection'                             = $null
            'LSA Extensions DLL'                                        = $null
            'ServerLevelPluginDll DNS Server DLL Hijacking'             = $null
            'LSA Password Filter DLL'                                   = $null
            'LSA Authentication Package DLL'                            = $null
            'LSA Security Package DLL'                                  = $null
            'Winlogon Notification Package'                             = $null
            'Explorer Tools Hijacking'                                  = $null
            'DbgManagedDebugger Custom Debugger'                        = $null
            'Wow6432Node DbgManagedDebugger Custom Debugger'            = $null
            'ErrorHandler.cmd Hijacking'                                = $null
            'WMI Event Subscription'                                    = $null
            'Windows Service'                                           = $null
            'Power Automate'                                            = $null
            'Terminal Services InitialProgram'                          = $null
            'Accessibility Tools Backdoor'                              = $null
            'Fake AMSI Provider'                                        = $null
            'Powershell Profile'                                        = $null
            'Silent Process Exit Monitor'                               = $null
            'Telemetry Controller Command'                              = $null
            'RDP WDS Startup Programs'                                  = $null
            'Scheduled Task'                                            = $null
            'BITS Job NotifyCmdLine'                                    = $null
            'Suspicious Screensaver Program'                            = $null
            'Office Application Startup'                                = $null
            'Service Control Manager Security Descriptor Manipulation'  = $null
            'Microsoft Office AI.exe Hijacking'                         = $null
        }
  
        # Collect the keys in a separate list
        $keys = $EventIDMapping.Keys | ForEach-Object { $_ }
  
        $i = 1000
        foreach ($key in $keys) {
            $EventIDMapping[$key] = $i
            $i++
        }
    }
  
    Process {
        switch ($LogType) {
            "CSV" {
                $Results |
                Export-Csv $Destination -NoTypeInformation
  
            }
            "JSON" {
                $Results | 
                ConvertTo-Json | Out-File $Destination
            }
            "EVENT" {
                $evtlog = "Application"
                $source = "PersistenceSniper"
          
  
                if ([System.Diagnostics.EventLog]::SourceExists($source) -eq $false) {
                    [System.Diagnostics.EventLog]::CreateEventSource($source, $evtlog)
                }
  
                foreach ($result in $Results) {
                    $evtID = $EventIDMapping[$result.technique]
                    $id = New-Object System.Diagnostics.EventInstance($evtID, 1); # Info Event
                    $propertiesValue = $result.PSObject.Properties | Select-Object -ExpandProperty Value
                    $evtObject = New-Object System.Diagnostics.EventLog;
                    $evtObject.Log = $evtlog;
                    $evtObject.Source = $source;
                    $propertiesValue = $result.PSObject.Properties | Select-Object -ExpandProperty Value
                    $evtObject.WriteEvent($id, $propertiesValue)
                }
                
            }
  
        }
    }
}
  