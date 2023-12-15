
function Write-ToETW {
    
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True,ValuefromPipeline=$True)]
        [PSObject[]]$scanResult
    )
          
    Process {

        $techniqueMapping = @{
            "Registry Run Key"="WriteRunAndRunOnce"
            "Registry RunEx Key"="WriteRunAndRunOnce"
            "Registry RunOnce Key"="WriteRunAndRunOnce"
            "Registry RunOnceEx Key"="WriteRunAndRunOnce"
            ".NET Startup Hooks DLL Sideloading" = "WriteDotNetStartupHooks"
            "Accessibility Tools Backdoor" = "WriteAccessibilityTools"
            "AEDebug Custom Debugger" = "WriteAeDebug"
            "App Paths" = "WriteAppPaths"
            "AppCertDlls" = "WriteAppCertDlls"
            "AutodialDLL Winsock Injection" = "WriteAutodialDLL"
            "BITS Job NotifyCmdLine" = "WriteBitsJobsNotifyCmdLine"
            "CHM Helper DLL" = "CHMHelperDll"
            "Command Processor AutoRun key"="WriteCmdAutoRun"
            "DbgManagedDebugger Custom Debugger" = "WriteDotNetDebugger"
            "DSRM Backdoor"="WriteDSRMBackdoor"
            "ErrorHandler.cmd Hijacking" = "WriteErrorHandlerCmd"
            "Explorer Load Property"="WriteExplorerLoad"
            "Explorer Tools Hijacking"="WriteExplorerTools"
            "Fake AMSI Provider" = "WriteAMSIProviders"
            "Group Policy Extension DLL"="WriteGPExtensionDlls"
            "Hijacking of hhctrl.ocx"="WriteHHCtrlHijacking"
            "Image File Execution Options"="WriteImageFileExecutionOptions"
            "LSA Authentication Package DLL"="WriteLsaAuthenticationPackages"
            "LSA Extensions DLL"="WriteLsaExtensions"
            "LSA Password Filter DLL"="WriteLsaPasswordFilter"
            "LSA Security Package DLL"="WriteLsaSecurityPackages"
            "Microsoft Office AI.exe Hijacking"="WriteMicrosoftOfficeAIHijacking"
            "Natural Language Development Platform 6 DLL Override Path"="WriteNLDPDllOverridePath"
            "Office Application Startup"="WriteOfficeTemplates"
            "Power Automate"="WritePowerAutomate"
            "Powershell Profile"="WritePowershellProfiles"
            "RDP WDS Startup Programs"="WriteRDPWDSStartupPrograms"
            "RID Hijacking"="WriteRidHijacking"
            "Scheduled Task"="WriteScheduledTasks"
            "ServerLevelPluginDll DNS Server DLL Hijacking"="WriteServerLevelPluginDll"
            "Service Control Manager Security Descriptor Manipulation"="WriteServiceControlManagerSD"
            "ServiceDll Hijacking"="WriteServiceDlls"
            "Silent Process Exit Monitor"="WriteSilentExitMonitor"
            "Startup Folder"="WriteStartupPrograms"
            "Suborner Attack"="WriteSubornerAttack"
            "Suspicious Screensaver Program"="WriteScreensaver"
            "Telemetry Controller Command"="WriteTelemetryController"
            "Terminal Services InitialProgram"="WriteTerminalServicesInitialProgram"
            "User Init Mpr Logon Script"="WriteUserInitMprScript"
            "Windows Error Reporting Debugger"="WriteWerFaultHangs"
            "Windows Error Reporting ReflectDebugger"="WriteWerFaultHangs"
            "Windows Service"="WriteWindowsServices"
            "Windows Terminal startOnUserLogin"="WriteTerminalProfileStartOnUserLogin"
            "Winlogon MPNotify Executable"="WriteWinlogonMPNotify"
            "Winlogon Notification Package"="WriteWinlogonNotificationPackages"
            "Winlogon Shell Property"="WriteWinlogonShell"
            "Winlogon Userinit Property"="WriteWinlogonUserinit"
            "WMI Event Subscription"="WriteWMIEventsSubscrition"
            "Wow6432Node AEDebug Custom Debugger"="WriteAeDebug"
            "Wow6432Node DbgManagedDebugger Custom Debugger"="WriteDotNetDebugger"
        }
    
        # Load the C# code
        Add-Type -Path "C:\PersistenceSniper\Modules\ETWLib.dll"
        
        
        foreach($result in $scanResult) {
            $expression = [string]::Format('[PersistenceSniper.ETWLib.PersistenceSniperEventSource]::Log.{0}("{1}","{2}","{3}","{4}","{5}","{6}","{7}","{8}","{9}","{10}","{11}","{12}")',
            $techniqueMapping[$result.Technique],
            "", 
            $result.Technique , 
            $result.Classification,
            $($result.Path  -replace '\\', '`\\'),
            $($result.Value -replace '"', '`"' -replace '\$', '`$'), # Escape double quotes
            $result."Access Gained",
            $result.Note,
            $result.Reference,
            $result.Signature ,
            $result.IsBuiltinBinary, 
            $result.IsLolbin, 
            $result.VTEntries)
        
            Invoke-Expression $expression
        }
    }
}