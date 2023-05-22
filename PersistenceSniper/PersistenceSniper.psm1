<#PSScriptInfo

    .VERSION 1.12.0

    .GUID 3ce01128-01f1-4503-8f7f-2e50deb56ebc

    .AUTHOR Federico @last0x00 Lagrasta

    .DESCRIPTION This module tries to enumerate all the persistence methods implanted on a compromised machine. New techniques may take some time before they are implemented in this script, so don't assume that because the module didn't find anything the machine is clean.

    .COMPANYNAME @APTortellini

    .COPYRIGHT Commons Clause

    .TAGS Windows Persistence Detection Blue Team

    .LICENSEURI https://github.com/last-byte/PersistenceSniper/blob/main/LICENSE

    .PROJECTURI https://github.com/last-byte/PersistenceSniper

    .ICONURI https://github.com/last-byte/PersistenceSniper/blob/main/resources/persistencesniper2.png

    .EXTERNALMODULEDEPENDENCIES

    .REQUIREDSCRIPTS

    .EXTERNALSCRIPTDEPENDENCIES

    .RELEASENOTES
    This release fixes a bug in the OutputCSV parameter, which up to version 1.11.0 would included false positives filtered out by the DiffCSV parameter, as well as implementing support for logging the output of the tool to the Windows Event Log.

    .PRIVATEDATA

#>

#Requires -RunAsAdministrator

function Find-AllPersistence
{ 
  <#
      .SYNOPSIS
      Find-AllPersistence is PersistenceSniper's main function. All the other functions defined in it are used by Find-AllPersistence to gather information on potential persistence techniques implanted on the machines PersistenceSniper is run on.

      .DESCRIPTION
      Enumerate all the persistence methods found on a machine and print them for the user to see.

      .PARAMETER PersistenceMethod
      Optional, choose a single persistence method to check for. Default value is All.

      .PARAMETER ComputerName
      Optional, an array of computernames to run the script on.

      .PARAMETER DiffCSV
      Optional, a CSV file to be taken as input and used to exclude from the output all the local persistences which match the ones in the CSV file itself. 

      .PARAMETER IncludeHighFalsePositivesChecks
      Optional, a switch which forces PersistenceSniper to also call a number of functions with checks which are more difficult to filter and in turn cause a lot of false positives.
	    
      .PARAMETER OutputCSV
      Optional, a CSV file to be used as output which will contain all the findings in a CSV format. 

      .EXAMPLE
      Find-AllPersistence
      Enumerate low false positive persistence techniques implanted on the local machine.
      
      .EXAMPLE
      Find-AllPersistence -PersistenceMethod RunAndRunOnce
      Enumerate only persistence techniques implanted on the local machine relying on the Run and RunOnce registry keys.

      .EXAMPLE
      $Persistences = Find-AllPersistence
      Enumerate low false positive persistence techniques implanted on the local machine and save them in Powershell variable for later processing.

      .EXAMPLE
      Find-AllPersistence -OutputCSV .\persistences.csv
      Enumerate low false positive persistence techniques implanted on the local machine and output to a CSV.

      .EXAMPLE
      Find-AllPersistence -LogFindings
      Enumerate low false positive persistence techniques implanted on the local machine and log results to the Windows Event Log.

      .EXAMPLE
      Find-AllPersistence -DiffCSV .\persistences.csv
      Enumerate low false positive persistence techniques implanted on the local machine but show us only the persistences which are not in an input CSV.

      .EXAMPLE
      Find-AllPersistence -DiffCSV .\persistences.csv -OutputCSV .\newPersistences.csv
      Enumerate low false positive persistence techniques implanted on the local machine but show us only the persistences which are not in an input CSV named persistences.csv and output the results on another CSV named newPersistences.csv.

      .EXAMPLE
      Find-AllPersistence -ComputerName @('dc1.macrohard.lol', 'dc2.macrohard.lol') -IncludeHighFalsePositivesChecks -DiffCSV .\persistences.csv -OutputCSV .\findings.csv
      Enumerate all persistence techniques implanted on an array of remote machines but show only the persistences which are not in an input CSV and output the findings on a CSV.

      .EXAMPLE
      Find-AllPersistence -ComputerName (Get-Content computers.txt) -IncludeHighFalsePositivesChecks -DiffCSV .\persistences.csv -OutputCSV .\findings.csv
      Enumerate all persistence techniques implanted on an array of remote machines retrieved from a file containing one hostname per line but show only the persistences which are not in an input CSV and output the findings on a CSV.

      .EXAMPLE
      Find-AllPersistence -DiffCSV .\persistences.csv -OutputCSV .\findings.csv | Where-Object Classification -Like "MITRE ATT&CK T*"
      Enumerate all persistence techniques implanted on the local machine, filter out the ones in the persistences.csv file, save the results in findings.csv and output to console only the persistences which are classified under the MITRE ATT&CK framework.
  #>
  
  Param(
    [Parameter(Position = 0)]
    [ValidateSet(
        'All',    
        'RunAndRunOnce',
        'ImageFileExecutionOptions',
        'NLDPDllOverridePath',
        'AeDebug',
        'WerFaultHangs',
        'CmdAutoRun',
        'ExplorerLoad',
        'WinlogonUserinit',
        'WinlogonShell',
        'TerminalProfileStartOnUserLogin',
        'AppCertDlls',
        'ServiceDlls',
        'GPExtensionDlls',
        'WinlogonMPNotify',
        'CHMHelperDll',
        'HHCtrlHijacking',
        'StartupPrograms',
        'UserInitMprScript',
        'AutodialDLL',
        'LsaExtensions',
        'ServerLevelPluginDll',
        'LsaPasswordFilter',
        'LsaAuthenticationPackages',
        'LsaSecurityPackages',
        'WinlogonNotificationPackages',
        'ExplorerTools',
        'DotNetDebugger',
        'ErrorHandlerCmd',
        'WMIEventsSubscrition',
        'WindowsServices',
        'AppPaths',
        'TerminalServicesInitialProgram',
        'AccessibilityTools',
        'AMSIProviders',
        'PowershellProfiles',
        'SilentExitMonitor',
        'TelemetryController',
        'RDPWDSStartupPrograms',
        'ScheduledTasks',
        'BitsJobsNotify',
        'Screensaver',
        'PowerAutomate',
        'OfficeAddinsAndTemplates',
        'Services',
        'ExplorerContextMenu',
        'ServiceControlManagerSD',
        'OfficeAiHijacking',
        'RunExAndRunOnceEx',
        'DotNetStartupHooks'
    )]
    $PersistenceMethod = 'All',
     
    [Parameter(Position = 1)]
    [String[]]
    $ComputerName = $null,
    
    [Parameter(Position = 2)]
    [String]
    $DiffCSV = $null, 
    
    [Parameter(Position = 3)]
    [Switch]
    $IncludeHighFalsePositivesChecks,
        
    [Parameter(Position = 4)]
    [String]
    $OutputCSV = $null, 

    [Parameter(Position = 5)]
    [String]
    $VTApiKey = $null,
    
    [Parameter(Position = 6)]
    [Switch]
    $LogFindings
  )
  
  # This array will hold all the persistence techniques found on all the machines the module is run on
  $globalPersistenceObjectArray = [Collections.ArrayList]::new()
  
  $ScriptBlock = 
  {
    $ErrorActionPreference = 'SilentlyContinue'
    $VerbosePreference = $Using:VerbosePreference
    $hostname = ([Net.Dns]::GetHostByName($env:computerName)).HostName
    $psProperties = @('PSChildName', 'PSDrive', 'PSParentPath', 'PSPath', 'PSProvider')
    $persistenceObjectArray = [Collections.ArrayList]::new()
    $systemAndUsersHives = [Collections.ArrayList]::new()
    $systemHive = (Get-Item Registry::HKEY_LOCAL_MACHINE).PSpath
    $null = $systemAndUsersHives.Add($systemHive)
    $sids = Get-ChildItem Registry::HKEY_USERS 
    foreach($sid in $sids)
    {
      $null = $systemAndUsersHives.Add($sid.PSpath)
    }
    function New-PersistenceObject
    {
      param(
        [String]
        $Hostname = $null,

        [String]
        $Technique = $null, 

        [String]
        $Classification = $null, 

        [String]
        $Path = $null, 

        [String]
        $Value = $null, 

        [String]
        $AccessGained = $null,
      
        [String]
        $Note = $null,
      
        [String]
        $Reference = $null,
		
        [String]
        $Signature = $null ,
		
        [Bool]
        $IsBuiltinBinary = $false,
		
        [Bool]
        $IsLolbin = $false,

        [String]
        $VTEntries = $null
      )
      
      $Executable = Get-ExecutableFromCommandLine $Value
      
      $PersistenceObject = [PSCustomObject]@{
        'Hostname' 			  = $Hostname
        'Technique'    		= $Technique
        'Classification' 	= $Classification
        'Path'         		= $Path
        'Value'       	 	= $Value
        'Access Gained' 	= $AccessGained
        'Note'         		= $Note
        'Reference'    		= $Reference
        'Signature'	  		= Find-CertificateInfo $Executable
        'IsBuiltinBinary'	= Get-IfBuiltinBinary $Executable
        'IsLolbin'			= Get-IfLolBin $Executable
        'VTEntries'			= Get-IfHashIsMalicious $Executable
      } 
      return $PersistenceObject
    }
    
    function Get-IfHashIsMalicious($executable)
    {
      $authenticode = Get-AuthenticodeSignature($executable)
      if ($authenticode.IsOSBinary -eq $false) {
        if ($VTApiKey)
        {
          $headers = @{
            'x-apikey' = $VTApiKey
          }
          $hash = (Get-FileHash $executable).Hash
          $result = Invoke-RestMethod -Headers $headers "https://www.virustotal.com/api/v3/search?query=$hash"
          Sleep 1
          if ($result.data) {
            $result.data.attributes.last_analysis_stats.malicious
          } else {
            return "0"
          }
        }
        else {
          return "N/A"
        }
      }
      else {
        return "N/A"
      }

    }
	
	
    function Get-IfLolBin
    {
      param(
        [String]
        $executable
      )
      # To get an updated list of lolbins 
      # curl https://lolbas-project.github.io/# | grep -E "bin-name\">(.*)\.exe<" -o | cut -d ">" -f 2 | cut -d "<" -f 1 
      [String[]]$lolbins = "APPINSTALLER.EXE", "ASPNET_COMPILER.EXE", "AT.EXE", "ATBROKER.EXE", "BASH.EXE", "BITSADMIN.EXE", "CERTOC.EXE", "CERTREQ.EXE", "CERTUTIL.EXE", "CMD.EXE", "CMDKEY.EXE", "CMDL32.EXE", "CMSTP.EXE", "CONFIGSECURITYPOLICY.EXE", "CONHOST.EXE", "CONTROL.EXE", "CSC.EXE", "CSCRIPT.EXE", "DATASVCUTIL.EXE", "DESKTOPIMGDOWNLDR.EXE", "DFSVC.EXE", "DIANTZ.EXE", "DISKSHADOW.EXE", "DNSCMD.EXE", "ESENTUTL.EXE", "EVENTVWR.EXE", "EXPAND.EXE", "EXPLORER.EXE", "EXTEXPORT.EXE", "EXTRAC32.EXE", "FINDSTR.EXE", "FINGER.EXE", "FLTMC.EXE", "FORFILES.EXE", "FTP.EXE", "GFXDOWNLOADWRAPPER.EXE", "GPSCRIPT.EXE", "HH.EXE", "IMEWDBLD.EXE", "IE4UINIT.EXE", "IEEXEC.EXE", "ILASM.EXE", "INFDEFAULTINSTALL.EXE", "INSTALLUTIL.EXE", "JSC.EXE", "MAKECAB.EXE", "MAVINJECT.EXE", "MICROSOFT.WORKFLOW.COMPILER.EXE", "MMC.EXE", "MPCMDRUN.EXE", "MSBUILD.EXE", "MSCONFIG.EXE", "MSDT.EXE", "MSHTA.EXE", "MSIEXEC.EXE", "NETSH.EXE", "ODBCCONF.EXE", "OFFLINESCANNERSHELL.EXE", "ONEDRIVESTANDALONEUPDATER.EXE", "PCALUA.EXE", "PCWRUN.EXE", "PKTMON.EXE", "PNPUTIL.EXE", "PRESENTATIONHOST.EXE", "PRINT.EXE", "PRINTBRM.EXE", "PSR.EXE", "RASAUTOU.EXE", "RDRLEAKDIAG.EXE", "REG.EXE", "REGASM.EXE", "REGEDIT.EXE", "REGINI.EXE", "REGISTER-CIMPROVIDER.EXE", "REGSVCS.EXE", "REGSVR32.EXE", "REPLACE.EXE", "RPCPING.EXE", "RUNDLL32.EXE", "RUNONCE.EXE", "RUNSCRIPTHELPER.EXE", "SC.EXE", "SCHTASKS.EXE", "SCRIPTRUNNER.EXE", "SETTINGSYNCHOST.EXE", "STORDIAG.EXE", "SYNCAPPVPUBLISHINGSERVER.EXE", "TTDINJECT.EXE", "TTTRACER.EXE", "VBC.EXE", "VERCLSID.EXE", "WAB.EXE", "WLRMDR.EXE", "WMIC.EXE", "WORKFOLDERS.EXE", "WSCRIPT.EXE", "WSRESET.EXE", "WUAUCLT.EXE", "XWIZARD.EXE", "ACCCHECKCONSOLE.EXE", "ADPLUS.EXE", "AGENTEXECUTOR.EXE", "APPVLP.EXE", "BGINFO.EXE", "CDB.EXE", "COREGEN.EXE", "CSI.EXE", "DEVTOOLSLAUNCHER.EXE", "DNX.EXE", "DOTNET.EXE", "DUMP64.EXE", "DXCAP.EXE", "EXCEL.EXE", "FSI.EXE", "FSIANYCPU.EXE", "MFTRACE.EXE", "MSDEPLOY.EXE", "MSXSL.EXE", "NTDSUTIL.EXE", "POWERPNT.EXE", "PROCDUMP(64).EXE", "RCSI.EXE", "REMOTE.EXE", "SQLDUMPER.EXE", "SQLPS.EXE", "SQLTOOLSPS.EXE", "SQUIRREL.EXE", "TE.EXE", "TRACKER.EXE", "UPDATE.EXE", "VSIISEXELAUNCHER.EXE", "VISUALUIAVERIFYNATIVE.EXE", "VSJITDEBUGGER.EXE", "WFC.EXE", "WINWORD.EXE", "WSL.EXE"
      foreach($lolbin in $lolbins){
        $exe = Split-Path -path $executable -Leaf
        if (($exe.ToUpper()) -eq $lolbin) {
          return $true
        }
      }
      return $false
    }

    function Get-IfBuiltinBinary
    {
      param(
        [String]
        $executable
      )
      try {
        $authenticode = Get-AuthenticodeSignature $executable
        if($authenticode.IsOsBinary)
        {
          return $true
        }
        else
        {
          return $false
        }
      } 
      catch { 
        return $false
      }
    }
	
    function Find-CertificateInfo
    {
      param(
        [String]
        $executable
      )
      try {
        $authenticode = Get-AuthenticodeSignature $executable
        $formattedString = [string]::Format("Status = {0}, Subject = {1}",$authenticode.Status, $authenticode.SignerCertificate.Subject)
        return $formattedString
      } 
      catch { 
        return "Unknown error occurred"
      }
    }
    function Get-ExecutableFromCommandLine 
    {
      param(
        [String]
        $pathName
      )
      $pathName = [System.Environment]::ExpandEnvironmentVariables($pathName) -Replace '"'
      
      $match = [regex]::Match($pathName, '[A-Za-z0-9\s]+\.(exe|dll|ocx|cmd|bat|ps1)', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
      if($match.Success)
      {
        # Grab Index from the [regex]::Match() result
        $Index = $Match.Index

        # Substring using the index we obtained above
        $ThingsBeforeMatch = $pathName.Substring(0, $Index)
        $path = "$ThingsBeforeMatch$match"
      }
      else
      {
        $path = $null
      }
      
      if(([System.IO.Path]::IsPathRooted($path)) -eq $false)
      {
        $path = (Get-Command $path).Source
      }
      return $path
    }
    function Get-IfSafeExecutable
    {
      param(
        [String]
        $executable
      )
    
      $exePath = Get-ExecutableFromCommandLine $executable
      if((Get-IfBuiltinBinary $exePath) -and -not (Get-IfLolBin $exePath) )
      {
        return $true
      }
      else
      {
        return $false
      }
    }
    
    function Get-IfSafeLibrary
    {
      param(
        [String]
        $dllFullPath
      )
      
      if((Get-IfBuiltinBinary $dllFullPath) -eq $true)
      {
        return $true
      }
      else
      {
        return $false
      }
    }

    function Get-RunAndRunOnce
    {
      Write-Verbose -Message "$hostname - Getting Run properties..."
      foreach($hive in $systemAndUsersHives)
      {
        
        $runProps = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 
        if($runProps)
        {
          Write-Verbose -Message "$hostname - [!] Found properties under $(Convert-Path -Path $hive)'s Run key which deserve investigation!"
          foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $runProps))
          {
            if($psProperties.Contains($prop.Name)) 
            {
              continue
            } # skip the property if it's powershell built-in property
            $propPath = Convert-Path -Path $runProps.PSPath
            $propPath += '\' + $prop.Name
            $currentHive = Convert-Path -Path $hive
            if(($currentHive -eq 'HKEY_LOCAL_MACHINE') -or ($currentHive -eq 'HKEY_USERS\S-1-5-18') -or ($currentHive -eq 'HKEY_USERS\S-1-5-19') -or ($currentHive -eq 'HKEY_USERS\S-1-5-20'))
            {
              $access = 'System'
            }
            else
            {
              $access = 'User'
            }
            
            if(Get-IfSafeExecutable $runProps.($prop.Name))
            {
              continue
            }
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Registry Run Key' -Classification 'MITRE ATT&CK T1547.001' -Path $propPath -Value $runProps.($prop.Name) -AccessGained $access -Note 'Executables in properties of the key (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows\CurrentVersion\Run are run when the user logs in or when the machine boots up (in the case of the HKLM hive).' -Reference 'https://attack.mitre.org/techniques/T1547/001/' 
            $null = $persistenceObjectArray.Add($PersistenceObject)
          }
        }
      }
    
      Write-Verbose -Message ''
      Write-Verbose -Message "$hostname - Getting RunOnce properties..."
      foreach($hive in $systemAndUsersHives)
      {
        $runOnceProps = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" 
        if($runOnceProps)
        {
          Write-Verbose -Message "$hostname - [!] Found properties under $(Convert-Path -Path $hive)'s RunOnce key which deserve investigation!"
          foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $runOnceProps))
          {
            if($psProperties.Contains($prop.Name)) 
            {
              continue
            } # skip the property if it's powershell built-in property
            $propPath = Convert-Path -Path $runOnceProps.PSPath
            $propPath += '\' + $prop.Name
            $currentHive = Convert-Path -Path $hive
            if(($currentHive -eq 'HKEY_LOCAL_MACHINE') -or ($currentHive -eq 'HKEY_USERS\S-1-5-18') -or ($currentHive -eq 'HKEY_USERS\S-1-5-19') -or ($currentHive -eq 'HKEY_USERS\S-1-5-20'))
            {
              $access = 'System'
            }
            else
            {
              $access = 'User'
            }
            if(Get-IfSafeExecutable $runOnceProps.($prop.Name))
            {
              continue
            }
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Registry RunOnce Key' -Classification 'MITRE ATT&CK T1547.001' -Path $propPath -Value $runOnceProps.($prop.Name) -AccessGained $access -Note 'Executables in properties of the key (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce are run once when the user logs in, or when the machine boots up (in the case of the HKLM hive), and then deleted.' -Reference 'https://attack.mitre.org/techniques/T1547/001/' 
            $null = $persistenceObjectArray.Add($PersistenceObject)
          }
        }
      }
      Write-Verbose -Message ''
    }
  
    function Get-ImageFileExecutionOptions
    {
      $IFEOptsDebuggers = New-Object -TypeName System.Collections.ArrayList
      $foundDangerousIFEOpts = $false
      Write-Verbose -Message "$hostname - Getting Image File Execution Options..."
      foreach($hive in $systemAndUsersHives)
      {
        $ifeOpts = Get-ChildItem -Path "$hive\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" 
        if($ifeOpts)
        {
          foreach($key in $ifeOpts)
          {
            $debugger = Get-ItemProperty -Path Registry::$key -Name Debugger 
            if($debugger) 
            {
              $foundDangerousIFEOpts = $true
              $null = $IFEOptsDebuggers.Add($key)
            }
          }
      
          if($foundDangerousIFEOpts)
          {
            Write-Verbose -Message "$hostname - [!] Found subkeys under the Image File Execution Options key of $(Convert-Path -Path $hive) which deserve investigation!"
            foreach($key in $IFEOptsDebuggers)
            {
              $ifeProps = Get-ItemProperty -Path Registry::$key -Name Debugger
              foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $ifeProps))
              {
                if($psProperties.Contains($prop.Name)) 
                {
                  continue
                } # skip the property if it's powershell built-in property
                $propPath = Convert-Path -Path $ifeProps.PSPath
                $propPath += '\' + $prop.Name
                if(Get-IfSafeExecutable $ifeProps.($prop.Name))
                {
                  continue
                }
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Image File Execution Options' -Classification 'MITRE ATT&CK T1546.012' -Path $propPath -Value $ifeProps.($prop.Name) -AccessGained 'System/User' -Note 'Executables in the Debugger property of a subkey of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ are run instead of the program corresponding to the subkey. Gained access depends on whose context the debugged process runs in.' -Reference 'https://attack.mitre.org/techniques/T1546/012/' 
                $null = $persistenceObjectArray.Add($PersistenceObject)
              }
            }
          }
        }
      }
      Write-Verbose -Message ''
    }
  
    function Get-NLDPDllOverridePath
    {
      $KeysWithDllOverridePath = New-Object -TypeName System.Collections.ArrayList
      $foundDllOverridePath = $false
      Write-Verbose -Message "$hostname - Getting Natural Language Development Platform DLL path override properties..."
      foreach($hive in $systemAndUsersHives)
      {
        $NLDPLanguages = Get-ChildItem -Path "$hive\SYSTEM\CurrentControlSet\Control\ContentIndex\Language" 
        if($NLDPLanguages)
        {
          foreach($key in $NLDPLanguages)
          {
            $DllOverridePath = Get-ItemProperty -Path Registry::$key -Name *DLLPathOverride 
            if($DllOverridePath) 
            {
              $foundDllOverridePath = $true
              $null = $KeysWithDllOverridePath.Add($key)
            }
          }
      
          if($foundDllOverridePath)
          {
            Write-Verbose -Message "$hostname - [!] Found subkeys under $(Convert-Path -Path $hive)\SYSTEM\CurrentControlSet\Control\ContentIndex\Language which deserve investigation!"
            foreach($key in $KeysWithDllOverridePath)
            {
              $properties = Get-ItemProperty -Path Registry::$key | Select-Object -Property *DLLPathOverride, PS*
              foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $properties))
              {
                if($psProperties.Contains($prop.Name)) 
                {
                  continue
                } # skip the property if it's powershell built-in property
                $propPath = Convert-Path -Path $properties.PSPath
                $propPath += '\' + $prop.Name
                $currentHive = Convert-Path -Path $hive
                if(($currentHive -eq 'HKEY_LOCAL_MACHINE') -or ($currentHive -eq 'HKEY_USERS\S-1-5-18') -or ($currentHive -eq 'HKEY_USERS\S-1-5-19') -or ($currentHive -eq 'HKEY_USERS\S-1-5-20'))
                {
                  $access = 'System'
                }
                else
                {
                  $access = 'User'
                }
                if(Get-IfSafeLibrary $properties.($prop.Name))
                {
                  continue
                }
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Natural Language Development Platform 6 DLL Override Path' -Classification 'Hexacorn Technique N.98' -Path $propPath -Value $properties.($prop.Name) -AccessGained $access -Note 'DLLs listed in properties of subkeys of (HKLM|HKEY_USERS\<SID>)\SYSTEM\CurrentControlSet\Control\ContentIndex\Language are loaded via LoadLibrary executed by SearchIndexer.exe' -Reference 'https://www.hexacorn.com/blog/2018/12/30/beyond-good-ol-run-key-part-98/'
                $null = $persistenceObjectArray.Add($PersistenceObject)
              }
            }
          }
        }
      }
      Write-Verbose -Message ''
    }
  
    function Get-AeDebug
    {
      Write-Verbose -Message "$hostname - Getting AeDebug properties..."
      foreach($hive in $systemAndUsersHives)
      {
        $aeDebugger = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name Debugger 
        if($aeDebugger)
        {
          Write-Verbose -Message "$hostname - [!] Found properties under the $(Convert-Path -Path $hive) AeDebug key which deserve investigation!"
          foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $aeDebugger))
          {
            if($psProperties.Contains($prop.Name)) 
            {
              continue
            } # skip the property if it's powershell built-in property
            $propPath = Convert-Path -Path $aeDebugger.PSPath
            $propPath += '\' + $prop.Name
            if(Get-IfSafeExecutable $aeDebugger.($prop.Name))
            {
              continue
            }
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'AEDebug Custom Debugger' -Classification 'Hexacorn Technique N.4' -Path $propPath -Value $aeDebugger.($prop.Name) -AccessGained 'System/User' -Note "The executable in the Debugger property of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug is run when a process crashes. Gained access depends on whose context the debugged process runs in; if the Auto property of the same registry key is set to 1, the debugger starts without user interaction. A value of 'C:\Windows\system32\vsjitdebugger.exe' might be a false positive if you have Visual Studio Community installed." -Reference 'https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/' 
            $null = $persistenceObjectArray.Add($PersistenceObject)
          }
        }
    
        $aeDebugger = Get-ItemProperty -Path "$hive\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name Debugger 
        if($aeDebugger)
        {
          Write-Verbose -Message "$hostname - [!] Found properties under the $(Convert-Path -Path $hive) Wow6432Node AeDebug key which deserve investigation!"
          foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $aeDebugger))
          {
            if($psProperties.Contains($prop.Name)) 
            {
              continue
            } # skip the property if it's powershell built-in property
            $propPath = Convert-Path -Path $aeDebugger.PSPath
            $propPath += '\' + $prop.Name
            if(Get-IfSafeExecutable $aeDebugger.($prop.Name))
            {
              continue
            }
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Wow6432Node AEDebug Custom Debugger' -Classification 'Hexacorn Technique N.4' -Path $propPath -Value $aeDebugger.($prop.Name) -AccessGained 'System/User' -Note "The executable in the Debugger property of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug is run when a 32 bit process on a 64 bit system crashes. Gained access depends on whose context the debugged process runs in; if the Auto property of the same registry key is set to 1, the debugger starts without user interaction. A value of 'C:\Windows\system32\vsjitdebugger.exe' might be a false positive if you have Visual Studio Community installed." -Reference 'https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
          }
        }
      }
      Write-Verbose -Message '' 
    }
  
    function Get-WerFaultHangs
    {
      Write-Verbose -Message "$hostname - Getting WerFault Hangs registry key Debug property..."
      foreach($hive in $systemAndUsersHives)
      {
        $werfaultDebugger = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs" -Name Debugger 
        if($werfaultDebugger)
        {
          Write-Verbose -Message "$hostname - [!] Found a Debugger property under the $(Convert-Path -Path $hive) WerFault Hangs key which deserve investigation!"
          $werfaultDebugger | Select-Object -Property Debugger, PS*
          foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $werfaultDebugger))
          {
            if($psProperties.Contains($prop.Name)) 
            {
              continue
            } # skip the property if it's powershell built-in property
            $propPath = Convert-Path -Path $werfaultDebugger.PSPath
            $propPath += '\' + $prop.Name
            if(Get-IfSafeExecutable $werfaultDebugger.($prop.Name))
            {
              continue
            }
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Windows Error Reporting Debugger' -Classification 'Hexacorn Technique N.116' -Path $propPath -Value $werfaultDebugger.($prop.Name) -AccessGained 'System' -Note 'The executable in the Debugger property of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs is spawned by WerFault.exe when a process crashes.' -Reference 'https://www.hexacorn.com/blog/2019/09/20/beyond-good-ol-run-key-part-116/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
          }
        }
      }
    
      Write-Verbose -Message ''
      Write-Verbose -Message "$hostname - Getting WerFault Hangs registry key ReflectDebug property..."
      foreach($hive in $systemAndUsersHives)
      {
        $werfaultReflectDebugger = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs" -Name ReflectDebugger 
        if($werfaultReflectDebugger)
        {
          Write-Verbose -Message "$hostname - [!] Found a ReflectDebugger property under the $(Convert-Path -Path $hive) WerFault Hangs key which deserve investigation!"
          $werfaultReflectDebugger | Select-Object -Property ReflectDebugger, PS*
          foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $werfaultReflectDebugger))
          {
            if($psProperties.Contains($prop.Name)) 
            {
              continue
            } # skip the property if it's powershell built-in property
            $propPath = Convert-Path -Path $werfaultReflectDebugger.PSPath
            $propPath += '\' + $prop.Name
            if(Get-IfSafeExecutable $werfaultReflectDebugger.($prop.Name))
            {
              continue
            }
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Windows Error Reporting ReflectDebugger' -Classification 'Hexacorn Technique N.85' -Path $propPath -Value $werfaultReflectDebugger.($prop.Name) -AccessGained 'System' -Note 'The executable in the ReflectDebugger property of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs is spawned by WerFault.exe when called with the -pr argument.' -Reference 'https://www.hexacorn.com/blog/2018/08/31/beyond-good-ol-run-key-part-85/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
          }
        }
      }
      Write-Verbose -Message ''
    }

    function Get-CmdAutoRun
    {
      Write-Verbose -Message "$hostname - Getting Command Processor's AutoRun property..."
      foreach($hive in $systemAndUsersHives)
      {
        $autorun = (Get-ItemProperty -Path "$hive\Software\Microsoft\Command Processor" -Name AutoRun).AutoRun
        if($autorun)
        {
          Write-Verbose -Message "$hostname - [!] $(Convert-Path -Path $hive) Command Processor's AutoRun property is set and deserves investigation!"
          $propPath = Convert-Path -Path $hive
          $propPath += "\Software\Microsoft\Command Processor\AutoRun"
          $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Command Processor AutoRun key' -Classification 'Uncatalogued Technique N.1' -Path $propPath -Value $autorun -AccessGained 'User' -Note 'The executable in the AutoRun property of (HKLM|HKEY_USERS\<SID>)\Software\Microsoft\Command Processor\AutoRun is run when cmd.exe is spawned without the /D argument.' -Reference 'https://persistence-info.github.io/Data/cmdautorun.html'
          $null = $persistenceObjectArray.Add($PersistenceObject)
          
        }
      }
      Write-Verbose -Message ''   
    }  
    function Get-ExplorerLoad
    {
      Write-Verbose -Message "$hostname - Getting Explorer's Load property..."
      foreach($hive in $systemAndUsersHives)
      {
        $loadKey = Get-ItemProperty -Path "$hive\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name Load 
        if($loadKey)
        {
          Write-Verbose -Message "$hostname - [!] $(Convert-Path -Path $hive) Load property is set and deserves investigation!"
          foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $loadKey))
          {
            if($psProperties.Contains($prop.Name)) 
            {
              continue
            } # skip the property if it's powershell built-in property
            $propPath = Convert-Path -Path $loadKey.PSPath
            $propPath += '\' + $prop.Name
            $currentHive = Convert-Path -Path $hive
            if(($currentHive -eq 'HKEY_LOCAL_MACHINE') -or ($currentHive -eq 'HKEY_USERS\S-1-5-18') -or ($currentHive -eq 'HKEY_USERS\S-1-5-19') -or ($currentHive -eq 'HKEY_USERS\S-1-5-20'))
            {
              $access = 'System'
            }
            else
            {
              $access = 'User'
            }
            if(Get-IfSafeExecutable $loadKey.($prop.Name))
            {
              continue
            }
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Explorer Load Property' -Classification 'Uncatalogued Technique N.2' -Path $propPath -Value $loadKey.($prop.Name) -AccessGained $access -Note 'The executable in the Load property of (HKLM|HKEY_USERS\<SID>)\Software\Microsoft\Windows NT\CurrentVersion\Windows is run by explorer.exe at login time.' -Reference 'https://persistence-info.github.io/Data/windowsload.html'
            $null = $persistenceObjectArray.Add($PersistenceObject)
          }
        }
      }
      Write-Verbose -Message ''
    }
  
    function Get-WinlogonUserinit
    {
      Write-Verbose -Message "$hostname - Getting Winlogon's Userinit property..."
      foreach($hive in $systemAndUsersHives)
      {
        $userinit = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name Userinit 
        if($userinit)
        {
          if($userinit.Userinit -ne 'C:\Windows\system32\userinit.exe,')
          {
            Write-Verbose -Message "$hostname - [!] $(Convert-Path -Path $hive) Winlogon's Userinit property is set to a non-standard value and deserves investigation!"
            foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $userinit))
            {
              if($psProperties.Contains($prop.Name)) 
              {
                continue
              } # skip the property if it's powershell built-in property
              $propPath = Convert-Path -Path $userinit.PSPath
              $propPath += '\' + $prop.Name
              $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Winlogon Userinit Property' -Classification 'MITRE ATT&CK T1547.004' -Path $propPath -Value $userinit.($prop.Name) -AccessGained 'System' -Note "The executables in the Userinit property of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon are run at login time by any user. Normally this property should be set to 'C:\Windows\system32\userinit.exe,' without any further executables appended." -Reference 'https://attack.mitre.org/techniques/T1547/004/'
              $null = $persistenceObjectArray.Add($PersistenceObject)
            }
          }
        }
      }
      Write-Verbose -Message ''
    }
  
    function Get-WinlogonShell
    {        
      Write-Verbose -Message "$hostname - Getting Winlogon's Shell property..."
      foreach($hive in $systemAndUsersHives)
      {

        $shell = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name Shell 
        if($shell)
        {
          if($shell.Shell -ne 'explorer.exe')
          {
            Write-Verbose -Message "$hostname - [!] $(Convert-Path -Path $hive) Winlogon's Shell property is set to a non-standard value and deserves investigation!"
            foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $shell))
            {
              if($psProperties.Contains($prop.Name)) 
              {
                continue
              } # skip the property if it's a powershell built-in property
              $propPath = Convert-Path -Path $shell.PSPath
              $propPath += '\' + $prop.Name
              $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Winlogon Shell Property' -Classification 'MITRE ATT&CK T1547.004' -Path $propPath -Value $shell.($prop.Name) -AccessGained 'User' -Note "The executables in the Shell property of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon are run as the default shells for any users. Normally this property should be set to 'explorer.exe' without any further executables appended." -Reference 'https://attack.mitre.org/techniques/T1547/004/'
              $null = $persistenceObjectArray.Add($PersistenceObject)
            }
          }
        }
      }
      Write-Verbose -Message ''
    }
  
    function Get-TerminalProfileStartOnUserLogin
    {
      Write-Verbose -Message "$hostname - Checking if users' Windows Terminal Profile's settings.json contains a startOnUserLogin value..."
      $userDirectories = Get-ChildItem -Path 'C:\Users\'
      foreach($directory in $userDirectories)
      {
        $terminalDirectories = Get-ChildItem -Path "$($directory.FullName)\Appdata\Local\Packages\Microsoft.WindowsTerminal_*" 
        foreach($terminalDirectory in $terminalDirectories)
        {
          $settingsFile = Get-Content -Raw -Path "$($terminalDirectory.FullName)\LocalState\settings.json" | ConvertFrom-Json
          if($settingsFile.startOnUserLogin -ne 'true') # skip to the next profile if startOnUserLogin is not present
          {
            break 
          } 
          $defaultProfileGuid = $settingsFile.defaultProfile
          $found = $false 
          foreach($profileList in $settingsFile.profiles)
          {
            foreach($profile in $profileList.list)
            {
              if($profile.guid -eq $defaultProfileGuid)
              {
                Write-Verbose -Message "$hostname - [!] The file $($terminalDirectory.FullName)\LocalState\settings.json has the startOnUserLogin key set, the default profile has GUID $($profile.guid)!"
                if($profile.commandline)
                {
                  $executable = $profile.commandline 
                }
                else 
                {
                  $executable = $profile.name 
                }
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Windows Terminal startOnUserLogin' -Classification 'Uncatalogued Technique N.3' -Path "$($terminalDirectory.FullName)\LocalState\settings.json" -Value "$executable" -AccessGained 'User' -Note "The executable specified as value of the key `"commandline`" of a profile which has the `"startOnUserLogin`" key set to `"true`" in the Windows Terminal's settings.json of a user is run every time that user logs in." -Reference 'https://twitter.com/nas_bench/status/1550836225652686848'
                $null = $persistenceObjectArray.Add($PersistenceObject)
                $found = $true
                break
              }
            }
            if ($found) 
            {
              break 
            } 
          }
        }
      }    
      Write-Verbose -Message ''
    }
  
    function Get-AppCertDlls
    {
      Write-Verbose -Message "$hostname - Getting AppCertDlls properties..."
      foreach($hive in $systemAndUsersHives)
      {
        $appCertDllsProps = Get-ItemProperty -Path "$hive\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls" 
        if($appCertDllsProps)
        {
          Write-Verbose -Message "$hostname - [!] Found properties under $(Convert-Path -Path $hive) AppCertDlls key which deserve investigation!"
          foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $appCertDllsProps))
          {
            if($psProperties.Contains($prop.Name)) { continue } # skip the property if it's powershell built-in property
            $propPath = Convert-Path -Path $appCertDllsProps.PSPath
            $propPath += '\' + $prop.Name
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'AppCertDlls' -Classification 'MITRE ATT&CK T1546.009' -Path $propPath -Value $appCertDllsProps.($prop.Name) -AccessGained 'System' -Note 'DLLs in properties of the key (HKLM|HKEY_USERS\<SID>)\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls are loaded by every process that loads the Win32 API at process creation.' -Reference 'https://attack.mitre.org/techniques/T1546/009/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
          }
        }
      }
      Write-Verbose -Message ''
    }
  
    function Get-AppPaths
    {
      Write-Verbose -Message "$hostname - Getting App Paths inside the registry..."
      foreach($hive in $systemAndUsersHives)
      {
        $appPathsKeys = Get-ChildItem -Path "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths" 
        foreach($key in $appPathsKeys)
        {
          $appPath = Get-ItemProperty -Path Registry::$key -Name '(Default)' 
          
          
          $exePath = $appPath.'(Default)'
          if(([System.IO.Path]::IsPathRooted([System.Environment]::ExpandEnvironmentVariables($exePath))) -eq $false)
          {
            $exePath = "C:\Windows\System32\$exePath"
          }
          if ($exePath.Contains('powershell') -or $exePath.Contains('cmd') -or -not (Get-AuthenticodeSignature -FilePath $exePath ).IsOSBinary)
          { 
            Write-Verbose -Message "$hostname - [!] Found subkeys under the $(Convert-Path -Path $hive) App Paths key which deserve investigation!"
            $propPath = Convert-Path -Path $key.PSPath
            $propPath += '\' + $appPath.Name
            if(Get-IfSafeExecutable $appPath.'(Default)')
            {
              continue
            }
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'App Paths' -Classification 'Hexacorn Technique N.3' -Path "$propPath(Default)" -Value $appPath.'(Default)' -AccessGained 'System/User' -Note 'Executables in the (Default) property of a subkey of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\ are run instead of the program corresponding to the subkey. Gained access depends on whose context the process runs in. Be aware this might be a false positive.' -Reference 'https://www.hexacorn.com/blog/2013/01/19/beyond-good-ol-run-key-part-3/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
          } 
        }
      }
      Write-Verbose -Message ''
    }  
  
    function Get-ServiceDlls
    {
      Write-Verbose -Message "$hostname - Getting Service DLLs inside the registry..."
      foreach($hive in $systemAndUsersHives)
      {
        $keys = Get-ChildItem -Path "$hive\SYSTEM\CurrentControlSet\Services\" 
        foreach ($key in $keys)
        {
          $ImagePath = (Get-ItemProperty -Path ($key.pspath)).ImagePath
          if ($null -ne $ImagePath)
          {
            if ($ImagePath.Contains('\svchost.exe'))
            {    
              if (Test-Path -Path ($key.pspath+'\Parameters'))
              {
                $ServiceDll = (Get-ItemProperty -Path ($key.pspath+'\Parameters')).ServiceDll
              }
              else
              {
                $ServiceDll = (Get-ItemProperty -Path ($key.pspath)).ServiceDll
              }
              if ($null -ne $ServiceDll)
              {
                $dllPath = $ServiceDll
                if(([System.IO.Path]::IsPathRooted([System.Environment]::ExpandEnvironmentVariables($dllPath))) -eq $false)
                {
                  $dllPath = "C:\Windows\System32\$dllPath"
                }
                if ((Get-IfSafeLibrary $dllPath) -EQ $false) 
                {
                  Write-Verbose -Message "$hostname - [!] Found subkeys under the $(Convert-Path -Path $hive) Services key which deserve investigation!"
                  $propPath = (Convert-Path -Path "$($key.pspath)") + '\Parameters\ServiceDll'
                  $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'ServiceDll Hijacking' -Classification 'Hexacorn Technique N.4' -Path $propPath -Value "$ServiceDll" -AccessGained 'System' -Note "DLLs in the ServiceDll property of (HKLM|HKEY_USERS\<SID>)\SYSTEM\CurrentControlSet\Services\<SERVICE_NAME>\Parameters are loaded by the corresponding service's svchost.exe. If an attacker modifies said entry, the malicious DLL will be loaded in place of the legitimate one." -Reference 'https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/'
                  $null = $persistenceObjectArray.Add($PersistenceObject)
                }
              }
            }
          }
        } 
      }
      Write-Verbose -Message ''
    }
  
    function Get-GPExtensionDlls
    {
      Write-Verbose -Message "$hostname - Getting Group Policy Extension DLLs inside the registry..."
      foreach($hive in $systemAndUsersHives)
      {
        $keys = Get-ChildItem -Path "$hive\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions" 
        foreach ($key in $keys)
        {
          $DllName = (Get-ItemProperty -Path ($key.pspath)).DllName
          if ($null -ne $DllName)
          {
            if(([System.IO.Path]::IsPathRooted([System.Environment]::ExpandEnvironmentVariables($DllName))) -eq $false)
            {
              $DllName = "C:\Windows\System32\$DllName"
            }
            if ((Get-IfSafeLibrary $DllName) -EQ $false) 
            {
              Write-Verbose -Message "$hostname - [!] Found DllName property under a subkey of the $(Convert-Path -Path $hive) GPExtensions key which deserve investigation!"
              $propPath = (Convert-Path -Path "$($key.pspath)") + '\DllName'
              $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Group Policy Extension DLL' -Classification 'Uncatalogued Technique N.4' -Path $propPath -Value "$DllName" -AccessGained 'System' -Note 'DLLs in the DllName property of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\<GUID>\ are loaded by the gpsvc process. If an attacker modifies said entry, the malicious DLL will be loaded in place of the legitimate one.' -Reference 'https://persistence-info.github.io/Data/gpoextension.html'
              $null = $persistenceObjectArray.Add($PersistenceObject)
            }
          }
        }  
      }
      Write-Verbose -Message ''
    }
  
    function Get-WinlogonMPNotify
    {
      Write-Verbose -Message "$hostname - Getting Winlogon MPNotify property..."
      foreach($hive in $systemAndUsersHives)
      {
        $mpnotify = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name mpnotify 
        if($mpnotify)
        {
          Write-Verbose -Message "$hostname - [!] Found MPnotify property under $(Convert-Path -Path $hive) Winlogon key!"
          $propPath = (Convert-Path -Path $mpnotify.PSPath) + '\mpnotify'
          $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Winlogon MPNotify Executable' -Classification 'Uncatalogued Technique N.5' -Path $propPath -Value $mpnotify.mpnotify -AccessGained 'System' -Note 'The executable specified in the "mpnotify" property of the (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon key is run by Winlogon when a user logs on. After the timeout (30s) the process and its child processes are terminated.' -Reference 'https://persistence-info.github.io/Data/mpnotify.html'
          $null = $persistenceObjectArray.Add($PersistenceObject)
        }
      }
      Write-Verbose -Message ''
    }
    
    function Get-CHMHelperDll
    {
      Write-Verbose -Message "$hostname - Getting CHM Helper DLL inside the registry..."
      foreach($hive in $systemAndUsersHives)
      {
        $dllLocation = Get-ItemProperty -Path "$hive\Software\Microsoft\HtmlHelp Author" -Name Location
        if($dllLocation)
        {
          $dllPath = $dllLocation.Location
          if ($null -ne $dllPath)
          {
            if(([System.IO.Path]::IsPathRooted([System.Environment]::ExpandEnvironmentVariables($dllPath))) -eq $false)
            {
              $dllPath = "C:\Windows\System32\$dllPath"
            }
            if ((Get-IfSafeLibrary $dllPath) -EQ $false) 
            {
              Write-Verbose -Message "$hostname - [!] Found Location property under $(Convert-Path -Path $hive)\Software\Microsoft\HtmlHelp Author\ which deserve investigation!"
              $propPath = (Convert-Path -Path "$($dllLocation.pspath)") + '\Location'
              $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'CHM Helper DLL' -Classification 'Hexacorn Technique N.76' -Path $propPath -Value "$($dllLocation.Location)" -AccessGained 'User' -Note 'DLLs in the Location property of (HKLM|HKEY_USERS\<SID>)\Software\Microsoft\HtmlHelp Author\ are loaded when a CHM help file is parsed. If an attacker adds said entry, the malicious DLL will be loaded.' -Reference 'https://www.hexacorn.com/blog/2018/04/22/beyond-good-ol-run-key-part-76/'
              $null = $persistenceObjectArray.Add($PersistenceObject)
            }
          }
        }  
      }
      Write-Verbose -Message ''
    }
    
    function Get-HHCtrlHijacking
    {
      Write-Verbose -Message "$hostname - Getting the hhctrl.ocx library inside the registry..."
      $hive = (Get-Item Registry::HKEY_CLASSES_ROOT).PSpath
      $dllLocation = Get-ItemProperty -Path "$hive\CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32" -Name '(Default)'
      $dllPath = $dllLocation.'(Default)'
      if ($null -ne $dllPath)
      {
        if(([System.IO.Path]::IsPathRooted([System.Environment]::ExpandEnvironmentVariables($dllPath))) -eq $false)
        {
          $dllPath = "C:\Windows\System32\$dllPath"
        }
        if (-not (Get-AuthenticodeSignature -FilePath $dllPath ).IsOSBinary)
        {
          Write-Verbose -Message "$hostname - [!] The DLL at $(Convert-Path -Path $hive)\CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32\(Default) is not an OS binary and deserves investigation!"
          $propPath = (Convert-Path -Path "$($dllLocation.pspath)") + '\(Default)'
          $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Hijacking of hhctrl.ocx' -Classification 'Hexacorn Technique N.77' -Path $propPath -Value "$($dllLocation.'(Default)')" -AccessGained 'User' -Note 'The DLL in the (Default) property of HKEY_CLASSES_ROOT\CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32 is loaded when a CHM help file is parsed or when hh.exe is started. If an attacker modifies said entry, the malicious DLL will be loaded. In case the loading fails for any reason, C:\Windows\hhctrl.ocx is loaded.' -Reference 'https://www.hexacorn.com/blog/2018/04/23/beyond-good-ol-run-key-part-77/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
        }
      }
      else
      {
        $dllPath = "C:\Windows\System32\hhctrl.ocx"
        if (-not (Get-AuthenticodeSignature -FilePath $dllPath ).IsOSBinary)
        {
          Write-Verbose -Message "$hostname - [!] The DLL at $dllPath is not an OS binary and deserves investigation!"
          $propPath = (Convert-Path -Path "$($dllLocation.pspath)") + '\(Default)'
          $PersistenceObject = New-PersistenceObject -Hostname "$hostname" -Technique 'Hijacking of hhctrl.ocx' -Classification 'Hexacorn Technique N.77' -Path "$dllPath" -Value "Not an OS binary" -AccessGained 'User' -Note 'The DLL in the (Default) property of HKEY_CLASSES_ROOT\CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32 is loaded when a CHM help file is parsed or when hh.exe is started. If an attacker modifies said entry, the malicious DLL will be loaded. In case the loading fails for any reason, C:\Windows\hhctrl.ocx is loaded.' -Reference 'https://www.hexacorn.com/blog/2018/04/23/beyond-good-ol-run-key-part-77/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
        }
      }  
      Write-Verbose -Message ''
    }
    
    function Get-StartupPrograms
    {
      Write-Verbose -Message "$hostname - Checking if users' Startup folder contains interesting artifacts..."
      $userDirectories = Get-ChildItem -Path 'C:\Users\'
      foreach($directory in $userDirectories)
      {
        $fullPath = $directory.FullName
        $startupDirectory = Get-ChildItem -Path "$fullPath\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\" 
        foreach($file in $startupDirectory)
        {
          $relPath = $file.Name
          Write-Verbose -Message "$hostname - [!] Found a file under $fullPath\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\ folder!"
          $safeCheck = Get-IfSafeExecutable "$fullPath\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\$relPath"
          if($safeCheck)
          {
            continue
          }          
          $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Startup Folder' -Classification 'MITRE ATT&CK T1547.001' -Path "$fullPath\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\" -Value "$fullPath\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\$relPath" -AccessGained 'User' -Note "The executables under the .\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\ of a user's folder are run every time that user logs in." -Reference 'https://attack.mitre.org/techniques/T1547/001/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
          $found = $true
          break
        }
      } 
      Write-Verbose -Message ''
    }
    
    function Get-UserInitMprScript
    {
      Write-Verbose -Message "$hostname - Getting users' UserInitMprLogonScript property..."
      foreach($hive in $systemAndUsersHives)
      {
        $mprlogonscript = Get-ItemProperty -Path "$hive\Environment" -Name UserInitMprLogonScript 
        if($mprlogonscript)
        {
          Write-Verbose -Message "$hostname - [!] Found UserInitMprLogonScript property under $(Convert-Path -Path $hive)\Environment\ key!"
          $propPath = (Convert-Path -Path $mprlogonscript.PSPath) + '\UserInitMprLogonScript'
          $currentHive = Convert-Path -Path $hive
          if(($currentHive -eq 'HKEY_LOCAL_MACHINE') -or ($currentHive -eq 'HKEY_USERS\S-1-5-18') -or ($currentHive -eq 'HKEY_USERS\S-1-5-19') -or ($currentHive -eq 'HKEY_USERS\S-1-5-20'))
          {
            $access = 'System'
          }
          else
          {
            $access = 'User'
          }
          $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'User Init Mpr Logon Script' -Classification 'MITRE ATT&CK T1037.001' -Path $propPath -Value $mprlogonscript.UserInitMprLogonScript -AccessGained $access -Note 'The executable specified in the "UserInitMprLogonScript" property of the HKEY_USERS\<SID>\Environment key is run when the user logs on.' -Reference 'https://attack.mitre.org/techniques/T1037/001/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
        }
      }
      Write-Verbose -Message ''
    }
    
    function Get-AutodialDLL
    {
      Write-Verbose -Message "$hostname - Getting the AutodialDLL property..."
      foreach($hive in $systemAndUsersHives)
      {
        $autodialDll = Get-ItemProperty -Path "$hive\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters" -Name AutodialDLL 
        if($autodialDll)
        {
          $dllPath = $autodialDll.AutodialDLL
          if(([System.IO.Path]::IsPathRooted([System.Environment]::ExpandEnvironmentVariables($dllPath))) -eq $false)
          {
            $dllPath = "C:\Windows\System32\$dllPath"
          }
          if ((Get-IfSafeLibrary $dllPath) -EQ $false)
          {
            Write-Verbose -Message "$hostname - [!] Found AutodialDLL property under $(Convert-Path -Path $hive)\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\ key which points to a non-OS DLL!"
            $propPath = (Convert-Path -Path $autodialDll.PSPath) + '\AutodialDLL'
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'AutodialDLL Winsock Injection' -Classification 'Hexacorn Technique N.24' -Path $propPath -Value $autodialDll.AutodialDLL -AccessGained 'System' -Note 'The DLL specified in the "AutodialDLL" property of the (HKLM|HKEY_USERS\<SID>)\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters key is loaded by the Winsock library everytime it connects to the internet.' -Reference 'https://www.hexacorn.com/blog/2015/01/13/beyond-good-ol-run-key-part-24/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
          }
        }
      }
      Write-Verbose -Message ''
    }
    
    function Get-LsaExtensions
    {
      Write-Verbose -Message "$hostname - Getting LSA's extensions..."
      foreach($hive in $systemAndUsersHives)
      {
        $lsaExtensions = Get-ItemProperty -Path "$hive\SYSTEM\CurrentControlSet\Control\LsaExtensionConfig\LsaSrv" -Name Extensions 
        if($lsaExtensions)
        {
          $dlls = $lsaExtensions.Extensions -split '\s+'
          foreach ($dll in $dlls)
          {
            $dllPath = $dll
            if(([System.IO.Path]::IsPathRooted([System.Environment]::ExpandEnvironmentVariables($dllPath))) -eq $false)
            {
              $dllPath = "C:\Windows\System32\$dllPath"
            }
            if ((Get-IfSafeLibrary $dllPath) -EQ $false)
            {
              Write-Verbose -Message "$hostname - [!] Found LSA Extension DLL under the $(Convert-Path -Path $hive)\SYSTEM\CurrentControlSet\Control\LsaExtensionConfig\LsaSrv\Extensions property which points to a non-OS DLL!"
              $propPath = (Convert-Path -Path $lsaExtensions.PSPath) + '\Extensions'
              $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'LSA Extensions DLL' -Classification 'Uncatalogued Technique N.6' -Path $propPath -Value $dll -AccessGained 'System' -Note 'The DLLs specified in the "Extensions" property of the (HKLM|HKEY_USERS\<SID>)\SYSTEM\CurrentControlSet\Control\LsaExtensionConfig\LsaSrv\ key are loaded by LSASS at machine boot.' -Reference 'https://persistence-info.github.io/Data/lsaaextension.html'
              $null = $persistenceObjectArray.Add($PersistenceObject)
            }
          }
        }
      }
      Write-Verbose -Message ''
    }
  
    function Get-ServerLevelPluginDll
    {
      Write-Verbose -Message "$hostname - Getting the ServerLevelPluginDll property..."
      foreach($hive in $systemAndUsersHives)
      {
        $pluginDll = Get-ItemProperty -Path "$hive\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name ServerLevelPluginDll 
        if($pluginDll)
        {
          $dllPath = $pluginDll.ServerLevelPluginDll
          if(([System.IO.Path]::IsPathRooted([System.Environment]::ExpandEnvironmentVariables($dllPath))) -eq $false)
          {
            $dllPath = "C:\Windows\System32\$dllPath"
          }
          if ((Get-IfSafeLibrary $dllPath) -EQ $false)
          {
            Write-Verbose -Message "$hostname - [!] Found ServerLevelPluginDll property under $(Convert-Path -Path $hive)\SYSTEM\CurrentControlSet\Services\DNS\Parameters key which points to a non-OS DLL!"
            $propPath = (Convert-Path -Path $pluginDll.PSPath) + '\ServerLevelPluginDll'
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'ServerLevelPluginDll DNS Server DLL Hijacking' -Classification 'Uncatalogued Technique N.7' -Path $propPath -Value $pluginDll.ServerLevelPluginDll -AccessGained 'System' -Note 'The DLL specified in the "ServerLevelPluginDll" property of the (HKLM|HKEY_USERS\<SID>)\SYSTEM\CurrentControlSet\Services\DNS\Parameters key is loaded by the DNS service on systems with the "DNS Server" role enabled.' -Reference 'https://persistence-info.github.io/Data/serverlevelplugindll.html'
            $null = $persistenceObjectArray.Add($PersistenceObject)
          }
        }
      }
      Write-Verbose -Message ''
    }
    
    function Get-LsaPasswordFilter
    {
      Write-Verbose -Message "$hostname - Getting LSA's password filters..."
      foreach($hive in $systemAndUsersHives)
      {
        $passwordFilters = Get-ItemProperty -Path "$hive\SYSTEM\CurrentControlSet\Control\Lsa" -Name 'Notification Packages' 
        if($passwordFilters)
        {
          $dlls = $passwordFilters.'Notification Packages' -split '\s+'
          foreach ($dll in $dlls)
          {
            $dllPath = "C:\Windows\System32\$dll.dll"
            if ((Get-IfSafeLibrary $dllPath) -EQ $false)
            {
              Write-Verbose -Message "$hostname - [!] Found a LSA password filter DLL under the $(Convert-Path -Path $hive)\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages property which points to a non-OS DLL!"
              $propPath = (Convert-Path -Path $passwordFilters.PSPath) + '\Notification Packages'
              $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'LSA Password Filter DLL' -Classification 'MITRE ATT&CK T1556.002' -Path $propPath -Value $dllPath -AccessGained 'System' -Note 'The DLLs specified in the "Notification Packages" property of the (HKLM|HKEY_USERS\<SID>)\SYSTEM\CurrentControlSet\Control\Lsa\ key are loaded by LSASS at machine boot.' -Reference 'https://attack.mitre.org/techniques/T1556/002/'
              $null = $persistenceObjectArray.Add($PersistenceObject)
            }
          }
        }
      }
      Write-Verbose -Message ''
    }
    
    function Get-LsaAuthenticationPackages
    {
      Write-Verbose -Message "$hostname - Getting LSA's authentication packages..."
      foreach($hive in $systemAndUsersHives)
      {
        $authPackages = Get-ItemProperty -Path "$hive\SYSTEM\CurrentControlSet\Control\Lsa" -Name 'Authentication Packages' 
        if($authPackages)
        {
          $dlls = $authPackages.'Authentication Packages' -split '\s+'
          foreach ($dll in $dlls)
          {
            $dllPath = "C:\Windows\System32\$dll.dll"
            if ((Get-IfSafeLibrary $dllPath) -EQ $false)
            {
              Write-Verbose -Message "$hostname - [!] Found a LSA authentication package DLL under the $(Convert-Path -Path $hive)\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages property which points to a non-OS DLL!"
              $propPath = (Convert-Path -Path $authPackages.PSPath) + '\Authentication Packages'
              $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'LSA Authentication Package DLL' -Classification 'MITRE ATT&CK T1547.002' -Path $propPath -Value $dllPath -AccessGained 'System' -Note 'The DLLs specified in the "Authentication Packages" property of the (HKLM|HKEY_USERS\<SID>)\SYSTEM\CurrentControlSet\Control\Lsa\ key are loaded by LSASS at machine boot.' -Reference 'https://attack.mitre.org/techniques/T1547/002/'
              $null = $persistenceObjectArray.Add($PersistenceObject)
            }
          }
        }
      }
      Write-Verbose -Message ''
    }
    
    function Get-LsaSecurityPackages
    {
      Write-Verbose -Message "$hostname - Getting LSA's security packages..."
      foreach($hive in $systemAndUsersHives)
      {
        $secPackages = Get-ItemProperty -Path "$hive\SYSTEM\CurrentControlSet\Control\Lsa" -Name 'Security Packages' 
        if($secPackages)
        {
          $packageString = $secPackages.'Security Packages' -replace '"',''
          $dlls = $packageString -split '\s+'
          foreach ($dll in $dlls)
          {
            if($dll -eq "")
            {
              continue
            }
            if(([System.IO.Path]::IsPathRooted([System.Environment]::ExpandEnvironmentVariables($dll))) -eq $false)
            {
              $dll = "C:\Windows\System32\$dll.dll"
            }
            if ((Get-IfSafeLibrary $dllPath) -EQ $false)
            {
              Write-Verbose -Message "$hostname - [!] Found a LSA security package DLL under the $(Convert-Path -Path $hive)\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages property which points to a non-OS DLL!"
              $propPath = (Convert-Path -Path $secPackages.PSPath) + '\Security Packages'
              $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'LSA Security Package DLL' -Classification 'MITRE ATT&CK T1547.005' -Path $propPath -Value $dll -AccessGained 'System' -Note 'The DLLs specified in the "Security Packages" property of the (HKLM|HKEY_USERS\<SID>)\SYSTEM\CurrentControlSet\Control\Lsa\ key are loaded by LSASS at machine boot.' -Reference 'https://attack.mitre.org/techniques/T1547/005/'
              $null = $persistenceObjectArray.Add($PersistenceObject)
            }
          }
        }
      }
      Write-Verbose -Message ''
    }
    
    function Get-WinlogonNotificationPackages
    {
      Write-Verbose -Message "$hostname - Getting Winlogon Notification packages..."
      foreach($hive in $systemAndUsersHives)
      {
        
        $notificationPackages = Get-ItemProperty -Path "$hive\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify" 
        if($notificationPackages)
        {
          Write-Verbose -Message "$hostname - [!] Found properties under $(Convert-Path -Path $hive)\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify key which deserve investigation!"
          foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $notificationPackages))
          {
            if($psProperties.Contains($prop.Name)) 
            {
              continue
            } # skip the property if it's powershell built-in property
            $propPath = Convert-Path -Path $notificationPackages.PSPath
            $propPath += '\' + $prop.Name
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Winlogon Notification Package' -Classification 'MITRE ATT&CK T1547.004' -Path $propPath -Value $notificationPackages.($prop.Name) -AccessGained 'System' -Note 'DLLs in the properties of the (HKLM|HKEY_USERS\<SID>)\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify key are loaded by the system when it boots.' -Reference 'https://attack.mitre.org/techniques/T1547/004/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
          }
        }
      }
      Write-Verbose -Message ''
    }
    
    function Get-ExplorerTools
    {
      Write-Verbose -Message "$hostname - Getting Explorer Tools..."
      foreach($hive in $systemAndUsersHives)
      {
        $explorerTools = Get-ChildItem -Path "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer" 
        foreach($key in $explorerTools)
        {
          $path = ((Get-ItemProperty -Path Registry::$key -Name '(Default)').'(Default)'-split '\s+')[0] # split the path and take only the executable in case there are arguments
          if(('' -ne $path) -and ([System.IO.Path]::IsPathRooted([System.Environment]::ExpandEnvironmentVariables($path)) -eq $false))
          {
            $path = "C:\Windows\System32\$path.dll"
          }
          if (-not (Get-AuthenticodeSignature -FilePath $path ).IsOSBinary) 
          {
            Write-Verbose -Message "$hostname - [!] Found an executable under a subkey of $(Convert-Path -Path $hive)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer key which deserve investigation!"
            $propPath = Convert-Path -Path $key.PSPath
            $propPath += '\(Default)'
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Explorer Tools Hijacking' -Classification 'Hexacorn Technique N.55' -Path $propPath -Value $path -AccessGained 'System' -Note 'Executables in the (Default) property of a subkey of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer are run when the corresponding event is triggered.' -Reference 'https://www.hexacorn.com/blog/2017/01/18/beyond-good-ol-run-key-part-55/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
          }
        }
      }
      Write-Verbose -Message ''
    }
    
    function Get-DotNetDebugger
    {
      Write-Verbose -Message "$hostname - Getting .NET Debugger properties..."
      foreach($hive in $systemAndUsersHives)
      {
        $dotNetDebugger = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\.NETFramework" -Name DbgManagedDebugger 
        if($dotNetDebugger.DbgManagedDebugger)
        {          
          if(Get-IfSafeExecutable $dotNetDebugger.DbgManagedDebugger)
          {
            continue
          }
          Write-Verbose -Message "$hostname - [!] Found DbgManagedDebugger under the $(Convert-Path -Path $hive)\SOFTWARE\Microsoft\.NETFramework key which deserve investigation!"
          $propPath = Convert-Path -Path $dotNetDebugger.PSPath
          $propPath += '\DbgManagedDebugger'

          $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'DbgManagedDebugger Custom Debugger' -Classification 'Hexacorn Technique N.4' -Path $propPath -Value $dotNetDebugger.DbgManagedDebugger -AccessGained 'System/User' -Note "The executable in the DbgManagedDebugger property of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Wow6432Node\Microsoft\.NETFramework is run when a .NET process crashes. Gained access depends on whose context the debugged process runs in." -Reference 'https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
        }
    
        $dotNetDebugger = Get-ItemProperty -Path "$hive\SOFTWARE\Wow6432Node\Microsoft\.NETFramework" -Name DbgManagedDebugger 
        if($dotNetDebugger.DbgManagedDebugger)
        {
          if(Get-IfSafeExecutable $dotNetDebugger.DbgManagedDebugger)
          {
            continue
          }
          Write-Verbose -Message "$hostname - [!] Found DbgManagedDebugger under the $(Convert-Path -Path $hive)\SOFTWARE\Wow6432Node\Microsoft\.NETFramework key which deserve investigation!"
          $propPath = Convert-Path -Path $dotNetDebugger.PSPath
          $propPath += '\DbgManagedDebugger'
          $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Wow6432Node DbgManagedDebugger Custom Debugger' -Classification 'Hexacorn Technique N.4' -Path $propPath -Value $dotNetDebugger.DbgManagedDebugger -AccessGained 'System/User' -Note "The executable in the DbgManagedDebugger property of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Wow6432Node\Microsoft\.NETFramework is run when a .NET 32 bit process on a 64 bit system crashes. Gained access depends on whose context the debugged process runs in." -Reference 'https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
        }
      }
      Write-Verbose -Message '' 
    }
    
    function Get-ErrorHandlerCmd
    {
      Write-Verbose -Message "$hostname - Checking if C:\WINDOWS\Setup\Scripts\ contains a file called ErrorHandler.cmd..."
      $errorHandlerCmd = Get-ChildItem -Path 'C:\WINDOWS\Setup\Scripts\ErrorHandler.cmd'
      if($errorHandlerCmd)
      {
        Write-Verbose -Message "$hostname - [!] Found C:\WINDOWS\Setup\Scripts\ErrorHandler.cmd!"          
        $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'ErrorHandler.cmd Hijacking' -Classification 'Hexacorn Technique N.135' -Path "C:\WINDOWS\Setup\Scripts\" -Value "ErrorHandler.cmd" -AccessGained 'User' -Note "The content of C:\WINDOWS\Setup\Scripts\ErrorHandler.cmd is read whenever some tools under C:\WINDOWS\System32\oobe\ (e.g. Setup.exe) fail to run for any reason." -Reference 'https://www.hexacorn.com/blog/2022/01/16/beyond-good-ol-run-key-part-135/'
        $null = $persistenceObjectArray.Add($PersistenceObject)
      } 
      Write-Verbose -Message ''
    }

    function Get-WMIEventsSubscrition
    {
      Write-Verbose -Message "$hostname - Checking WMI Subscriptions..."
      $cmdEventConsumer = Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer
      if ($cmdEventConsumer)
      {
        foreach ( $cmdEntry in ($cmdEventConsumer))
        {
          $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'WMI Event Subscription' -Classification 'MITRE ATT&CK T1546.003' -Path $cmdEntry.__PATH -Value "CommandLineTemplate: $($cmdEntry.CommandLineTemplate) / ExecutablePath: $($cmdEntry.ExecutablePath)" -AccessGained 'System' -Note "WMI Events subscriptions can be used to link script/command executions to specific events. Here we list the active consumer events, but you may want to review also existing Filters (with Get-WMIObject -Namespace root\Subscription -Class __EventFilter) and Bindings (with Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding)" -Reference 'https://attack.mitre.org/techniques/T1546/003/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
        }
      }

      $scriptEventConsumer = Get-WMIObject -Namespace root\Subscription -Class ActiveScriptEventConsumer
      if ($scriptEventConsumer)
      {
        foreach ( $scriptEntry in ($scriptEventConsumer))
        {
          $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'WMI Event Subscription' -Classification 'MITRE ATT&CK T1546.003' -Path $scriptEntry.__PATH -Value "ScriptingEngine: $($scriptEntry.ScriptingEngine) / ScriptFileName: $($scriptEntry.ScriptFileName) / ScriptText: $($scriptEntry.ScriptText)"  -AccessGained 'System' -Note "WMI Events subscriptions can be used to link script/command executions to specific events. Here we list the active consumer events, but you may want to review also existing Filters (with Get-WMIObject -Namespace root\Subscription -Class __EventFilter) and Bindings (with Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding)" -Reference 'https://attack.mitre.org/techniques/T1546/003/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
        }
      }
      Write-Verbose -Message ''
    }
	
    function Get-WindowsServices
    {
      Write-Verbose -Message "$hostname - Checking Windows Services..."
      $services = Get-CimInstance -ClassName win32_service | Select-Object Name,DisplayName,State,PathName
      foreach ( $service in $services) 
      {
        $path = Get-ExecutableFromCommandLine $service.PathName
        if ((Get-IfSafeExecutable $path) -EQ $false) 
        {
          Write-Verbose -Message "$hostname - [!] Found Windows Services which may deserve investigation..."
          $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Windows Service' -Classification 'MITRE ATT&CK T1543.003' -Path $service.Name  -Value $service.PathName  -AccessGained 'System' -Note "Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions."  -Reference 'https://attack.mitre.org/techniques/T1543/003/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
        }
      }
      Write-Verbose -Message ''
    }
    
    function Get-PowerAutomate
    {
      Write-Verbose -Message "$hostname - Checking Power Automate presence..."

      $PADFolder = "$env:ProgramData\Microsoft\Power Automate\Logs"
      $LastPALog = Get-ChildItem -Path $PADFolder | Sort-Object LastWriteTime -Descending| Select-Object -First 1

      if ($LastPALog)
      {
        $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Power Automate' -Classification 'Uncatalogued Technique N.12' -Path $PADFolder -Value $LastPALog -AccessGained 'System/User' -Note "'Power Automate' is an RPA (Robotic Process Automation) made available by Microsoft. It can runs on standalone system or through Azure Tenants. Given the high number of functions available and the 'legit source' of these executables and processes, it could be used for malicious intent as well. The presence of the logs means that the system is in some way running these flows. Review if they are legit or not (last log is shown in Value)." -Reference 'https://github.com/mbrg/defcon30/tree/main/No_Code_Malware'
        $null = $persistenceObjectArray.Add($PersistenceObject)
      }
      
      Write-Verbose -Message '' 
    }

    function Get-TSInitialProgram
    {
      Write-Verbose -Message "$hostname - Getting Terminal Services InitialProgram properties..."
      foreach($hive in $systemAndUsersHives)
      {
        $InitialProgram = Get-ItemProperty -Path "$hive\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name InitialProgram
        $fInheritInitialProgram = Get-ItemProperty -Path "$hive\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name fInheritInitialProgram 
        if($null -ne $InitialProgram.InitialProgram -and $InitialProgram.InitialProgram.Length -ne 0 -and $fInheritInitialProgram -eq 1)
        {
          Write-Verbose -Message "$hostname - [!] Found InitialProgram property under the $(Convert-Path -Path $hive) Terminal Services key which deserve investigation!"
          foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $InitialProgram))
          {
            if($psProperties.Contains($prop.Name)) 
            {
              continue
            } # skip the property if it's powershell built-in property
            $propPath = Convert-Path -Path $InitialProgram.PSPath
            $propPath += '\' + $prop.Name
            if(Get-IfSafeExecutable $InitialProgram.($prop.Name))
            {
              continue
            }
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Terminal Services InitialProgram' -Classification 'Uncatalogued Technique N.8' -Path $propPath -Value $InitialProgram.($prop.Name) -AccessGained 'System/User' -Note "The executable in the InitialProgram property of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services is run when a Remote Desktop Connection is made to the target machine. Gained access depends on whether the key is in the system hive or a user's hive. For this technique to work, the fInheritInitialProgram property of the same key must also be set to 1." -Reference 'https://persistence-info.github.io/Data/tsinitialprogram.html' 
            $null = $persistenceObjectArray.Add($PersistenceObject)
          }
        }
    
        $InitialProgram = Get-ItemProperty -Path "$hive\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name InitialProgram 
        $fInheritInitialProgram = Get-ItemProperty -Path "$hive\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name fInheritInitialProgram 
        if($null -ne $InitialProgram.InitialProgram -and $InitialProgram.InitialProgram.Length -ne 0 -and $fInheritInitialProgram -eq 1)
        {
          Write-Verbose -Message "$hostname - [!] Found InitialProgram property under the $(Convert-Path -Path $hive) Terminal Services key which deserve investigation!"
          foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $InitialProgram))
          {
            if($psProperties.Contains($prop.Name)) 
            {
              continue
            } # skip the property if it's powershell built-in property
            $propPath = Convert-Path -Path $InitialProgram.PSPath
            $propPath += '\' + $prop.Name
            if(Get-IfSafeExecutable $InitialProgram.($prop.Name))
            {
              continue
            }
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Terminal Services InitialProgram' -Classification 'Uncatalogued Technique N.8' -Path $propPath -Value $InitialProgram.($prop.Name) -AccessGained 'System/User' -Note "The executable in the InitialProgram property of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services is run when a Remote Desktop Connection is made to the target machine. Gained access depends on whether the key is in the system hive or a user's hive. For this technique to work, the fInheritInitialProgram property of the same key must also be set to 1." -Reference 'https://persistence-info.github.io/Data/tsinitialprogram.html'
            $null = $persistenceObjectArray.Add($PersistenceObject)
          }
        }
      }
      Write-Verbose -Message '' 
    }
    
    function Get-AccessibilityTools
    {   
      Write-Verbose -Message "$hostname - Looking for accessibility tools backdoors..."
      
      $accessibilityTools = @(
        "$env:windir\System32\sethc.exe",
        "$env:windir\System32\osk.exe",
        "$env:windir\System32\Narrator.exe",
        "$env:windir\System32\Magnify.exe",
        "$env:windir\System32\DisplaySwitch.exe"
      )
      
      $cmdHash = Get-FileHash -LiteralPath $env:windir\System32\cmd.exe
      $psHash = Get-FileHash -LiteralPath $env:windir\System32\WindowsPowerShell\v1.0\powershell.exe
      $explorerHash = Get-FileHash -LiteralPath $env:windir\explorer.exe
      
      $backdoorHashes = [ordered]@{
        $cmdHash.Hash = "$env:windir\System32\cmd.exe";
        $psHash.Hash = "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe";
        $explorerHash.Hash = "$env:windir\explorer.exe"
      }
      
      foreach($tool in $accessibilityTools)
      {
        if((Get-AuthenticodeSignature -FilePath $tool).IsOSBinary -ne $true)
        {
          Write-Verbose -Message "$hostname - [!] Found a suspicious executable in place of of the accessibility tool $tool"
          $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Accessibility Tools Backdoor' -Classification 'MITRE ATT&CK T1546.008' -Path $tool -Value $tool -AccessGained 'System' -Note "Accessibility tools are executables that can be run from the lock screen of a Windows machine and are supposed to enable accessibility features like text to speech or zooming in on the screen. If an attacker replaces them with malicious or LOLBIN executables they can execute code with SYSTEM permission from a lock screen, effectively bypassing authentication. In this case, the accessibility tool in the Path field is not an OS executable, so it may have been replaced with a malicious, non-Microsoft executable." -Reference 'https://attack.mitre.org/techniques/T1546/008/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
        }
        else
        {
          $toolHash = Get-FileHash -LiteralPath $tool
          foreach($hash in $backdoorHashes.Keys)
          { 
            if($toolHash.Hash -eq $hash)
            {
              Write-Verbose -Message "$hostname - [!] Found a suspicious executable in place of of the accessibility tool $tool"
              $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Accessibility Tools Backdoor' -Classification 'MITRE ATT&CK T1546.008' -Path $tool -Value $backdoorHashes[$hash] -AccessGained 'System' -Note "Accessibility tools are executables that can be run from the lock screen of a Windows machine and are supposed to enable accessibility features like text to speech or zooming in on the screen. If an attacker replaces them with malicious or LOLBIN executables they can execute code with SYSTEM permission from a lock screen, effectively bypassing authentication. In this case, the accessibility tool in the Path field has been replaced with the binary in the Value field." -Reference 'https://attack.mitre.org/techniques/T1546/008/'
              $null = $persistenceObjectArray.Add($PersistenceObject)
            }
          }
        }
      }
      Write-Verbose -Message ''
    }
    
    function Get-AMSIProviders
    {
      Write-Verbose -Message "$hostname - Getting AMSI providers..."
      $legitAMSIGUID = '{2781761E-28E0-4109-99FE-B9D127C57AFE}' # this is the GUID of Microsoft's legitimate AMSI provider
      $amsiProviders = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\" 
      foreach($key in $amsiProviders)
      {
        $keyGUID = $key.PSChildName
        if($keyGUID -eq $legitAMSIGUID)
        {
          continue
        }
        Write-Verbose -Message "$hostname - [!] Found an unknown AMSI provider under the key HKLM\SOFTWARE\Microsoft\AMSI\Providers\$keyGUID which deserves investigation!"
        $path = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\CLSID\$keyGUID\InprocServer32" -Name '(Default)').'(Default)'
        if (-not ($path -like '*.dll')) # if the DLL is specified without a .dll, append it
        {
          $path = $path + '.dll'
        }
        if(([System.IO.Path]::IsPathRooted([System.Environment]::ExpandEnvironmentVariables($path))) -eq $false) # if the DLL is specified without a path, assume it's under System32
        {
          $path = "C:\Windows\System32\$path"
        }
        $propPath = "HKLM:\SOFTWARE\Classes\CLSID\$keyGUID\InprocServer32\(Default)"
        $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Fake AMSI Provider' -Classification 'Uncatalogued Technique N.9' -Path $propPath -Value $path -AccessGained 'System/User' -Note 'DLLs in the (Default) property of HKLM:\SOFTWARE\Classes\CLSID\$keyGUID\InprocServer32 where $keyGUID is a GUID listed under HKLM:\SOFTWARE\Microsoft\AMSI\Providers\ are considered AMSI providers and loaded by all processes also loading the .NET CLR.' -Reference 'https://b4rtik.github.io/posts/antimalware-scan-interface-provider-for-persistence/'
        $null = $persistenceObjectArray.Add($PersistenceObject)
      }
      
      Write-Verbose -Message ''
    }
    
    function Get-PowershellProfiles
    {
      Write-Verbose -Message "$hostname - Getting Powershell profiles..."
      $script:powershellProfilesArray = [Collections.ArrayList]::new()
      $systemProfile = Get-ChildItem 'C:\Windows\System32\WindowsPowerShell\v1.0\Profile.ps1'
      $microsoftSystemProfile = Get-ChildItem 'C:\Windows\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1'
      if($systemProfile)
      {
        $null = $powershellProfilesArray.Add($systemProfile)
      }
      if($microsoftSystemProfile)
      {
        $null = $powershellProfilesArray.Add($microsoftSystemProfile)
      }
      $userDirectories = Get-ChildItem -Path 'C:\Users\'
      foreach($directory in $userDirectories)
      {
        $userProfile = Get-ChildItem -Path "$($directory.FullName)\Documents\WindowsPowerShell\Profile.ps1"
        if($userProfile)
        {
          $null = $powershellProfilesArray.Add($userProfile)
        }
        $userProfile = Get-ChildItem -Path "$($directory.FullName)\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
        if($userProfile)
        {
          $null = $powershellProfilesArray.Add($userProfile)
        }
      }
      foreach($profile in $powershellProfilesArray)
      {
        Write-Verbose -Message "$hostname - [!] Found a Powershell profile under $($profile.FullName) which deserves investigation!"
        $path = $profile
        $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Powershell Profile' -Classification 'MITRE ATT&CK T1546.013' -Path $path.DirectoryName -Value $path.FullName -AccessGained 'User' -Note "Files named 'Profile.ps1' or 'Microsoft.PowerShell_profile.ps1' under System32's Powershell directory or a user's Documents\WindowsPowerShell folder are loaded whenever a user launches Powershell."  -Reference 'https://attack.mitre.org/techniques/T1546/013/'
        $null = $persistenceObjectArray.Add($PersistenceObject)
      }
      Write-Verbose -Message ''
    }
    
    function Get-SilentExitMonitor
    {
      Write-Verbose -Message "$hostname - Getting Silent exit monitors..."
      $exitMonitors = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\"
      foreach($key in $exitMonitors)
      {
        $monitoredApp = $key.PSPath
        $monitoringApp = (Get-ItemProperty $monitoredApp).MonitorProcess
        Write-Verbose -Message "$hostname - [!] Found a silently monitored process under HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\ which deserves investigation!"
        $propPath = Convert-Path -Path $monitoredApp
        $propPath += '\MonitorProcess'
        $path = $monitoringApp
        if(([System.IO.Path]::IsPathRooted([System.Environment]::ExpandEnvironmentVariables($path))) -eq $false) # if the exe is specified without a path, try to get it with Get-Command
        {
          $path = (Get-Command $path).Source
        }
        $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Silent Process Exit Monitor' -Classification 'MITRE ATT&CK T1546.012' -Path $propPath -Value $path -AccessGained 'System/User' -Note 'Executables specified under subkeys of HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\ are run when the process associated with the subkey is terminated by another process.' -Reference 'https://attack.mitre.org/techniques/T1546/012/'
        $null = $persistenceObjectArray.Add($PersistenceObject)
      }
      
      Write-Verbose -Message ''
    }
    
    function Get-TelemetryController
    {
      Write-Verbose -Message "$hostname - Getting Telemetry controllers..."
      $telemetryController = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController").Command
      if($telemetryController)
      {
        $propPath = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController\Command'
        $path = $telemetryController
        if(([System.IO.Path]::IsPathRooted([System.Environment]::ExpandEnvironmentVariables($path))) -eq $false) # if the exe is specified without a path, try to get it with Get-Command
        {
          $path = (Get-Command $path).Source
        }
        $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Telemetry Controller Command' -Classification 'Uncatalogued Technique N.10' -Path $propPath -Value $path -AccessGained 'System' -Note "Executables specified under the Command property of HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController\ are run by the Windows Compatibility Telemetry's binary named CompatTelRunner.exe" -Reference 'https://www.trustedsec.com/blog/abusing-windows-telemetry-for-persistence/'
        $null = $persistenceObjectArray.Add($PersistenceObject)
      } 
      Write-Verbose -Message ''
    }
    
    function Get-RDPWDSStartupPrograms
    {
      Write-Verbose -Message "$hostname - Getting RDP WDS startup programs"
      $startupPrograms = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd").StartupPrograms
      if($startupPrograms)
      {
        $executables = $startupPrograms.split(',')
        foreach($exe in $executables)
        {
          if($exe -eq 'rdpclip')
          {
            continue
          }
          $propPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms'
          $path = $exe
          if(([System.IO.Path]::IsPathRooted([System.Environment]::ExpandEnvironmentVariables($path))) -eq $false) # if the exe is specified without a path, try to get it with Get-Command
          {
            $path = (Get-Command $path).Source
          }
          $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'RDP WDS Startup Programs' -Classification 'Uncatalogued Technique N.11' -Path $propPath -Value $path -AccessGained 'System' -Note "Executables specified under the StartupPrograms property of HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd are run whenever a user logs on the machine through remote desktop." -Reference 'https://persistence-info.github.io/Data/rdpwdstartupprograms.html'
          $null = $persistenceObjectArray.Add($PersistenceObject)
        } 
      }
      Write-Verbose -Message ''
    }
    
    function Get-ScheduledTasks
    {
      Write-Verbose -Message "$hostname - Getting scheduled tasks"
      $tasks = Get-ScheduledTask
      if($tasks)
      {
        foreach($task in $tasks)
        {
          $propPath = $task.TaskPath
          $propPath += $task.TaskName
          $path = ($task.Actions).Execute + " " + ($task.Actions).Arguments
          if($task.UserId -eq 'SYSTEM')
          {
            $access = 'System'
          }
          else
          {
            $access = 'User'
          }
          
          $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Scheduled Task' -Classification 'MITRE ATT&CK T1053.005' -Path $propPath -Value $path -AccessGained $access -Note "Scheduled tasks run executables or actions when certain conditions, such as user log in or machine boot up, are met." -Reference 'https://attack.mitre.org/techniques/T1053/005/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
        } 
      }
      Write-Verbose -Message ''
    }

    function Get-BitsJobsNotifyCmdLine
    {
      Write-Verbose -Message "$hostname - Getting BITS Jobs"
      $jobs =  Get-BitsTransfer -AllUsers | Where-Object {$_.JobState -eq "Error" } | Where-Object {$_.NotifyCmdLine.Length -gt 0}
      if($jobs)
      {
        foreach($job in $jobs)
        {
          $propPath += $job.JobId
          $path = $job.NotifyCmdLine
          if($job.OwnerAccount -eq 'NT AUTHORITY\SYSTEM')
          {
            $access = 'System'
          }
          else
          {
            $access = 'User'
          }
          
          $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'BITS Job NotifyCmdLine' -Classification 'MITRE ATT&CK T1197.003' -Path $propPath -Value $path -AccessGained $access -Note "Windows Background Intelligent Transfer Service (BITS) can be used to persistently execute code by creating long-standing jobs. Specifically, if an attacker sets the SetNotifyCmdLine when creating a job which will error, the executable specified will be run everytime the BITS job fails." -Reference 'https://attack.mitre.org/techniques/T1197/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
        } 
      }
      Write-Verbose -Message ''
    }
    
    function Get-Screensaver
    {
      Write-Verbose -Message "$hostname - Getting Screensaver programs"
      foreach($sid in $systemAndUsersHives) 
      {
        $legitimatePrograms = "C:\Windows\system32\Mystify.scr", "C:\Windows\system32\Ribbons.scr", "C:\Windows\system32\Bubbles.scr", "C:\Windows\system32\ssText3d.scr", "C:\Windows\system32\scrnsave.scr", "C:\Windows\system32\PhotoScreensaver.scr"
        $screenSaverProgram = (Get-ItemProperty -ErrorAction SilentlyContinue -Path "$sid\Control Panel\Desktop\" -Name "SCRNSAVE.exe")
        if(($screenSaverProgram) -and ($screenSaverProgram."SCRNSAVE.EXE" -ne ""))
        {
          $executable = $screenSaverProgram."SCRNSAVE.EXE"
          if ($legitimatePrograms.Contains($Executable)) {
            continue
          }
          $propPath = Convert-Path -Path $screenSaverProgram.PSPath
          $propPath = $propPath + "SCRNSAVE.EXE"

          $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Suspicious Screensaver Program' -Classification 'MITRE ATT&CK T1546.002' -Path $propPath -Value $executable -AccessGained 'User' -Note "Executables specified under the SCRNSAVE.EXE property of the HKEY_USERS\<SID>\Control Panel\Desktop key will be run in place of the legitimate screensaver, thus achieving persistence on a compromised machine. " -Reference 'https://attack.mitre.org/techniques/T1546/002/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
        }
      }
      Write-Verbose -Message ''
    }
    
    function Get-OfficeTemplates
    {
      Write-Verbose -Message "$hostname - Checking if users' Office folders contains interesting templates..."
      $userDirectories = Get-ChildItem -Path 'C:\Users\'
      foreach($directory in $userDirectories)
      {
        $addins = Get-ChildItem -Path "$($directory.FullName)\AppData\Roaming\Microsoft\Word\STARTUP\" 
        $addins += Get-ChildItem -Path "$($directory.FullName)\AppData\Roaming\Microsoft\Templates\" -Filter *.dotm
        $addins += Get-ChildItem -Path "$($directory.FullName)\AppData\Roaming\Microsoft\Excel\XLSTART\"
        $addins += Get-ChildItem -Path "$($directory.FullName)\AppData\Roaming\Microsoft\AddIns\"
        $addins += Get-ChildItem -Path "$($directory.FullName)\AppData\Roaming\Microsoft\Outlook\" -Filter *.OTM
        foreach($file in $addins)
        {
          $fullname = $file.FullName
          $path = Split-Path -Path $fullname
          Write-Verbose -Message "$hostname - Found $fullname"
          $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Office Application Startup' -Classification 'MITRE ATT&CK T1137.001' -Path "$path\" -Value "$fullname" -AccessGained 'User' -Note "Attackers can drop macro-enabled files in specific folders to trigger their execution every time the victim user opens an Office application." -Reference 'https://attack.mitre.org/techniques/T1137/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
        }
      }
      Write-Verbose -Message ''
    }
    
    function Get-ExplorerContextMenu
    {
      Write-Verbose -Message "$hostname - Checking for Explorer Context Menu hijacking..."
      $path = (Get-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\{B7CDF620-DB73-44C0-8611-832B261A0107}" -Name '(Default)').'(Default)'
      if($null -ne $path)
      {  
        if(([System.IO.Path]::IsPathRooted([System.Environment]::ExpandEnvironmentVariables($path))) -eq $false)
        {
          $path = "C:\Windows\System32\$path"
        }
      
        Write-Verbose -Message "$hostname - [!] Found a DLL in the (Default) property of the 'HKCR:\AllFilesystemObjects\shellex\ContextMenuHandlers\{B7CDF620-DB73-44C0-8611-832B261A0107}' key which deserve investigation!"
        $propPath = 'HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\{B7CDF620-DB73-44C0-8611-832B261A0107}\(Default)'
        $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Explorer Tools Hijacking' -Classification 'Uncatalogued Technique N.13' -Path $propPath -Value $path -AccessGained 'User' -Note 'DLLs in the (Default) property of the "HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\{B7CDF620-DB73-44C0-8611-832B261A0107}" key are run when the user right clicks any explorer Window.' -Reference 'https://ristbs.github.io/2023/02/15/hijack-explorer-context-menu-for-persistence-and-fun.html'
        $null = $persistenceObjectArray.Add($PersistenceObject)
      }
      Write-Verbose -Message ''
    }
    
    function Get-ServiceControlManagerSecurityDescriptor
    {
      Write-Verbose -Message "$hostname - Checking for manipulation of the security descriptor of the Service Control Manager..."
      
      $currentSDDL = (sc.exe sdshow scmanager) -join ''
      $defaultSDDL = 'D:(A;;CC;;;AU)(A;;CCLCRPRC;;;IU)(A;;CCLCRPRC;;;SU)(A;;CCLCRPWPRC;;;SY)(A;;KA;;;BA)(A;;CC;;;AC)(A;;CC;;;S-1-15-3-1024-528118966-3876874398-709513571-1907873084-3598227634-3698730060-278077788-3990600205)S:(AU;FA;KA;;;WD)(AU;OIIOFA;GA;;;WD)'

      if($defaultSDDL -eq $currentSDDL)
      {
        return
      }

      Write-Verbose -Message "$hostname - [!] It looks like the Security Descriptor of the Service Control Manager is not set to the default value and should be investigated."
      $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Service Control Manager Security Descriptor Manipulation' -Classification 'Uncatalogued Technique N.14' -Path 'N/A' -Value $currentSDDL -AccessGained 'System' -Note 'The Service Control Manager is the software responsible for starting and stopping services in the Windows OS. If its ACL is loosely set, it would be possible for a non administrative process to start administrative processes by creating a service running with high or SYSTEM privileges.' -Reference 'https://pentestlab.blog/2023/03/20/persistence-service-control-manager/'
      $null = $persistenceObjectArray.Add($PersistenceObject)
      Write-Verbose -Message ''
    }
    
    function Get-MicrosoftOfficeAIHijacking
    {
      Write-Verbose -Message "$hostname - Checking for the hijacking of the Microsoft Office AI.exe executable..."
      
      $officex64Dir = [System.Environment]::ExpandEnvironmentVariables('%ProgramFiles%\Microsoft Office\root\')
      
      $officex86Dir = [System.Environment]::ExpandEnvironmentVariables('%PROGRAMFILES(X86)%\Microsoft Office\root\')
      
      $paths = @(Get-ChildItem $officex64Dir)
      $paths += @(Get-ChildItem $officex86Dir)
      
      foreach($path in $paths)
      {  
        if((Test-Path -Path "$($path.FullName)\ai.exe") -eq $false)
        {
          continue
        }
      
        Write-Verbose -Message "$hostname - [!] Found AI.exe under an Office path which deserve investigation!"
        $propPath = $path.FullName
        $exePath = "$($path.FullName)\ai.exe"
        $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Microsoft Office AI.exe Hijacking' -Classification 'Uncatalogued Technique N.15' -Path $propPath -Value $exePath -AccessGained 'User' -Note 'Office executables like WINWORD.exe look for AI.exe under the %ProgramFiles%\Microsoft Office\root\<Office Version> and %ProgramFiles(x86)%\Microsoft Office\root\<Office Version> directories. An attacker may place a malicious AI.exe there in order to have persistence whenever a user interacts with the Microsoft Office Suite.' -Reference 'https://twitter.com/laughing_mantis/status/1645268114966470662'
        $null = $persistenceObjectArray.Add($PersistenceObject)
      }
      Write-Verbose -Message ''
    }
    
    function Get-RunExAndRunOnceEx
    {
      Write-Verbose -Message "$hostname - Getting Run properties..."
      foreach($hive in $systemAndUsersHives)
      {
        $runKeys = Get-ChildItem -Path "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx"
        foreach($key in $runKeys)
        {
          Write-Verbose -Message "$hostname - [!] Found keys under $(Convert-Path -Path $hive)'s RunEx key which deserve investigation!"
          $runProps = Get-ItemProperty -Path $key.PSPath 
          if($runProps)
          {
            Write-Verbose -Message "$hostname - [!] Found properties under a key in $(Convert-Path -Path $hive)'s RunEx key which deserve investigation!"
            foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $runProps))
            {
              if($psProperties.Contains($prop.Name)) 
              {
                continue
              } # skip the property if it's powershell built-in property
              $propPath = Convert-Path -Path $runProps.PSPath
              $propPath += '\' + $prop.Name
              $currentHive = Convert-Path -Path $hive
              if(($currentHive -eq 'HKEY_LOCAL_MACHINE') -or ($currentHive -eq 'HKEY_USERS\S-1-5-18') -or ($currentHive -eq 'HKEY_USERS\S-1-5-19') -or ($currentHive -eq 'HKEY_USERS\S-1-5-20'))
              {
                $access = 'System'
              }
              else
              {
                $access = 'User'
              }
            
              if(Get-IfSafeExecutable $runProps.($prop.Name))
              {
                continue
              }
              $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Registry RunEx Key' -Classification 'MITRE ATT&CK T1547.001' -Path $propPath -Value $runProps.($prop.Name) -AccessGained $access -Note 'Executables in properties of any key under the (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx key are run when the user logs in or when the machine boots up (in the case of the HKLM hive).' -Reference 'https://attack.mitre.org/techniques/T1547/001/' 
              $null = $persistenceObjectArray.Add($PersistenceObject)
            }
          }
        }
      }
    
      Write-Verbose -Message ''
      Write-Verbose -Message "$hostname - Getting RunOnce properties..."
      foreach($hive in $systemAndUsersHives)
      {
        $runOnceKeys = Get-ChildItem -Path "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"
        foreach($key in $runOnceKeys)
        {
          Write-Verbose -Message "$hostname - [!] Found keys under $(Convert-Path -Path $hive)'s RunOnceEx key which deserve investigation!"
          $runOnceProps = Get-ItemProperty -Path $key.PSPath
         
          if($runOnceProps)
          {
            Write-Verbose -Message "$hostname - [!] Found properties under a key in $(Convert-Path -Path $hive)'s RunOnceEx key which deserve investigation!"
            foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $runOnceProps))
            {
              if($psProperties.Contains($prop.Name)) 
              {
                continue
              } # skip the property if it's powershell built-in property
              $propPath = Convert-Path -Path $runOnceProps.PSPath
              $propPath += '\' + $prop.Name
              $currentHive = Convert-Path -Path $hive
              if(($currentHive -eq 'HKEY_LOCAL_MACHINE') -or ($currentHive -eq 'HKEY_USERS\S-1-5-18') -or ($currentHive -eq 'HKEY_USERS\S-1-5-19') -or ($currentHive -eq 'HKEY_USERS\S-1-5-20'))
              {
                $access = 'System'
              }
              else
              {
                $access = 'User'
              }
              if(Get-IfSafeExecutable $runOnceProps.($prop.Name))
              {
                continue
              }
              $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Registry RunOnceEx Key' -Classification 'MITRE ATT&CK T1547.001' -Path $propPath -Value $runOnceProps.($prop.Name) -AccessGained $access -Note 'Executables in properties of any key under the (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx key are run when the user logs in or when the machine boots up (in the case of the HKLM hive), and then deleted.' -Reference 'https://attack.mitre.org/techniques/T1547/001/' 
              $null = $persistenceObjectArray.Add($PersistenceObject)
            }
          }
        }
      }
      Write-Verbose -Message ''
    }
    function Get-DotNetStartupHooks
    {
      Write-Verbose -Message "$hostname - Getting DotNet Startup Hooks..."
      foreach($hive in $systemAndUsersHives)
      {
        $dotnetHooks = (Get-ItemProperty -Path "$hive\Environment" -Name DOTNET_STARTUP_HOOKS).DOTNET_STARTUP_HOOKS
        if($dotnetHooks)
        {
          $dotnetHooks = $dotnetHooks -split ';'
        }
        foreach($hook in $dotnetHooks)
        {
          Write-Verbose -Message "$hostname - [!] Found a .NET hook in the DOTNET_STARTUP_HOOKS property in the $(Convert-Path -Path $hive)\Environment key!"
          $propPath = Convert-Path -Path $hive
          $propPath += "\Environment\DOTNET_STARTUP_HOOKS"
          $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique '.NET Startup Hooks DLL Sideloading' -Classification 'MITRE ATT&CK T1574.002' -Path $propPath -Value $hook -AccessGained 'User/System' -Note 'The .NET DLLs listed in the DOTNET_STARTUP_HOOKS environment variable are loaded into .NET processes at runtime.' -Reference 'https://persistence-info.github.io/Data/dotnetstartuphooks.html'
          $null = $persistenceObjectArray.Add($PersistenceObject) 
        }
      }
      
      $systemHooks = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name DOTNET_STARTUP_HOOKS).DOTNET_STARTUP_HOOKS
      if($systemHooks)
      {
        $systemHooks = $systemHooks -split ';'
      }
      foreach($hook in $systemHooks)
      {
        Write-Verbose -Message "$hostname - [!] Found a .NET hook in the DOTNET_STARTUP_HOOKS property in the $(Convert-Path -Path $hive)\Environment key!"
        $propPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique '.NET Startup Hooks DLL Sideloading' -Classification 'MITRE ATT&CK T1574.002' -Path $propPath -Value $hook -AccessGained 'User/System' -Note 'The .NET DLLs listed in the DOTNET_STARTUP_HOOKS environment variable are loaded into .NET processes at runtime.' -Reference 'https://persistence-info.github.io/Data/dotnetstartuphooks.html'
        $null = $persistenceObjectArray.Add($PersistenceObject) 
      }
      
      Write-Verbose -Message ''   
    }
    
    function Out-EventLog 
    {

      Param (

        [Parameter(Mandatory = $true)]
        [Collections.ArrayList]$Findings

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
        $evtlog = "Application"
        $source = "PersistenceSniper"


        if ([System.Diagnostics.EventLog]::SourceExists($source) -eq $false) {
          [System.Diagnostics.EventLog]::CreateEventSource($source, $evtlog)
        }

        foreach ($finding in $Findings) {
          $evtID = $EventIDMapping[$finding.technique]
          $id = New-Object System.Diagnostics.EventInstance($evtID, 1) # Info Event
          $propertiesValue = $finding.PSObject.Properties | Select-Object -ExpandProperty Value
          $evtObject = New-Object System.Diagnostics.EventLog
          $evtObject.Log = $evtlog
          $evtObject.Source = $source
          $evtObject.WriteEvent($id, $propertiesValue)
        }
      }
    }

    Write-Verbose -Message "$hostname - Starting execution..."

    if($PersistenceMethod -eq 'All')
    {
      Get-RunAndRunOnce
      Get-ImageFileExecutionOptions
      Get-NLDPDllOverridePath
      Get-AeDebug
      Get-WerFaultHangs
      Get-CmdAutoRun
      Get-ExplorerLoad
      Get-WinlogonUserinit
      Get-WinlogonShell
      Get-TerminalProfileStartOnUserLogin
      Get-AppCertDlls
      Get-ServiceDlls
      Get-GPExtensionDlls
      Get-WinlogonMPNotify
      Get-CHMHelperDll
      Get-HHCtrlHijacking
      Get-StartupPrograms
      Get-UserInitMprScript
      Get-AutodialDLL
      Get-LsaExtensions
      Get-ServerLevelPluginDll
      Get-LsaPasswordFilter
      Get-LsaAuthenticationPackages
      Get-LsaSecurityPackages
      Get-WinlogonNotificationPackages
      Get-ExplorerTools
      Get-DotNetDebugger
      Get-ErrorHandlerCmd
      Get-WMIEventsSubscrition
      Get-TSInitialProgram
      Get-AccessibilityTools
      Get-AMSIProviders
      Get-PowershellProfiles
      Get-SilentExitMonitor
      Get-TelemetryController
      Get-RDPWDSStartupPrograms
      Get-BitsJobsNotifyCmdLine
      Get-Screensaver
      Get-PowerAutomate
      Get-OfficeTemplates
      Get-ExplorerContextMenu
      Get-ServiceControlManagerSecurityDescriptor
      Get-MicrosoftOfficeAIHijacking
      Get-RunExAndRunOnceEx
      Get-DotNetStartupHooks
      
      if($IncludeHighFalsePositivesChecks.IsPresent)
      {
        Write-Verbose -Message "$hostname - You have used the -IncludeHighFalsePositivesChecks switch, this may generate a lot of false positives since it includes checks with results which are difficult to filter programmatically..."
        Get-AppPaths
        Get-WindowsServices
        Get-ScheduledTasks
      }
    }
    
    else
    {
      switch($PersistenceMethod)
      {
        'RunAndRunOnce'
        {
          Get-RunAndRunOnce
          break
        }
        'ImageFileExecutionOptions'
        {
          Get-ImageFileExecutionOptions
          break
        }
        'NLDPDllOverridePath'
        {
          Get-NLDPDllOverridePath
          break
        }
        'AeDebug'
        {
          Get-AeDebug
          break
        }
        'WerFaultHangs'
        {
          Get-WerFaultHangs
          break
        }
        'CmdAutoRun'
        {
          Get-CmdAutoRun
          break
        }
        'ExplorerLoad'
        {
          Get-ExplorerLoad
          break
        }
        'WinlogonUserinit'
        {
          Get-WinlogonUserinit
          break
        }
        'WinlogonShell'
        {
          Get-WinlogonShell
          break
        }
        'TerminalProfileStartOnUserLogin'
        {
          Get-TerminalProfileStartOnUserLogin
          break
        }
        'AppCertDlls'
        {
          Get-AppCertDlls
          break
        }
        'ServiceDlls'
        {
          Get-ServiceDlls
          break
        }
        'GPExtensionDlls'
        {
          Get-GPExtensionDlls
          break
        }
        'WinlogonMPNotify'
        {
          Get-WinlogonMPNotify
          break
        }
        'CHMHelperDll'
        {
          Get-CHMHelperDll
          break
        }
        'HHCtrlHijacking'
        {
          Get-HHCtrlHijacking
          break
        }
        'StartupPrograms'
        {
          Get-StartupPrograms
          break
        }
        'UserInitMprScript'
        {
          Get-UserInitMprScript
          break
        }
        'AutodialDLL'
        {
          Get-AutodialDLL
          break
        }
        'LsaExtensions'
        {
          Get-LsaExtensions       
          break  
        }
        'ServerLevelPluginDll'
        {
          Get-ServerLevelPluginDll
          break        
        }
        'LsaPasswordFilter'
        {
          Get-LsaPasswordFilter
          break         
        }
        'LsaAuthenticationPackages'
        {
          Get-LsaAuthenticationPackages
          break          
        }
        'LsaSecurityPackages'
        {
          Get-LsaSecurityPackages 
          break         
        }
        'WinlogonNotificationPackages'
        {
          Get-WinlogonNotificationPackages
          break          
        }
        'ExplorerTools'
        {
          Get-ExplorerTools
          break          
        }
        'DotNetDebugger'
        {
          Get-DotNetDebugger
          break         
        }
        'ErrorHandlerCmd'
        {
          Get-ErrorHandlerCmd
          break
        }
        'WMIEventsSubscrition'
        {
          Get-WMIEventsSubscrition
          break
        }
        'WindowsServices'
        {
          Get-WindowsServices
          break
        }
        'AppPaths'
        {
          Get-AppPaths
          break
        }
        'TerminalServicesInitialProgram'
        {
          Get-TSInitialProgram
          break
        }
        'AccessibilityTools'
        {
          Get-AccessibilityTools
          break
        }
        'AMSIProviders'
        {
          Get-AMSIProviders
          break
        }
        'PowershellProfiles'
        {
          Get-PowershellProfiles
          break
        }
        'SilentExitMonitor'
        {
          Get-SilentExitMonitor
          break
        }
        'TelemetryController'
        {
          Get-TelemetryController
          break
        }
        'RDPWDSStartupPrograms'
        {
          Get-RDPWDSStartupPrograms
          break
        }
        'ScheduledTasks'
        {
          Get-ScheduledTasks
          break
        }

        'Screensaver'
        {
          Get-Screensaver
          break
        }

        'BitsJobsNotify'
        {
          Get-BitsJobsNotifyCmdLine
          break
        }
        'PowerAutomate'
        {
          Get-PowerAutomate
          break
        }
        'Services'
        {
          Get-WindowsServices 
          break
        }
        'ScheduledTasks'
        {
          Get-ScheduledTasks
          break
        }
        'OfficeAddinsAndTemplates'
        {
          Get-OfficeTemplates
          break
        }
        'ExplorerContextMenu'
        {
          Get-ExplorerContextMenu
          break
        }
        'ServiceControlManagerSD'
        {
          Get-ServiceControlManagerSecurityDescriptor
          break
        }
        'OfficeAiHijacking'
        {
          Get-MicrosoftOfficeAIHijacking
          break
        }
        'RunExAndRunOnceEx'
        {
          Get-RunExAndRunOnceEx
          break
        }
        'DotNetStartupHooks'
        {
          Get-DotNetStartupHooks
          break
        }
      }
    }
    
    if($LogFindings.IsPresent)
    {
      Write-Verbose -Message "$hostname - You have used the -LogFindings switch, what's been found on the machine will be saved in the Event Log."
      Out-EventLog $persistenceObjectArray
    }
    
    # Save all the techniques found on this machine in the global array.
    foreach($finding in $persistenceObjectArray)
    {
      $null = $globalPersistenceObjectArray.Add($finding)
    }
    
    Write-Verbose -Message "$hostname - Execution finished, outputting results..."
  }
  
  if($ComputerName)
  {
    Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -ErrorAction Continue
  }
  else
  {
    Invoke-Command -ScriptBlock $ScriptBlock
  }
  
  
  # Use input CSV to make a diff of the results and only show us the persistences implanted on the machine which are not in the CSV
  if($DiffCSV)
  {
    Write-Verbose -Message 'Diffing found persistences with the ones in the input CSV...'
    $importedPersistenceObjectArray = Import-Csv -Path $DiffCSV -ErrorAction Stop
    $newPersistenceObjectArray = New-Object -TypeName System.Collections.ArrayList
    foreach($localPersistence in $globalPersistenceObjectArray)
    {
      $found = $false
      foreach($importedPersistence in $importedPersistenceObjectArray)
      {
        if(($importedPersistence.Technique -eq $localPersistence.Technique) -and ($importedPersistence.Path -eq $localPersistence.Path) -and ($importedPersistence.Value -eq $localPersistence.Value))
        {
          $found = $true
          break
        }
      }
      if($found -eq $false)
      {
        $null = $newPersistenceObjectArray.Add($localPersistence)
      }
    }
    $globalPersistenceObjectArray = $newPersistenceObjectArray.Clone()
  }
  
  if($OutputCSV)
  {
    $globalPersistenceObjectArray |
    ConvertTo-Csv -NoTypeInformation |
    Out-File -FilePath $OutputCSV -ErrorAction Stop
  }
  else
  {
    # Output the final result to stdin
    $globalPersistenceObjectArray
  }
  
  Write-Verbose -Message 'Module execution finished.'  
}

# SIG # Begin signature block
# MIIVlQYJKoZIhvcNAQcCoIIVhjCCFYICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUugbqmFxTxEfYG1PWUjAJKz+X
# OoWgghH1MIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
# AQwFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVy
# MRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEh
# MB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTIxMDUyNTAwMDAw
# MFoXDTI4MTIzMTIzNTk1OVowVjELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3Rp
# Z28gTGltaXRlZDEtMCsGA1UEAxMkU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5n
# IFJvb3QgUjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjeeUEiIE
# JHQu/xYjApKKtq42haxH1CORKz7cfeIxoFFvrISR41KKteKW3tCHYySJiv/vEpM7
# fbu2ir29BX8nm2tl06UMabG8STma8W1uquSggyfamg0rUOlLW7O4ZDakfko9qXGr
# YbNzszwLDO/bM1flvjQ345cbXf0fEj2CA3bm+z9m0pQxafptszSswXp43JJQ8mTH
# qi0Eq8Nq6uAvp6fcbtfo/9ohq0C/ue4NnsbZnpnvxt4fqQx2sycgoda6/YDnAdLv
# 64IplXCN/7sVz/7RDzaiLk8ykHRGa0c1E3cFM09jLrgt4b9lpwRrGNhx+swI8m2J
# mRCxrds+LOSqGLDGBwF1Z95t6WNjHjZ/aYm+qkU+blpfj6Fby50whjDoA7NAxg0P
# OM1nqFOI+rgwZfpvx+cdsYN0aT6sxGg7seZnM5q2COCABUhA7vaCZEao9XOwBpXy
# bGWfv1VbHJxXGsd4RnxwqpQbghesh+m2yQ6BHEDWFhcp/FycGCvqRfXvvdVnTyhe
# Be6QTHrnxvTQ/PrNPjJGEyA2igTqt6oHRpwNkzoJZplYXCmjuQymMDg80EY2NXyc
# uu7D1fkKdvp+BRtAypI16dV60bV/AK6pkKrFfwGcELEW/MxuGNxvYv6mUKe4e7id
# FT/+IAx1yCJaE5UZkADpGtXChvHjjuxf9OUCAwEAAaOCARIwggEOMB8GA1UdIwQY
# MBaAFKARCiM+lvEH7OKvKe+CpX/QMKS0MB0GA1UdDgQWBBQy65Ka/zWWSC8oQEJw
# IDaRXBeF5jAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUE
# DDAKBggrBgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEMGA1Ud
# HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FBQUNlcnRpZmlj
# YXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBDAUAA4IBAQASv6Hvi3Sa
# mES4aUa1qyQKDKSKZ7g6gb9Fin1SB6iNH04hhTmja14tIIa/ELiueTtTzbT72ES+
# BtlcY2fUQBaHRIZyKtYyFfUSg8L54V0RQGf2QidyxSPiAjgaTCDi2wH3zUZPJqJ8
# ZsBRNraJAlTH/Fj7bADu/pimLpWhDFMpH2/YGaZPnvesCepdgsaLr4CnvYFIUoQx
# 2jLsFeSmTD1sOXPUC4U5IOCFGmjhp0g4qdE2JXfBjRkWxYhMZn0vY86Y6GnfrDyo
# XZ3JHFuu2PMvdM+4fvbXg50RlmKarkUT2n/cR/vfw1Kf5gZV6Z2M8jpiUbzsJA8p
# 1FiAhORFe1rYMIIGGjCCBAKgAwIBAgIQYh1tDFIBnjuQeRUgiSEcCjANBgkqhkiG
# 9w0BAQwFADBWMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MS0wKwYDVQQDEyRTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYw
# HhcNMjEwMzIyMDAwMDAwWhcNMzYwMzIxMjM1OTU5WjBUMQswCQYDVQQGEwJHQjEY
# MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSswKQYDVQQDEyJTZWN0aWdvIFB1Ymxp
# YyBDb2RlIFNpZ25pbmcgQ0EgUjM2MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIB
# igKCAYEAmyudU/o1P45gBkNqwM/1f/bIU1MYyM7TbH78WAeVF3llMwsRHgBGRmxD
# eEDIArCS2VCoVk4Y/8j6stIkmYV5Gej4NgNjVQ4BYoDjGMwdjioXan1hlaGFt4Wk
# 9vT0k2oWJMJjL9G//N523hAm4jF4UjrW2pvv9+hdPX8tbbAfI3v0VdJiJPFy/7Xw
# iunD7mBxNtecM6ytIdUlh08T2z7mJEXZD9OWcJkZk5wDuf2q52PN43jc4T9OkoXZ
# 0arWZVeffvMr/iiIROSCzKoDmWABDRzV/UiQ5vqsaeFaqQdzFf4ed8peNWh1OaZX
# nYvZQgWx/SXiJDRSAolRzZEZquE6cbcH747FHncs/Kzcn0Ccv2jrOW+LPmnOyB+t
# AfiWu01TPhCr9VrkxsHC5qFNxaThTG5j4/Kc+ODD2dX/fmBECELcvzUHf9shoFvr
# n35XGf2RPaNTO2uSZ6n9otv7jElspkfK9qEATHZcodp+R4q2OIypxR//YEb3fkDn
# 3UayWW9bAgMBAAGjggFkMIIBYDAfBgNVHSMEGDAWgBQy65Ka/zWWSC8oQEJwIDaR
# XBeF5jAdBgNVHQ4EFgQUDyrLIIcouOxvSK4rVKYpqhekzQwwDgYDVR0PAQH/BAQD
# AgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwGwYD
# VR0gBBQwEjAGBgRVHSAAMAgGBmeBDAEEATBLBgNVHR8ERDBCMECgPqA8hjpodHRw
# Oi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmluZ1Jvb3RS
# NDYuY3JsMHsGCCsGAQUFBwEBBG8wbTBGBggrBgEFBQcwAoY6aHR0cDovL2NydC5z
# ZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25pbmdSb290UjQ2LnA3YzAj
# BggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJKoZIhvcNAQEM
# BQADggIBAAb/guF3YzZue6EVIJsT/wT+mHVEYcNWlXHRkT+FoetAQLHI1uBy/YXK
# ZDk8+Y1LoNqHrp22AKMGxQtgCivnDHFyAQ9GXTmlk7MjcgQbDCx6mn7yIawsppWk
# vfPkKaAQsiqaT9DnMWBHVNIabGqgQSGTrQWo43MOfsPynhbz2Hyxf5XWKZpRvr3d
# MapandPfYgoZ8iDL2OR3sYztgJrbG6VZ9DoTXFm1g0Rf97Aaen1l4c+w3DC+IkwF
# kvjFV3jS49ZSc4lShKK6BrPTJYs4NG1DGzmpToTnwoqZ8fAmi2XlZnuchC4NPSZa
# PATHvNIzt+z1PHo35D/f7j2pO1S8BCysQDHCbM5Mnomnq5aYcKCsdbh0czchOm8b
# kinLrYrKpii+Tk7pwL7TjRKLXkomm5D1Umds++pip8wH2cQpf93at3VDcOK4N7Ew
# oIJB0kak6pSzEu4I64U6gZs7tS/dGNSljf2OSSnRr7KWzq03zl8l75jy+hOds9TW
# SenLbjBQUGR96cFr6lEUfAIEHVC1L68Y1GGxx4/eRI82ut83axHMViw1+sVpbPxg
# 51Tbnio1lB93079WPFnYaOvfGAA0e0zcfF/M9gXr+korwQTh2Prqooq2bYNMvUoU
# KD85gnJ+t0smrWrb8dee2CvYZXD5laGtaAxOfy/VKNmwuWuAh9kcMIIGYDCCBMig
# AwIBAgIRANqGcyslm0jf1LAmu7gf13AwDQYJKoZIhvcNAQEMBQAwVDELMAkGA1UE
# BhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDErMCkGA1UEAxMiU2VjdGln
# byBQdWJsaWMgQ29kZSBTaWduaW5nIENBIFIzNjAeFw0yMjA4MzAwMDAwMDBaFw0y
# NTA4MjkyMzU5NTlaMFQxCzAJBgNVBAYTAklUMQ0wCwYDVQQIDARSb21hMRowGAYD
# VQQKDBFGZWRlcmljbyBMYWdyYXN0YTEaMBgGA1UEAwwRRmVkZXJpY28gTGFncmFz
# dGEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCWUdcGbyUbCFFFZ6Mj
# e/e1M0dGv9oWUKwB6O1XNQGLG5wMpsiJZRc1w6uV9iYsqIb2K5MyrbL7YNhMMgSv
# JGM51OCphdX4MN2JKyG8oZs0CGnMfKckJfNw0rukD513VlL9s34Y1A+4xyfdgJ8q
# pKz455vUM5PA3emF6ydRwdAa7vPRATqKqa/E6jUABluW0juMsMwNLucJeudD4lvL
# INY8WBxdb7U6a9XmMqW67DdrrE93nenuDF1VYL3R4s0c9bYXvnLF45im/NjMnK+F
# MJZfZq1OuE7DsTKNQ2KLru5i5luZAYnrFEP9U2oGZI1G149beOuzGBVju5TS5yqr
# L9uVOaoRxvHpFUuZXE9Wxn7eNTAuA1NBfSqvwlJuL9xLStCR+Ep20euMihqKyROV
# Jy/UbXbA9haB9D4xnGWPhdMbzh62og2taeCyUSR/ITznssDa8gj2Zz2dqdKI985M
# BWlb+rIcnhTvfguBLo5aGvOcTepcxjcgs7WRq9AoL+tmXsFlHbnenmOXeyypfS1B
# /L3WVND4sKU4RImFw1DHRUdUhtzv/OzXWn1MyTH/W1v0L8AMe/5YBmexHlcOaB05
# xZJNxy3BQVXg/DEWAgIdZlatw7vrTPzROV4VPUkU1IPe/ZCJNe9Ij2ICa2kmb2I1
# 8dVZ3m1o8T8P6Lq1rB/+d8yTMQIDAQABo4IBqzCCAacwHwYDVR0jBBgwFoAUDyrL
# IIcouOxvSK4rVKYpqhekzQwwHQYDVR0OBBYEFD9Q0l33XgRE0bG3DGVYiX6xoX03
# MA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUF
# BwMDMEoGA1UdIARDMEEwNQYMKwYBBAGyMQECAQMCMCUwIwYIKwYBBQUHAgEWF2h0
# dHBzOi8vc2VjdGlnby5jb20vQ1BTMAgGBmeBDAEEATBJBgNVHR8EQjBAMD6gPKA6
# hjhodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmlu
# Z0NBUjM2LmNybDB5BggrBgEFBQcBAQRtMGswRAYIKwYBBQUHMAKGOGh0dHA6Ly9j
# cnQuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nQ0FSMzYuY3J0
# MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTAgBgNVHREEGTAX
# gRVmZWQubGFnQHByb3Rvbm1haWwuY2gwDQYJKoZIhvcNAQEMBQADggGBAJj2JGru
# B4OuFoVRe64Tj83gGZbenpMtVVzLsSXzqoYv9Xy/+DdgQpBCksbCM7lL+BXbjlrO
# aRAhtshMcPXyKC0LyUK/97fmuZSEd0uJv+5bA+8J+syr/Bm7mfy+Wp0y3vN/rH0Y
# 6OuUm8YVnEsh3dN5LkYBtht0E4uOMhaAY8FvQ+UqoVO64IEYGZvfeIQxpeoOFcZ6
# LXNTEPwUsXT6aBwrdzXoTthdzYPG1OZscG5t1A+Q4FzjPgye0asKDEcL6nIiLsgn
# KFwVxJoOvSg+xpj4urUbQ5K5STKvy6FeN05JjN00w91pauOXowy+sWKsA2tk0sEj
# 7GyXN5xpdmmpS9syU0Piom/9stGkGJurdoUPNcCCagSQ6+6lDVDhxSnMroR75hIS
# lYKhmhoGgn1vWQqUwx7CywDXxMGY7GT+ufXCssa6xZT+Nn+CIaHpb4EJyrNdKN/m
# uFkQgQqZUeeV0/azIa5L9T1IaEn1xhe2ETNqZCHeGzmpmvifXW/N9+/HZDGCAwow
# ggMGAgEBMGkwVDELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRl
# ZDErMCkGA1UEAxMiU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5nIENBIFIzNgIR
# ANqGcyslm0jf1LAmu7gf13AwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAI
# oAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIB
# CzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFHfTU0Eir/IBnx9L6hLm
# 0JHi0W3fMA0GCSqGSIb3DQEBAQUABIICADK2HY6lw6970xC4OLr+6Qhmih5MeNnI
# 0HW9FxZwPCCni6fsYQBCWMJUhwWTIvcklySPcavrUZT1DfWNjJFPJVjdhAKkHJGI
# nyfKEmPK7k8MM9fqgvPE4BBoHTZdRDB+OgbBdHTtk2qpYdl25MPZrbFgAGi3Wq1K
# T//LrDGNzB0KfVgSKt95wwEMQjxFY/4vCy03MMbBGvjI1PmxjocmONGY9p1HSLgK
# /Jt+vmEhkQMHxiScMyuxeNzpUc4V0R8YnHXGnaEsiW2J+kEu8iV2D2fxCe1HiYTI
# RImP119+mhzqGpkiaKvzKee51VSULTpn/7ZrjEoDLlnaGYPqWt9srJ40C7r6Na6N
# Bx3M6MYEd76e6iv8MQbAQkRZXwbsNV+lQnpDhsAvRuw3C7u0Rj3XMK+h/tDOf/EG
# mBwXYtiUyhwpX8QDdA180/M8jL8GqUQuMc+zc8RBML3UfnnAVpV0dqbp/311plnR
# 7lFVnDDs6MUUdMWOqsZIDObuYMB+6G3/q4DlJjyclVbSnIvlyECSdZNoFQvA+mzP
# DIjkXn2XfWZ7XePCTexaHNrWpy4iTEQsWrHVENc3dGlYuCHj0nJjNTXvUxJy4Gmv
# ytFfkDxqWWwlFxxXCsa8cffpPIlHuuJMZkeE8HV8C0IEO2OrNTyoY7jSaFMHMCOV
# wm5IArd9nElv
# SIG # End signature block
