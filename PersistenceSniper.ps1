#Requires -RunAsAdministrator
function Find-AllPersistence
{ 
  <#
      .SYNOPSIS

      This script tries to enumerate all the persistence methods implanted on a compromised machine.

      Function: Find-AllPersistence
      Authors: Federico `last` Lagrasta, Twitter: @last0x00; Riccardo Ancarani, Twitter: @dottor_morte
      License: https://creativecommons.org/publicdomain/zero/1.0/
      Required Dependencies: None
      Optional Dependencies: None

      .DESCRIPTION

      Enumerate all the persistence methods found on a machine and print them for the user to see.

      .PARAMETER DiffCSV

      String: Take a CSV as input and exclude from the output all the local persistences which match the ones in the input CSV. 

      .PARAMETER ComputerName

      Optional, an array of computernames to run the script on.
	    
      .PARAMETER OutputCSV

      String: Output to a CSV file for later consumption.

      .PARAMETER IncludeHighFalsePositivesChecks

      Switch: Forces Persistence Sniper to also call a number of functions with checks which are more difficult to filter and in turn can cause a lot of false positives.

      .EXAMPLE

      Enumerate low false positive persistence techniques implanted on the local machine.
      Find-AllPersistence

      .EXAMPLE

      Enumerate low false positive persistence techniques implanted on the local machine and output to a CSV.
      Find-AllPersistence -OutputCSV .\persistences.csv

      .EXAMPLE

      Enumerate low false positive persistence techniques implanted on the local machine but show us only the persistences which are not in an input CSV.
      Find-AllPersistence -DiffCSV .\persistences.csv

      .EXAMPLE

      Enumerate all persistence techniques implanted on the local machine but show us only the persistences which are not in an input CSV and output the findings on a CSV.
      Find-AllPersistence -DiffCSV .\persistences.csv -OutputCSV .\findings.csv -IncludeHighFalsePositivesChecks

      .NOTES

      This script tries to enumerate all persistence techniques that may have been deployed on a compromised machine. New techniques may take some time before they are implemented in this script, so don't assume that because the script didn't find anything the machine is clean.
     
      .LINK

      https://github.com/last-byte/PersistenceSniper
  #>
  
  
  Param(
    [Parameter(Position = 0)]
    [String]
    $DiffCSV = $null, 
    
    [Parameter(Position = 0)]
    [String[]]
    $ComputerName = $null,
    
    [Parameter(Position = 1)]
    [Switch]
    $IncludeHighFalsePositivesChecks,
        
    [Parameter(Position = 2)]
    [String]
    $OutputCSV = $null  
  )
  
  $ScriptBlock = {
    $ErrorActionPreference = 'SilentlyContinue'
    $VerbosePreference = $Using:VerbosePreference
    $hostname = ([System.Net.Dns]::GetHostByName($env:computerName)).HostName
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
        [Parameter(Mandatory)]
        [String]
        $Hostname,
      
        [Parameter(Mandatory)]
        [String]
        $Technique, 
      
        [Parameter(Mandatory)]
        [String]
        $Classification, 
      
        [Parameter(Mandatory)]
        [String]
        $Path, 
      
        [Parameter(Mandatory)]
        [String]
        $Value, 
      
        [Parameter(Mandatory)]
        [String]
        $AccessGained,
      
        [Parameter(Mandatory)]
        [String]
        $Note,
      
        [Parameter(Mandatory)]
        [String]
        $Reference
      )
      $PersistenceObject = [PSCustomObject]@{
        'Hostname' = $Hostname
        'Technique'    = $Technique
        'Classification' = $Classification
        'Path'         = $Path
        'Value'        = $Value
        'Access Gained' = $AccessGained
        'Note'         = $Note
        'Reference'    = $Reference
      } 
      return $PersistenceObject
    }

    function Get-RunAndRunOnce
    {
      Write-Verbose -Message 'Getting Run properties...'
      foreach($hive in $systemAndUsersHives)
      {
        
        $runProps = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 
        if($runProps)
        {
          Write-Verbose -Message "[!] Found properties under $(Convert-Path -Path $hive)'s Run key which deserve investigation!"
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
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Registry Run Key' -Classification 'MITRE ATT&CK T1547.001' -Path $propPath -Value $runProps.($prop.Name) -AccessGained $access -Note 'Executables in properties of the key (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows\CurrentVersion\Run are run when the user logs in.' -Reference 'https://attack.mitre.org/techniques/T1547/001/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
            $PersistenceObject
          }
        }
      }
    
      Write-Verbose -Message ''
      Write-Verbose -Message 'Getting RunOnce properties...'
      foreach($hive in $systemAndUsersHives)
      {
        $runOnceProps = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" 
        if($runOnceProps)
        {
          Write-Verbose -Message "[!] Found properties under $(Convert-Path -Path $hive)'s RunOnce key which deserve investigation!"
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
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Registry RunOnce Key' -Classification 'MITRE ATT&CK T1547.001' -Path $propPath -Value $runOnceProps.($prop.Name) -AccessGained $access -Note 'Executables in properties of the key (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce are run once when the user logs in and then deleted.' -Reference 'https://attack.mitre.org/techniques/T1547/001/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
            $PersistenceObject
          }
        }
      }
      Write-Verbose -Message ''
    }
  
    function Get-ImageFileExecutionOptions
    {
      $IFEOptsDebuggers = New-Object -TypeName System.Collections.ArrayList
      $foundDangerousIFEOpts = $false
      Write-Verbose -Message 'Getting Image File Execution Options...'
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
            Write-Verbose -Message "[!] Found subkeys under the Image File Execution Options key of $(Convert-Path -Path $hive) which deserve investigation!"
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
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Image File Execution Options' -Classification 'MITRE ATT&CK T1546.012' -Path $propPath -Value $ifeProps.($prop.Name) -AccessGained 'System/User' -Note 'Executables in the Debugger property of a subkey of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ are run instead of the program corresponding to the subkey. Gained access depends on whose context the debugged process runs in.' -Reference 'https://attack.mitre.org/techniques/T1546/012/'
                $null = $persistenceObjectArray.Add($PersistenceObject)
                $PersistenceObject
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
      Write-Verbose -Message 'Getting Natural Language Development Platform DLL path override properties...'
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
            Write-Verbose -Message "[!] Found subkeys under $(Convert-Path -Path $hive)\SYSTEM\CurrentControlSet\Control\ContentIndex\Language which deserve investigation!"
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
                $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Natural Language Development Platform 6 DLL Override Path' -Classification 'Hexacorn Technique N.98' -Path $propPath -Value $properties.($prop.Name) -AccessGained $access -Note 'DLLs listed in properties of subkeys of (HKLM|HKEY_USERS\<SID>)\SYSTEM\CurrentControlSet\Control\ContentIndex\Language are loaded via LoadLibrary executed by SearchIndexer.exe' -Reference 'https://www.hexacorn.com/blog/2018/12/30/beyond-good-ol-run-key-part-98/'
                $null = $persistenceObjectArray.Add($PersistenceObject)
                $PersistenceObject
              }
            }
          }
        }
      }
      Write-Verbose -Message ''
    }
  
    function Get-AeDebug
    {
      Write-Verbose -Message 'Getting AeDebug properties...'
      foreach($hive in $systemAndUsersHives)
      {
        $aeDebugger = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name Debugger 
        if($aeDebugger)
        {
          Write-Verbose -Message "[!] Found properties under the $(Convert-Path -Path $hive) AeDebug key which deserve investigation!"
          foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $aeDebugger))
          {
            if($psProperties.Contains($prop.Name)) 
            {
              continue
            } # skip the property if it's powershell built-in property
            $propPath = Convert-Path -Path $aeDebugger.PSPath
            $propPath += '\' + $prop.Name
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'AEDebug Custom Debugger' -Classification 'Hexacorn Technique N.4' -Path $propPath -Value $aeDebugger.($prop.Name) -AccessGained 'System/User' -Note "The executable in the Debugger property of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug is run when a process crashes. Gained access depends on whose context the debugged process runs in; if the Auto property of the same registry key is set to 1, the debugger starts without user interaction. A value of 'C:\Windows\system32\vsjitdebugger.exe' might be a false positive if you have Visual Studio Community installed." -Reference 'https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
            $PersistenceObject
          }
        }
    
        $aeDebugger = Get-ItemProperty -Path "$hive\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name Debugger 
        if($aeDebugger)
        {
          Write-Verbose -Message "[!] Found properties under the $(Convert-Path -Path $hive) Wow6432Node AeDebug key which deserve investigation!"
          foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $aeDebugger))
          {
            if($psProperties.Contains($prop.Name)) 
            {
              continue
            } # skip the property if it's powershell built-in property
            $propPath = Convert-Path -Path $aeDebugger.PSPath
            $propPath += '\' + $prop.Name
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Wow6432Node AEDebug Custom Debugger' -Classification 'Hexacorn Technique N.4' -Path $propPath -Value $aeDebugger.($prop.Name) -AccessGained 'System/User' -Note "The executable in the Debugger property of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug is run when a 32 bit process on a 64 bit system crashes. Gained access depends on whose context the debugged process runs in; if the Auto property of the same registry key is set to 1, the debugger starts without user interaction. A value of 'C:\Windows\system32\vsjitdebugger.exe' might be a false positive if you have Visual Studio Community installed." -Reference 'https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
            $PersistenceObject
          }
        }
      }
      Write-Verbose -Message '' 
    }
  
    function Get-WerFaultHangs
    {
      Write-Verbose -Message 'Getting WerFault Hangs registry key Debug property...'
      foreach($hive in $systemAndUsersHives)
      {
        $werfaultDebugger = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs" -Name Debugger 
        if($werfaultDebugger)
        {
          Write-Verbose -Message "[!] Found a Debugger property under the $(Convert-Path -Path $hive) WerFault Hangs key which deserve investigation!"
          $werfaultDebugger | Select-Object -Property Debugger, PS*
          foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $werfaultDebugger))
          {
            if($psProperties.Contains($prop.Name)) 
            {
              continue
            } # skip the property if it's powershell built-in property
            $propPath = Convert-Path -Path $werfaultDebugger.PSPath
            $propPath += '\' + $prop.Name
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Windows Error Reporting Debugger' -Classification 'Hexacorn Technique N.116' -Path $propPath -Value $werfaultDebugger.($prop.Name) -AccessGained 'System' -Note 'The executable in the Debugger property of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs is spawned by WerFault.exe when a process crashes.' -Reference 'https://www.hexacorn.com/blog/2019/09/20/beyond-good-ol-run-key-part-116/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
            $PersistenceObject
          }
        }
      }
    
      Write-Verbose -Message ''
      Write-Verbose -Message 'Getting WerFault Hangs registry key ReflectDebug property...'
      foreach($hive in $systemAndUsersHives)
      {
        $werfaultReflectDebugger = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs" -Name ReflectDebugger 
        if($werfaultReflectDebugger)
        {
          Write-Verbose -Message "[!] Found a ReflectDebugger property under the $(Convert-Path -Path $hive) WerFault Hangs key which deserve investigation!"
          $werfaultReflectDebugger | Select-Object -Property ReflectDebugger, PS*
          foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $werfaultReflectDebugger))
          {
            if($psProperties.Contains($prop.Name)) 
            {
              continue
            } # skip the property if it's powershell built-in property
            $propPath = Convert-Path -Path $werfaultReflectDebugger.PSPath
            $propPath += '\' + $prop.Name
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Windows Error Reporting ReflectDebugger' -Classification 'Hexacorn Technique N.85' -Path $propPath -Value $werfaultReflectDebugger.($prop.Name) -AccessGained 'System' -Note 'The executable in the ReflectDebugger property of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs is spawned by WerFault.exe when called with the -pr argument.' -Reference 'https://www.hexacorn.com/blog/2018/08/31/beyond-good-ol-run-key-part-85/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
            $PersistenceObject
          }
        }
      }
      Write-Verbose -Message ''
    }

    function Get-CmdAutoRun
    {
      Write-Verbose -Message "Getting Command Processor's AutoRun property..."
      foreach($hive in $systemAndUsersHives)
      {
        $autorun = Get-ItemProperty -Path "$hive\Software\Microsoft\Command Processor" -Name AutoRun 
        if($autorun)
        {
          Write-Verbose -Message "[!] $(Convert-Path -Path $hive) Command Processor's AutoRun property is set and deserves investigation!"
          foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $autorun))
          {
            if($psProperties.Contains($prop.Name)) { continue } # skip the property if it's powershell built-in property
            $propPath = Convert-Path -Path $autorun.PSPath
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
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Command Processor AutoRun key' -Classification 'Uncatalogued Technique N.1' -Path $propPath -Value $autorun.($prop.Name) -AccessGained $access -Note 'The executable in the AutoRun property of (HKLM|HKEY_USERS\<SID>)\Software\Microsoft\Command Processor\AutoRun is run when cmd.exe is spawned without the /D argument.' -Reference 'https://persistence-info.github.io/Data/cmdautorun.html'
            $null = $persistenceObjectArray.Add($PersistenceObject)
            $PersistenceObject
          }
        }
      }
      Write-Verbose -Message ''   
    }  
    function Get-ExplorerLoad
    {
      Write-Verbose -Message "Getting Explorer's Load property..."
      foreach($hive in $systemAndUsersHives)
      {
        $loadKey = Get-ItemProperty -Path "$hive\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name Load 
        if($loadKey)
        {
          Write-Verbose -Message "[!] $(Convert-Path -Path $hive) Load property is set and deserves investigation!"
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
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Explorer Load Property' -Classification 'Uncatalogued Technique N.2' -Path $propPath -Value $loadKey.($prop.Name) -AccessGained $access -Note 'The executable in the Load property of (HKLM|HKEY_USERS\<SID>)\Software\Microsoft\Windows NT\CurrentVersion\Windows is run by explorer.exe at login time.' -Reference 'https://persistence-info.github.io/Data/windowsload.html'
            $null = $persistenceObjectArray.Add($PersistenceObject)
            $PersistenceObject
          }
        }
      }
      Write-Verbose -Message ''
    }
  
    function Get-WinlogonUserinit
    {
      Write-Verbose -Message "Getting Winlogon's Userinit property..."
      foreach($hive in $systemAndUsersHives)
      {
        $userinit = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name Userinit 
        if($userinit)
        {
          if($userinit.Userinit -ne 'C:\Windows\system32\userinit.exe,')
          {
            Write-Verbose -Message "[!] $(Convert-Path -Path $hive) Winlogon's Userinit property is set to a non-standard value and deserves investigation!"
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
              $PersistenceObject
            }
          }
        }
      }
      Write-Verbose -Message ''
    }
  
    function Get-WinlogonShell
    {        
      Write-Verbose -Message "Getting Winlogon's Shell property..."
      foreach($hive in $systemAndUsersHives)
      {

        $shell = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name Shell 
        if($shell)
        {
          if($shell.Shell -ne 'explorer.exe')
          {
            Write-Verbose -Message "[!] $(Convert-Path -Path $hive) Winlogon's Shell property is set to a non-standard value and deserves investigation!"
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
              $PersistenceObject
            }
          }
        }
      }
      Write-Verbose -Message ''
    }
  
    function Get-TerminalProfileStartOnUserLogin
    {
      Write-Verbose -Message "Checking if users' Windows Terminal Profile's settings.json contains a startOnUserLogin value..."
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
                Write-Verbose -Message "[!] The file $($terminalDirectory.FullName)\LocalState\settings.json has the startOnUserLogin key set, the default profile has GUID $($profile.guid)!"
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
                $PersistenceObject
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
      Write-Verbose -Message 'Getting AppCertDlls properties...'
      foreach($hive in $systemAndUsersHives)
      {
        $appCertDllsProps = Get-ItemProperty -Path "$hive\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls" 
        if($appCertDllsProps)
        {
          Write-Verbose -Message "[!] Found properties under $(Convert-Path -Path $hive) AppCertDlls key which deserve investigation!"
          foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $appCertDllsProps))
          {
            if($psProperties.Contains($prop.Name)) { continue } # skip the property if it's powershell built-in property
            $propPath = Convert-Path -Path $appCertDllsProps.PSPath
            $propPath += '\' + $prop.Name
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'AppCertDlls' -Classification 'MITRE ATT&CK T1546.009' -Path $propPath -Value $appCertDllsProps.($prop.Name) -AccessGained 'System' -Note 'DLLs in properties of the key (HKLM|HKEY_USERS\<SID>)\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls are loaded by every process that loads the Win32 API at process creation.' -Reference 'https://attack.mitre.org/techniques/T1546/009/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
            $PersistenceObject
          }
        }
      }
      Write-Verbose -Message ''
    }
  
    function Get-AppPaths
    {
      Write-Verbose -Message 'Getting App Paths inside the registry...'
      foreach($hive in $systemAndUsersHives)
      {
        $appPathsKeys = Get-ChildItem -Path "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths" 
        foreach($key in $appPathsKeys)
        {
          $appPath = Get-ItemProperty -Path Registry::$key -Name '(Default)' 
          if($appPath) 
          { 
            Write-Verbose -Message "[!] Found subkeys under the $(Convert-Path -Path $hive) App Paths key which deserve investigation!"
            $propPath = Convert-Path -Path $key.PSPath
            $propPath += '\' + $appPath.Name
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'App Paths' -Classification 'Hexacorn Technique N.3' -Path "$propPath(Default)" -Value $appPath.'(Default)' -AccessGained 'System/User' -Note 'Executables in the (Default) property of a subkey of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\ are run instead of the program corresponding to the subkey. Gained access depends on whose context the process runs in. Be aware this might be a false positive.' -Reference 'https://www.hexacorn.com/blog/2013/01/19/beyond-good-ol-run-key-part-3/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
            $PersistenceObject
          } 
        }
      }
      Write-Verbose -Message ''
    }  
  
    function Get-ServiceDlls
    {
      Write-Verbose -Message 'Getting Service DLLs inside the registry...'
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
                if ((Get-AuthenticodeSignature -FilePath $ServiceDll ).IsOSBinary) 
                {
                  continue
                }
                else
                {
                  Write-Verbose -Message "[!] Found subkeys under the $(Convert-Path -Path $hive) Services key which deserve investigation!"
                  $propPath = (Convert-Path -Path "$($key.pspath)") + '\Parameters\ServiceDll'
                  $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'ServiceDll Hijacking' -Classification 'Hexacorn Technique N.4' -Path $propPath -Value "$ServiceDll" -AccessGained 'System' -Note "DLLs in the ServiceDll property of (HKLM|HKEY_USERS\<SID>)\SYSTEM\CurrentControlSet\Services\<SERVICE_NAME>\Parameters are loaded by the corresponding service's svchost.exe. If an attacker modifies said entry, the malicious DLL will be loaded in place of the legitimate one." -Reference 'https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/'
                  $null = $persistenceObjectArray.Add($PersistenceObject)
                  $PersistenceObject
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
      Write-Verbose -Message 'Getting Group Policy Extension DLLs inside the registry...'
      foreach($hive in $systemAndUsersHives)
      {
        $keys = Get-ChildItem -Path "$hive\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions" 
        foreach ($key in $keys)
        {
          $DllName = (Get-ItemProperty -Path ($key.pspath)).DllName
          if ($null -ne $DllName)
          {
            if((Test-Path -Path $DllName -PathType leaf) -eq $false)
            {
              $DllName = "C:\Windows\System32\$DllName"
            }
            if ((Get-AuthenticodeSignature -FilePath $DllName ).IsOSBinary) 
            {
              continue
            }
            else
            {
              Write-Verbose -Message "[!] Found DllName property under a subkey of the $(Convert-Path -Path $hive) GPExtensions key which deserve investigation!"
              $propPath = (Convert-Path -Path "$($key.pspath)") + '\DllName'
              $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Group Policy Extension DLL' -Classification 'Uncatalogued Technique N.4' -Path $propPath -Value "$DllName" -AccessGained 'System' -Note 'DLLs in the DllName property of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\<GUID>\ are loaded by the gpsvc process. If an attacker modifies said entry, the malicious DLL will be loaded in place of the legitimate one.' -Reference 'https://persistence-info.github.io/Data/gpoextension.html'
              $null = $persistenceObjectArray.Add($PersistenceObject)
              $PersistenceObject
            }
          }
        }  
      }
      Write-Verbose -Message ''
    }
  
    function Get-WinlogonMPNotify
    {
      Write-Verbose -Message 'Getting Winlogon MPNotify property...'
      foreach($hive in $systemAndUsersHives)
      {
        $mpnotify = Get-ItemProperty -Path "$hive\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name mpnotify 
        if($mpnotify)
        {
          Write-Verbose -Message "[!] Found MPnotify property under $(Convert-Path -Path $hive) Winlogon key!"
          $propPath = (Convert-Path -Path $mpnotify.PSPath) + '\mpnotify'
          $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Winlogon MPNotify Executable' -Classification 'Uncatalogued Technique N.5' -Path $propPath -Value $mpnotify.mpnotify -AccessGained 'System' -Note 'The executable specified in the "mpnotify" property of the (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon key is run by Winlogon when a user logs on. After the timeout (30s) the process and its child processes are terminated.' -Reference 'https://persistence-info.github.io/Data/mpnotify.html'
          $null = $persistenceObjectArray.Add($PersistenceObject)
          $PersistenceObject
        }
      }
      Write-Verbose -Message ''
    }
  
    Write-Verbose -Message 'Starting execution...'

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
  
    if($IncludeHighFalsePositivesChecks.IsPresent)
    {
      Write-Verbose -Message 'You have used the -IncludeHighFalsePositivesChecks switch, this may generate a lot of false positives since it includes checks with results which are difficult to filter programmatically...'
      Get-AppPaths
    }
  }
  
  if($ComputerName)
  {
    Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock
  }
  else
  {
    Invoke-Command -ScriptBlock $ScriptBlock
  }
  
  # Use Input CSV to make a diff of the results and only show us the persistences implanted on the local machine which are not in the CSV
  if($DiffCSV)
  {
    Write-Verbose -Message 'Diffing found persistences with the ones in the input CSV...'
    $importedPersistenceObjectArray = Import-Csv -Path $DiffCSV -ErrorAction Stop
    $newPersistenceObjectArray = New-Object -TypeName System.Collections.ArrayList
    foreach($localPersistence in $persistenceObjectArray)
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
    $persistenceObjectArray = $newPersistenceObjectArray.Clone()
  }
  
  if($OutputCSV)
  {
    $persistenceObjectArray |
    ConvertTo-Csv |
    Out-File -FilePath $OutputCSV -ErrorAction Stop
  }
  
  Write-Verbose -Message 'Execution finished.'  
  
}