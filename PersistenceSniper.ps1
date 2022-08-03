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
      $Persistences = Find-AllPersistence
      Enumerate low false positive persistence techniques implanted on the local machine and save them in Powershell variable for later processing.

      .EXAMPLE
      Find-AllPersistence -OutputCSV .\persistences.csv
      Enumerate low false positive persistence techniques implanted on the local machine and output to a CSV.

      .EXAMPLE
      Find-AllPersistence -DiffCSV .\persistences.csv
      Enumerate low false positive persistence techniques implanted on the local machine but show us only the persistences which are not in an input CSV.

      .EXAMPLE
      Find-AllPersistence -DiffCSV .\persistences.csv
      Enumerate low false positive persistence techniques implanted on the local machine but show us only the persistences which are not in an input CSV and output the results on another CSV.

      .EXAMPLE
      Find-AllPersistence -ComputerName @('dc1.macrohard.lol', 'dc2.macrohard.lol') -IncludeHighFalsePositivesChecks -DiffCSV .\persistences.csv -OutputCSV .\findings.csv
      Enumerate all persistence techniques implanted on an array of remote machines but show only the persistences which are not in an input CSV and output the findings on a CSV.

      .EXAMPLE
      Find-AllPersistence -ComputerName (Get-Content computers.txt) -IncludeHighFalsePositivesChecks -DiffCSV .\persistences.csv -OutputCSV .\findings.csv
      Enumerate all persistence techniques implanted on an array of remote machines retrieved from a file containing one hostname per line but show only the persistences which are not in an input CSV and output the findings on a CSV.

      .EXAMPLE
      Find-AllPersistence -DiffCSV .\persistences.csv -OutputCSV .\findings.csv | Where-Object Classification -Like "MITRE ATT&CK T*"
      Enumerate all persistence techniques implanted on the local machine, filter out the ones in the persistences.csv file, save the results in findings.csv and output to console only the persistences which are classified under the MITRE ATT&CK framework.

      .NOTES
      This script tries to enumerate all persistence techniques that may have been deployed on a compromised machine. New techniques may take some time before they are implemented in this script, so don't assume that because the script didn't find anything the machine is clean.
     
      .LINK
      https://github.com/last-byte/PersistenceSniper
  #>
  
  Param(
        
    [Parameter(Position = 0)]
    [String[]]
    $ComputerName = $null,
    
    [Parameter(Position = 1)]
    [String]
    $DiffCSV = $null, 
    
    [Parameter(Position = 2)]
    [Switch]
    $IncludeHighFalsePositivesChecks,
        
    [Parameter(Position = 3)]
    [String]
    $OutputCSV = $null  
  )
  
  $ScriptBlock = {
    $hostname = hostname
    $ErrorActionPreference = 'SilentlyContinue'
    $VerbosePreference = $Using:VerbosePreference
    $hostname = ([Net.Dns]::GetHostByName($env:computerName)).HostName
    $script:psProperties = @('PSChildName', 'PSDrive', 'PSParentPath', 'PSPath', 'PSProvider')
    $script:persistenceObjectArray = [Collections.ArrayList]::new()
    $script:systemAndUsersHives = [Collections.ArrayList]::new()
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
        $Reference = $null
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
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Registry Run Key' -Classification 'MITRE ATT&CK T1547.001' -Path $propPath -Value $runProps.($prop.Name) -AccessGained $access -Note 'Executables in properties of the key (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows\CurrentVersion\Run are run when the user logs in.' -Reference 'https://attack.mitre.org/techniques/T1547/001/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
            $PersistenceObject
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
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'AEDebug Custom Debugger' -Classification 'Hexacorn Technique N.4' -Path $propPath -Value $aeDebugger.($prop.Name) -AccessGained 'System/User' -Note "The executable in the Debugger property of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug is run when a process crashes. Gained access depends on whose context the debugged process runs in; if the Auto property of the same registry key is set to 1, the debugger starts without user interaction. A value of 'C:\Windows\system32\vsjitdebugger.exe' might be a false positive if you have Visual Studio Community installed." -Reference 'https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
            $PersistenceObject
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
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Windows Error Reporting Debugger' -Classification 'Hexacorn Technique N.116' -Path $propPath -Value $werfaultDebugger.($prop.Name) -AccessGained 'System' -Note 'The executable in the Debugger property of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs is spawned by WerFault.exe when a process crashes.' -Reference 'https://www.hexacorn.com/blog/2019/09/20/beyond-good-ol-run-key-part-116/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
            $PersistenceObject
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
      Write-Verbose -Message "$hostname - Getting Command Processor's AutoRun property..."
      foreach($hive in $systemAndUsersHives)
      {
        $autorun = Get-ItemProperty -Path "$hive\Software\Microsoft\Command Processor" -Name AutoRun 
        if($autorun)
        {
          Write-Verbose -Message "$hostname - [!] $(Convert-Path -Path $hive) Command Processor's AutoRun property is set and deserves investigation!"
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
              $PersistenceObject
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
              $PersistenceObject
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
            $PersistenceObject
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
          if((Test-Path -Path $exePath -PathType leaf) -eq $false)
          {
            $exePath = "C:\Windows\System32\$exePath"
          }
          if ((Test-Path -Path $exePath -PathType leaf) -and ($exePath.Contains('powershell') -or $exePath.Contains('cmd') -or -not (Get-AuthenticodeSignature -FilePath $exePath ).IsOSBinary))
          { 
            Write-Verbose -Message "$hostname - [!] Found subkeys under the $(Convert-Path -Path $hive) App Paths key which deserve investigation!"
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
                if((Test-Path -Path $dllPath -PathType leaf) -eq $false)
                {
                  $dllPath = "C:\Windows\System32\$dllPath.dll"
                }
                if ((Test-Path -Path $dllPath -PathType leaf) -and -not (Get-AuthenticodeSignature -FilePath $ServiceDll ).IsOSBinary) 
                {
                  Write-Verbose -Message "$hostname - [!] Found subkeys under the $(Convert-Path -Path $hive) Services key which deserve investigation!"
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
      Write-Verbose -Message "$hostname - Getting Group Policy Extension DLLs inside the registry..."
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
            if ((Test-Path -Path $DllName -PathType leaf) -and -not (Get-AuthenticodeSignature -FilePath $DllName ).IsOSBinary) 
            {
              Write-Verbose -Message "$hostname - [!] Found DllName property under a subkey of the $(Convert-Path -Path $hive) GPExtensions key which deserve investigation!"
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
          $PersistenceObject
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
            if((Test-Path -Path $dllPath -PathType leaf) -eq $false)
            {
              $dllPath = "C:\Windows\System32\$dllPath"
            }
            if ((Test-Path -Path $dllPath -PathType leaf) -and -not (Get-AuthenticodeSignature -FilePath $dllPath ).IsOSBinary) 
            {
              Write-Verbose -Message "$hostname - [!] Found Location property under $(Convert-Path -Path $hive)\Software\Microsoft\HtmlHelp Author\ which deserve investigation!"
              $propPath = (Convert-Path -Path "$($dllLocation.pspath)") + '\Location'
              $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'CHM Helper DLL' -Classification 'Hexacorn Technique N.76' -Path $propPath -Value "$($dllLocation.Location)" -AccessGained 'User' -Note 'DLLs in the Location property of (HKLM|HKEY_USERS\<SID>)\Software\Microsoft\HtmlHelp Author\ are loaded when a CHM help file is parsed. If an attacker adds said entry, the malicious DLL will be loaded.' -Reference 'https://www.hexacorn.com/blog/2018/04/22/beyond-good-ol-run-key-part-76/'
              $null = $persistenceObjectArray.Add($PersistenceObject)
              $PersistenceObject
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
        if((Test-Path -Path $dllPath -PathType leaf) -eq $false)
        {
          $dllPath = "C:\Windows\System32\$dllPath"
        }
        if ((Test-Path -Path $dllPath -PathType leaf) -and -not (Get-AuthenticodeSignature -FilePath $dllPath ).IsOSBinary)
        {
          Write-Verbose -Message "$hostname - [!] The DLL at $(Convert-Path -Path $hive)\CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32\(Default) is not an OS binary and deserves investigation!"
          $propPath = (Convert-Path -Path "$($dllLocation.pspath)") + '\(Default)'
          $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Hijacking of hhctrl.ocx' -Classification 'Hexacorn Technique N.77' -Path $propPath -Value "$($dllLocation.'(Default)')" -AccessGained 'User' -Note 'The DLL in the (Default) property of HKEY_CLASSES_ROOT\CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32 is loaded when a CHM help file is parsed or when hh.exe is started. If an attacker modifies said entry, the malicious DLL will be loaded. In case the loading fails for any reason, C:\Windows\hhctrl.ocx is loaded.' -Reference 'https://www.hexacorn.com/blog/2018/04/23/beyond-good-ol-run-key-part-77/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
          $PersistenceObject
        }
      }
      else
      {
        $dllPath = "C:\Windows\System32\hhctrl.ocx"
        if ((Test-Path -Path $dllPath -PathType Leaf) -and -not (Get-AuthenticodeSignature -FilePath $dllPath ).IsOSBinary)
        {
          Write-Verbose -Message "$hostname - [!] The DLL at $dllPath is not an OS binary and deserves investigation!"
          $propPath = (Convert-Path -Path "$($dllLocation.pspath)") + '\(Default)'
          $PersistenceObject = New-PersistenceObject -Hostname "$hostname" -Technique 'Hijacking of hhctrl.ocx' -Classification 'Hexacorn Technique N.77' -Path "$dllPath" -Value "Not an OS binary" -AccessGained 'User' -Note 'The DLL in the (Default) property of HKEY_CLASSES_ROOT\CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32 is loaded when a CHM help file is parsed or when hh.exe is started. If an attacker modifies said entry, the malicious DLL will be loaded. In case the loading fails for any reason, C:\Windows\hhctrl.ocx is loaded.' -Reference 'https://www.hexacorn.com/blog/2018/04/23/beyond-good-ol-run-key-part-77/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
          $PersistenceObject
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
        $startupDirectory = Get-ChildItem -Path "$($directory.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\" 
        foreach($file in $startupDirectory)
        {
          Write-Verbose -Message "$hostname - [!] Found a file under $($directory.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\ folder!"          
          $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Startup Folder' -Classification 'MITRE ATT&CK T1547.001' -Path "$($directory.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\" -Value "$file" -AccessGained 'User' -Note "The executables under the \AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\ of a user's folder are run every time that user logs in." -Reference 'https://attack.mitre.org/techniques/T1547/001/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
          $PersistenceObject
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
          $PersistenceObject
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
          if((Test-Path -Path $dllPath -PathType leaf) -eq $false)
          {
            $dllPath = "C:\Windows\System32\$dllPath"
          }
          if ((Test-Path -Path $dllPath -PathType leaf) -and -not (Get-AuthenticodeSignature -FilePath $dllPath ).IsOSBinary)
          {
            Write-Verbose -Message "$hostname - [!] Found AutodialDLL property under $(Convert-Path -Path $hive)\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\ key which points to a non-OS DLL!"
            $propPath = (Convert-Path -Path $autodialDll.PSPath) + '\AutodialDLL'
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'AutodialDLL Winsock Injection' -Classification 'Hexacorn Technique N.24' -Path $propPath -Value $autodialDll.AutodialDLL -AccessGained 'System' -Note 'The DLL specified in the "AutodialDLL" property of the (HKLM|HKEY_USERS\<SID>)\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters key is loaded by the Winsock library everytime it connects to the internet.' -Reference 'https://www.hexacorn.com/blog/2015/01/13/beyond-good-ol-run-key-part-24/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
            $PersistenceObject
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
            if((Test-Path -Path $dllPath -PathType leaf) -eq $false)
            {
              $dllPath = "C:\Windows\System32\$dllPath"
            }
            if ((Test-Path -Path $dllPath -PathType leaf) -and -not (Get-AuthenticodeSignature -FilePath $dllPath ).IsOSBinary)
            {
              Write-Verbose -Message "$hostname - [!] Found LSA Extension DLL under the $(Convert-Path -Path $hive)\SYSTEM\CurrentControlSet\Control\LsaExtensionConfig\LsaSrv\Extensions property which points to a non-OS DLL!"
              $propPath = (Convert-Path -Path $lsaExtensions.PSPath) + '\Extensions'
              $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'LSA Extensions DLL' -Classification 'Uncatalogued Technique N.6' -Path $propPath -Value $dll -AccessGained 'System' -Note 'The DLLs specified in the "Extensions" property of the (HKLM|HKEY_USERS\<SID>)\SYSTEM\CurrentControlSet\Control\LsaExtensionConfig\LsaSrv\ key are loaded by LSASS at machine boot.' -Reference 'https://persistence-info.github.io/Data/lsaaextension.html'
              $null = $persistenceObjectArray.Add($PersistenceObject)
              $PersistenceObject
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
          if((Test-Path -Path $dllPath -PathType leaf) -eq $false)
          {
            $dllPath = "C:\Windows\System32\$dllPath"
          }
          if ((Test-Path -Path $dllPath -PathType leaf) -and -not (Get-AuthenticodeSignature -FilePath $dllPath ).IsOSBinary)
          {
            Write-Verbose -Message "$hostname - [!] Found ServerLevelPluginDll property under $(Convert-Path -Path $hive)\SYSTEM\CurrentControlSet\Services\DNS\Parameters key which points to a non-OS DLL!"
            $propPath = (Convert-Path -Path $pluginDll.PSPath) + '\ServerLevelPluginDll'
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'ServerLevelPluginDll DNS Server DLL Hijacking' -Classification 'Uncatalogued Technique N.7' -Path $propPath -Value $pluginDll.ServerLevelPluginDll -AccessGained 'System' -Note 'The DLL specified in the "ServerLevelPluginDll" property of the (HKLM|HKEY_USERS\<SID>)\SYSTEM\CurrentControlSet\Services\DNS\Parameters key is loaded by the DNS service on systems with the "DNS Server" role enabled.' -Reference 'https://persistence-info.github.io/Data/serverlevelplugindll.html'
            $null = $persistenceObjectArray.Add($PersistenceObject)
            $PersistenceObject
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
            $dllPath = $dll
            if((Test-Path -Path $dllPath -PathType leaf) -eq $false)
            {
              $dllPath = "C:\Windows\System32\$dllPath.dll"
            }
            if ((Test-Path -Path $dllPath -PathType leaf) -and -not (Get-AuthenticodeSignature -FilePath $dllPath ).IsOSBinary)
            {
              Write-Verbose -Message "$hostname - [!] Found a LSA password filter DLL under the $(Convert-Path -Path $hive)\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages property which points to a non-OS DLL!"
              $propPath = (Convert-Path -Path $passwordFilters.PSPath) + '\Notification Packages'
              $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'LSA Password Filter DLL' -Classification 'MITRE ATT&CK T1556.002' -Path $propPath -Value $dll -AccessGained 'System' -Note 'The DLLs specified in the "Notification Packages" property of the (HKLM|HKEY_USERS\<SID>)\SYSTEM\CurrentControlSet\Control\Lsa\ key are loaded by LSASS at machine boot.' -Reference 'https://attack.mitre.org/techniques/T1556/002/'
              $null = $persistenceObjectArray.Add($PersistenceObject)
              $PersistenceObject
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
            $dllPath = $dll
            if((Test-Path -Path $dllPath -PathType leaf) -eq $false)
            {
              $dllPath = "C:\Windows\System32\$dllPath.dll"
            }
            if ((Test-Path -Path $dllPath -PathType leaf) -and -not (Get-AuthenticodeSignature -FilePath $dllPath ).IsOSBinary)
            {
              Write-Verbose -Message "$hostname - [!] Found a LSA authentication package DLL under the $(Convert-Path -Path $hive)\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages property which points to a non-OS DLL!"
              $propPath = (Convert-Path -Path $authPackages.PSPath) + '\Authentication Packages'
              $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'LSA Authentication Package DLL' -Classification 'MITRE ATT&CK T1547.002' -Path $propPath -Value $dll -AccessGained 'System' -Note 'The DLLs specified in the "Authentication Packages" property of the (HKLM|HKEY_USERS\<SID>)\SYSTEM\CurrentControlSet\Control\Lsa\ key are loaded by LSASS at machine boot.' -Reference 'https://attack.mitre.org/techniques/T1547/002/'
              $null = $persistenceObjectArray.Add($PersistenceObject)
              $PersistenceObject
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
          $dlls = $secPackages.'Security Packages' -split '\s+'
          foreach ($dll in $dlls)
          {
            $dllPath = $dll -replace '"','' # security packages are often delimited by double quotes so we want to get rid of them
            if((Test-Path -Path $dllPath -PathType leaf) -eq $false)
            {
              $dllPath = "C:\Windows\System32\$dllPath.dll"
            }
            if ((Test-Path -Path $dllPath -PathType leaf) -and -not (Get-AuthenticodeSignature -FilePath $dllPath ).IsOSBinary)
            {
              Write-Verbose -Message "$hostname - [!] Found a LSA security package DLL under the $(Convert-Path -Path $hive)\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages property which points to a non-OS DLL!"
              $propPath = (Convert-Path -Path $secPackages.PSPath) + '\Security Packages'
              $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'LSA Security Package DLL' -Classification 'MITRE ATT&CK T1547.005' -Path $propPath -Value $dll -AccessGained 'System' -Note 'The DLLs specified in the "Security Packages" property of the (HKLM|HKEY_USERS\<SID>)\SYSTEM\CurrentControlSet\Control\Lsa\ key are loaded by LSASS at machine boot.' -Reference 'https://attack.mitre.org/techniques/T1547/005/'
              $null = $persistenceObjectArray.Add($PersistenceObject)
              $PersistenceObject
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
            $PersistenceObject
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
          if((Test-Path -Path $path -PathType leaf) -eq $false)
          {
            $path = "C:\Windows\System32\$path.dll"
          }
          if ((Test-Path -Path $path -PathType leaf) -and -not (Get-AuthenticodeSignature -FilePath $path ).IsOSBinary) 
          {
            Write-Verbose -Message "$hostname - [!] Found an executable under a subkey of $(Convert-Path -Path $hive)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer key which deserve investigation!"
            $propPath = Convert-Path -Path $key.PSPath
            $propPath += '\(Default)'
            $PersistenceObject = New-PersistenceObject -Hostname $hostname -Technique 'Explorer Tools Hijacking' -Classification 'Hexacorn Technique N.55' -Path $propPath -Value $path -AccessGained 'System' -Note 'Executables in the (Default) property of a subkey of (HKLM|HKEY_USERS\<SID>)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer are run when the corresponding event is triggered.' -Reference 'https://www.hexacorn.com/blog/2017/01/18/beyond-good-ol-run-key-part-55/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
            $PersistenceObject
          }
        }
      }
      Write-Verbose -Message ''
    }
    
    Write-Verbose -Message "$hostname - Starting execution..."

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
  
    if($IncludeHighFalsePositivesChecks.IsPresent)
    {
      Write-Verbose -Message "$hostname - You have used the -IncludeHighFalsePositivesChecks switch, this may generate a lot of false positives since it includes checks with results which are difficult to filter programmatically..."
      Get-AppPaths
    }
    
    Write-Verbose -Message "$hostname - Execution finished."
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
  
  Write-Verbose -Message 'Script execution finished.'  
  
}