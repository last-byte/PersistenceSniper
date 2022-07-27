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
    
    [Parameter(Position = 2)]
    [String]
    $OutputCSV = $null,  
    
    [Parameter(Position = 1)]
    [Switch]
    $IncludeHighFalsePositivesChecks
  )  
  
  $psProperties = @('PSChildName', 'PSDrive', 'PSParentPath', 'PSPath', 'PSProvider')
  $persistenceObjectArray = [Collections.ArrayList]::new()
  
  function New-PersistenceObject
  {
    param(
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
  function Get-UsersRunAndRunOnce
  {
    Write-Verbose -Message "Getting users' Run properties..."
    $hkeyUsers = Get-ChildItem -Path Registry::HKEY_USERS
    foreach($sidHive in $hkeyUsers)
    {
      $currentUser = "Registry::$sidHive"
      $runProps = Get-ItemProperty -Path "$currentUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
      if($runProps)
      {
        Write-Verbose -Message "[!] Found properties under $sidHive user's Run key which deserve investigation!"
        foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $runProps))
        {
          if($psProperties.Contains($prop.Name)) 
          {
            continue
          } # skip the property if it's powershell built-in property
          $propPath = Convert-Path -Path $runProps.PSPath
          $propPath += '\' + $prop.Name
          $PersistenceObject = New-PersistenceObject -Technique 'Registry Run Key' -Classification 'MITRE ATT&CK T1547.001' -Path $propPath -Value $runProps.($prop.Name) -AccessGained 'User' -Note 'Executables in properties of the key HKEY_USERS\<User_SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Run are run when the user logs in.' -Reference 'https://attack.mitre.org/techniques/T1547/001/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
          $PersistenceObject
        }
      }
    }
    
    Write-Verbose -Message ''
    Write-Verbose -Message "Getting users' RunOnce properties..."
    foreach($sidHive in $hkeyUsers)
    {
      $currentUser = "Registry::$sidHive"
      $runOnceProps = Get-ItemProperty -Path "$currentUser\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue
      if($runOnceProps)
      {
        Write-Verbose -Message "[!] Found properties under $sidHive user's RunOnce key which deserve investigation!"
        foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $runOnceProps))
        {
          if($psProperties.Contains($prop.Name)) 
          {
            continue
          } # skip the property if it's powershell built-in property
          $propPath = Convert-Path -Path $runOnceProps.PSPath
          $propPath += '\' + $prop.Name
          $PersistenceObject = New-PersistenceObject -Technique 'Registry RunOnce Key' -Classification 'MITRE ATT&CK T1547.001' -Path $propPath -Value $runOnceProps.($prop.Name) -AccessGained 'User' -Note 'Executables in properties of the key HKEY_USERS\<User_SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce are run once when the user logs in and then deleted.' -Reference 'https://attack.mitre.org/techniques/T1547/001/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
          $PersistenceObject
        }
      }
    }
    Write-Verbose -Message ''
  }
  
  function Get-SystemRunAndRunOnce
  {
    Write-Verbose -Message "Getting system's Run properties..."
    $runProps = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
    if($runProps)
    {
      Write-Verbose -Message "[!] Found properties under system's Run key which deserve investigation!"
      foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $runProps))
      {
        if($psProperties.Contains($prop.Name)) 
        {
          continue
        } # skip the property if it's powershell built-in property
        $propPath = Convert-Path -Path $runProps.PSPath
        $propPath += '\' + $prop.Name
        $PersistenceObject = New-PersistenceObject -Technique 'Registry Run Key' -Classification 'MITRE ATT&CK T1547.001' -Path $propPath -Value $runProps.($prop.Name) -AccessGained 'System' -Note 'Executables in properties of the key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run are run when the system boots.' -Reference 'https://attack.mitre.org/techniques/T1547/001/'
        $null = $persistenceObjectArray.Add($PersistenceObject)
        $PersistenceObject
      }
    }
    
    Write-Verbose -Message ''
    Write-Verbose -Message "Getting system's RunOnce properties..."
    $runOnceProps = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue
    if($runOnceProps)
    {
      Write-Verbose -Message "[!] Found properties under system's RunOnce key which deserve investigation!"
      foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $runOnceProps))
      {
        if($psProperties.Contains($prop.Name)) 
        {
          continue
        } # skip the property if it's powershell built-in property
        $propPath = Convert-Path -Path $runOnceProps.PSPath
        $propPath += '\' + $prop.Name
        $PersistenceObject = New-PersistenceObject -Technique 'Registry RunOnce Key' -Classification 'MITRE ATT&CK T1547.001' -Path $propPath -Value $runOnceProps.($prop.Name) -AccessGained 'System' -Note 'Executables in properties of the key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce are run once when the system boots and then deleted.' -Reference 'https://attack.mitre.org/techniques/T1547/001/'
        $null = $persistenceObjectArray.Add($PersistenceObject)
        $PersistenceObject
      }
    }
    Write-Verbose -Message ''
  }
  
  function Get-ImageFileExecutionOptions
  {
    $IFEOptsDebuggers = New-Object -TypeName System.Collections.ArrayList
    $foundDangerousIFEOpts = $false
    Write-Verbose -Message 'Getting Image File Execution Options...'
    $ifeOpts = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue
    if($ifeOpts)
    {
      foreach($key in $ifeOpts)
      {
        $debugger = Get-ItemProperty -Path Registry::$key -Name Debugger -ErrorAction SilentlyContinue
        if($debugger) 
        {
          $foundDangerousIFEOpts = $true
          $null = $IFEOptsDebuggers.Add($key)
        }
      }
      
      if($foundDangerousIFEOpts)
      {
        Write-Verbose -Message '[!] Found subkeys under the Image File Execution Options key which deserve investigation!'
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
            $PersistenceObject = New-PersistenceObject -Technique 'Image File Execution Options' -Classification 'MITRE ATT&CK T1546.012' -Path $propPath -Value $ifeProps.($prop.Name) -AccessGained 'System/User' -Note 'Executables in the Debugger property of a subkey of HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ are run instead of the program corresponding to the subkey. Gained access depends on whose context the debugged process runs in.' -Reference 'https://attack.mitre.org/techniques/T1546/012/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
            $PersistenceObject
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
    $NLDPLanguages = Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ContentIndex\Language' -ErrorAction SilentlyContinue
    if($NLDPLanguages)
    {
      foreach($key in $NLDPLanguages)
      {
        $DllOverridePath = Get-ItemProperty -Path Registry::$key -Name *DLLPathOverride -ErrorAction SilentlyContinue
        if($DllOverridePath) 
        {
          $foundDllOverridePath = $true
          $null = $KeysWithDllOverridePath.Add($key)
        }
      }
      
      if($foundDllOverridePath)
      {
        Write-Verbose -Message '[!] Found subkeys under HKLM:\SYSTEM\CurrentControlSet\Control\ContentIndex\Language which deserve investigation!'
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
            $PersistenceObject = New-PersistenceObject -Technique 'Natural Language Development Platform 6 DLL Override Path' -Classification 'Hexacorn Technique N.98' -Path $propPath -Value $properties.($prop.Name) -AccessGained 'System' -Note 'DLLs listed in properties of subkeys of HKLM:\SYSTEM\CurrentControlSet\Control\ContentIndex\Language are loaded via LoadLibrary executed by SearchIndexer.exe' -Reference 'https://www.hexacorn.com/blog/2018/12/30/beyond-good-ol-run-key-part-98/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
            $PersistenceObject
          }
        }
      }
    }
    Write-Verbose -Message ''
  }
  
  function Get-AeDebug
  {
    Write-Verbose -Message 'Getting AeDebug properties...'
    $aeDebugger = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug' -Name Debugger -ErrorAction SilentlyContinue
    if($aeDebugger)
    {
      Write-Verbose -Message '[!] Found properties under the AeDebug key which deserve investigation!'
      foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $aeDebugger))
      {
        if($psProperties.Contains($prop.Name)) 
        {
          continue
        } # skip the property if it's powershell built-in property
        $propPath = Convert-Path -Path $aeDebugger.PSPath
        $propPath += '\' + $prop.Name
        $PersistenceObject = New-PersistenceObject -Technique 'AEDebug Custom Debugger' -Classification 'Hexacorn Technique N.4' -Path $propPath -Value $aeDebugger.($prop.Name) -AccessGained 'System/User' -Note "The executable in the Debugger property of HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug is run when a process crashes. Gained access depends on whose context the debugged process runs in; if the Auto property of the same registry key is set to 1, the debugger starts without user interaction. A value of 'C:\Windows\system32\vsjitdebugger.exe' might be a false positive if you have Visual Studio Community installed." -Reference 'https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/'
        $null = $persistenceObjectArray.Add($PersistenceObject)
        $PersistenceObject
      }
    }
    
    $aeDebugger = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug' -Name Debugger -ErrorAction SilentlyContinue
    if($aeDebugger)
    {
      Write-Verbose -Message '[!] Found properties under the Wow6432Node AeDebug key which deserve investigation!'
      foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $aeDebugger))
      {
        if($psProperties.Contains($prop.Name)) 
        {
          continue
        } # skip the property if it's powershell built-in property
        $propPath = Convert-Path -Path $aeDebugger.PSPath
        $propPath += '\' + $prop.Name
        $PersistenceObject = New-PersistenceObject -Technique 'Wow6432Node AEDebug Custom Debugger' -Classification 'Hexacorn Technique N.4' -Path $propPath -Value $aeDebugger.($prop.Name) -AccessGained 'System/User' -Note "The executable in the Debugger property of HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug is run when a 32 bit process on a 64 bit system crashes. Gained access depends on whose context the debugged process runs in; if the Auto property of the same registry key is set to 1, the debugger starts without user interaction. A value of 'C:\Windows\system32\vsjitdebugger.exe' might be a false positive if you have Visual Studio Community installed." -Reference 'https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/'
        $null = $persistenceObjectArray.Add($PersistenceObject)
        $PersistenceObject
      }
    }
    Write-Verbose -Message '' 
  }
  
  function Get-WerFaultHangs
  {
    Write-Verbose -Message 'Getting WerFault Hangs registry key Debug property...'
    $werfaultDebugger = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs' -Name Debugger -ErrorAction SilentlyContinue
    if($werfaultDebugger)
    {
      Write-Verbose -Message '[!] Found a Debugger property under the WerFault Hangs key which deserve investigation!'
      $werfaultDebugger | Select-Object -Property Debugger, PS*
      foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $werfaultDebugger))
      {
        if($psProperties.Contains($prop.Name)) 
        {
          continue
        } # skip the property if it's powershell built-in property
        $propPath = Convert-Path -Path $werfaultDebugger.PSPath
        $propPath += '\' + $prop.Name
        $PersistenceObject = New-PersistenceObject -Technique 'Windows Error Reporting Debugger' -Classification 'Hexacorn Technique N.116' -Path $propPath -Value $werfaultDebugger.($prop.Name) -AccessGained 'System' -Note 'The executable in the Debugger property of HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs is spawned by WerFault.exe when a process crashes.' -Reference 'https://www.hexacorn.com/blog/2019/09/20/beyond-good-ol-run-key-part-116/'
        $null = $persistenceObjectArray.Add($PersistenceObject)
        $PersistenceObject
      }
    }
    
    Write-Verbose -Message ''
    Write-Verbose -Message 'Getting WerFault Hangs registry key ReflectDebug property...'
    $werfaultReflectDebugger = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs' -Name ReflectDebugger -ErrorAction SilentlyContinue
    if($werfaultReflectDebugger)
    {
      Write-Verbose -Message '[!] Found a ReflectDebugger property under the WerFault Hangs key which deserve investigation!'
      $werfaultReflectDebugger | Select-Object -Property ReflectDebugger, PS*
      foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $werfaultReflectDebugger))
      {
        if($psProperties.Contains($prop.Name)) 
        {
          continue
        } # skip the property if it's powershell built-in property
        $propPath = Convert-Path -Path $werfaultReflectDebugger.PSPath
        $propPath += '\' + $prop.Name
        $PersistenceObject = New-PersistenceObject -Technique 'Windows Error Reporting ReflectDebugger' -Classification 'Hexacorn Technique N.85' -Path $propPath -Value $werfaultReflectDebugger.($prop.Name) -AccessGained 'System' -Note 'The executable in the ReflectDebugger property of HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs is spawned by WerFault.exe when called with the -pr argument.' -Reference 'https://www.hexacorn.com/blog/2018/08/31/beyond-good-ol-run-key-part-85/'
        $null = $persistenceObjectArray.Add($PersistenceObject)
        $PersistenceObject
      }
    }
    Write-Verbose -Message ''
  }

  function Get-UsersCmdAutoRun
  {
    Write-Verbose -Message "Getting users' cmd.exe's AutoRun property..."
    $hkeyUsers = Get-ChildItem -Path Registry::HKEY_USERS
    foreach($sidHive in $hkeyUsers)
    {
      $currentUser = "Registry::$sidHive"
      $autorun = Get-ItemProperty -Path "$currentUser\Software\Microsoft\Command Processor" -Name AutoRun -ErrorAction SilentlyContinue
      if($autorun)
      {
        Write-Verbose -Message "[!] $sidHive user's cmd.exe's AutoRun property is set and deserves investigation!"
        foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $autorun))
        {
          if($psProperties.Contains($prop.Name)) 
          {
            continue
          } # skip the property if it's powershell built-in property
          $propPath = Convert-Path -Path $autorun.PSPath
          $propPath += '\' + $prop.Name
          $PersistenceObject = New-PersistenceObject -Technique "Users' cmd.exe AutoRun key" -Classification 'Uncatalogued Technique N.1' -Path $propPath -Value $autorun.($prop.Name) -AccessGained 'User' -Note 'The executable in the AutoRun property of HKEY_USERS\<User_SID>\Software\Microsoft\Command Processor\AutoRun is run when cmd.exe is spawned without the /D argument.' -Reference 'https://persistence-info.github.io/Data/cmdautorun.html'
          $null = $persistenceObjectArray.Add($PersistenceObject)
          $PersistenceObject
        }
      }
    }
    Write-Verbose -Message ''   
  }
  
  function Get-SystemCmdAutoRun
  {
    Write-Verbose -Message "Getting system's cmd.exe's AutoRun property..."
    $autorun = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Command Processor' -Name AutoRun -ErrorAction SilentlyContinue
    if($autorun)
    {
      Write-Verbose -Message "[!] System's cmd.exe's AutoRun property is set and deserves investigation!"
      foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $autorun))
      {
        if($psProperties.Contains($prop.Name)) 
        {
          continue
        } # skip the property if it's powershell built-in property
        $propPath = Convert-Path -Path $autorun.PSPath
        $propPath += '\' + $prop.Name
        $PersistenceObject = New-PersistenceObject -Technique "System's cmd.exe AutoRun key" -Classification 'Uncatalogued Technique N.1' -Path $propPath -Value $autorun.($prop.Name) -AccessGained 'User' -Note 'The executable in the AutoRun property of HKEY_LOCAL_MACHINE\Software\Microsoft\Command Processor\AutoRun is run when cmd.exe is spawned without the /D argument.' -Reference 'https://persistence-info.github.io/Data/cmdautorun.html'
        $null = $persistenceObjectArray.Add($PersistenceObject)
        $PersistenceObject
      }
    }
    
    Write-Verbose -Message ''
  }
  
  function Get-ExplorerLoad
  {
    Write-Verbose -Message "Getting current user's Explorer's Load property..."
    $loadKey = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows' -Name Load -ErrorAction SilentlyContinue
    if($loadKey)
    {
      Write-Verbose -Message "[!] Current user's Load property is set and deserves investigation!"
      foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $loadKey))
      {
        if($psProperties.Contains($prop.Name)) 
        {
          continue
        } # skip the property if it's powershell built-in property
        $propPath = Convert-Path -Path $loadKey.PSPath
        $propPath += '\' + $prop.Name
        $PersistenceObject = New-PersistenceObject -Technique 'Explorer Load Property' -Classification 'Uncatalogued Technique N.2' -Path $propPath -Value $loadKey.($prop.Name) -AccessGained 'User' -Note 'The executable in the Load property of HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows is run by explorer.exe at login time.' -Reference 'https://persistence-info.github.io/Data/windowsload.html'
        $null = $persistenceObjectArray.Add($PersistenceObject)
        $PersistenceObject
      }
    }
    Write-Verbose -Message ''
  }
  
  function Get-SystemWinlogonUserinit
  {
    Write-Verbose -Message "Getting system's Winlogon's Userinit property..."
    $userinit = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Userinit -ErrorAction SilentlyContinue
    if($userinit)
    {
      if($userinit.Userinit -ne 'C:\Windows\system32\userinit.exe,')
      {
        Write-Verbose -Message "[!] Winlogon's Userinit property is set to a non-standard value and deserves investigation!"
        foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $userinit))
        {
          if($psProperties.Contains($prop.Name)) 
          {
            continue
          } # skip the property if it's powershell built-in property
          $propPath = Convert-Path -Path $userinit.PSPath
          $propPath += '\' + $prop.Name
          $PersistenceObject = New-PersistenceObject -Technique 'Winlogon Userinit Property' -Classification 'MITRE ATT&CK T1547.004' -Path $propPath -Value $userinit.($prop.Name) -AccessGained 'User' -Note "The executables in the Userinit property of HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon are run at login time by any user. Normally this property should be set to 'C:\Windows\system32\userinit.exe,' without any further executables appended." -Reference 'https://attack.mitre.org/techniques/T1547/004/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
          $PersistenceObject
        }
      }
    }
    Write-Verbose -Message ''
  }
  
  function Get-SystemWinlogonShell
  {
    Write-Verbose -Message "Getting Winlogon's Shell property..."
    $shell = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Shell -ErrorAction SilentlyContinue
    if(!$shell)
    {
      Write-Verbose -Message '[!] No Shell property found, it may be an error...'
    }
    else 
    {
      if($shell.Shell -ne 'explorer.exe')
      {
        Write-Verbose -Message "[!] Winlogon's Shell property is set to a non-standard value and deserves investigation!"
        foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $shell))
        {
          if($psProperties.Contains($prop.Name)) 
          {
            continue
          } # skip the property if it's a powershell built-in property
          $propPath = Convert-Path -Path $shell.PSPath
          $propPath += '\' + $prop.Name
          $PersistenceObject = New-PersistenceObject -Technique 'Winlogon Shell Property' -Classification 'MITRE ATT&CK T1547.004' -Path $propPath -Value $shell.($prop.Name) -AccessGained 'User' -Note "The executables in the Shell property of HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon are run as the default shells for any users. Normally this property should be set to 'explorer.exe' without any further executables appended." -Reference 'https://attack.mitre.org/techniques/T1547/004/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
          $PersistenceObject
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
      $terminalDirectories = Get-ChildItem -Path "$($directory.FullName)\Appdata\Local\Packages\Microsoft.WindowsTerminal_*" -ErrorAction SilentlyContinue
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
              
              $PersistenceObject = New-PersistenceObject -Technique 'Windows Terminal startOnUserLogin' -Classification 'Uncatalogued Technique N.3' -Path "$($terminalDirectory.FullName)\LocalState\settings.json" -Value "$executable" -AccessGained 'User' -Note "The executable specified as value of the key `"commandline`" of a profile which has the `"startOnUserLogin`" key set to `"true`" in the Windows Terminal's settings.json of a user is run every time that user logs in." -Reference 'https://twitter.com/nas_bench/status/1550836225652686848'
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
    $appCertDllsProps = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' -ErrorAction SilentlyContinue
    if($appCertDllsProps)
    {
      Write-Verbose -Message "[!] Found properties under system's AppCertDlls key which deserve investigation!"
      foreach ($prop in (Get-Member -MemberType NoteProperty -InputObject $appCertDllsProps))
      {
        if($psProperties.Contains($prop.Name)) 
        {
          continue
        } # skip the property if it's powershell built-in property
        $propPath = Convert-Path -Path $appCertDllsProps.PSPath
        $propPath += '\' + $prop.Name
        $PersistenceObject = New-PersistenceObject -Technique 'AppCertDlls' -Classification 'MITRE ATT&CK T1546.009' -Path $propPath -Value $appCertDllsProps.($prop.Name) -AccessGained 'System' -Note 'DLLs in properties of the key HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls are loaded by every process that loads the Win32 API at process creation.' -Reference 'https://attack.mitre.org/techniques/T1546/009/'
        $null = $persistenceObjectArray.Add($PersistenceObject)
        $PersistenceObject
      }
    }
    Write-Verbose -Message ''
  }
  
  function Get-AppPaths
  {
    Write-Verbose -Message 'Getting App Paths inside the registry...'
    $appPathsKeys = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths' -ErrorAction SilentlyContinue
    foreach($key in $appPathsKeys)
    {
      $appPath = Get-ItemProperty -Path Registry::$key -Name '(Default)' -ErrorAction SilentlyContinue
      if($appPath) 
      { 
        Write-Verbose -Message '[!] Found subkeys under the App Paths key which deserve investigation!'
        $propPath = Convert-Path -Path $key.PSPath
        $propPath += '\' + $appPath.Name
        $PersistenceObject = New-PersistenceObject -Technique 'App Paths' -Classification 'Hexacorn Technique N.3' -Path "$propPath(Default)" -Value $appPath.'(Default)' -AccessGained 'System/User' -Note 'Executables in the (Default) property of a subkey of HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\ are run instead of the program corresponding to the subkey. Gained access depends on whose context the process runs in. Be aware this might be a false positive.' -Reference 'https://www.hexacorn.com/blog/2013/01/19/beyond-good-ol-run-key-part-3/'
        $null = $persistenceObjectArray.Add($PersistenceObject)
        $PersistenceObject
      } 
    }
    Write-Verbose -Message ''
  }  
  
  function Get-ServiceDlls
  {
    Write-Verbose -Message 'Getting Service DLLs inside the registry...'
    $keys = Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\'

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
            if ((Get-AuthenticodeSignature -FilePath $ServiceDll -ErrorAction SilentlyContinue).IsOSBinary) 
            {
              continue
            }
            else
            {
              Write-Verbose -Message '[!] Found subkeys under the Services key which deserve investigation!'
              $propPath = (Convert-Path -Path "$($key.pspath)") + '\Parameters\ServiceDll'
              $PersistenceObject = New-PersistenceObject -Technique 'ServiceDll Hijacking' -Classification 'Hexacorn Technique N.4' -Path $propPath -Value "$ServiceDll" -AccessGained 'System' -Note "DLLs in the ServiceDll property of HKLM:\SYSTEM\CurrentControlSet\Services\<SERVICE_NAME>\Parameters are loaded by the corresponding service's svchost.exe. If an attacker modifies said entry, the malicious DLL will be loaded in place of the legitimate one." -Reference 'https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/'
              $null = $persistenceObjectArray.Add($PersistenceObject)
              $PersistenceObject
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
    $keys = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions'

    foreach ($key in $keys)
    {
      $DllName = (Get-ItemProperty -Path ($key.pspath)).DllName
      if ($null -ne $DllName)
      {
        if((Test-Path -Path $DllName -PathType leaf) -eq $false)
        {
          $DllName = "C:\Windows\System32\$DllName"
        }
        if ((Get-AuthenticodeSignature -FilePath $DllName -ErrorAction SilentlyContinue).IsOSBinary) 
        {
          continue
        }
        else
        {
          Write-Verbose -Message '[!] Found DllName property under a subkey of the GPExtensions key which deserve investigation!'
          $propPath = (Convert-Path -Path "$($key.pspath)") + '\DllName'
          $PersistenceObject = New-PersistenceObject -Technique 'Group Policy Extension DLL' -Classification 'Uncatalogued Technique N.4' -Path $propPath -Value "$DllName" -AccessGained 'System' -Note 'DLLs in the DllName property of HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\<GUID>\ are loaded by the gpsvc process. If an attacker modifies said entry, the malicious DLL will be loaded in place of the legitimate one.' -Reference 'https://persistence-info.github.io/Data/gpoextension.html'
          $null = $persistenceObjectArray.Add($PersistenceObject)
          $PersistenceObject
        }
      }
    }  
    Write-Verbose -Message ''
  }
  
  function Get-WinlogonMPNotify
  {
    Write-Verbose -Message 'Getting Winlogon MPNotify property...'
    $mpnotify = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name mpnotify -ErrorAction SilentlyContinue
    if($mpnotify)
    {
      Write-Verbose -Message "[!] Found MPnotify property under system's Winlogon key!"
      $propPath = (Convert-Path -Path $mpnotify.PSPath) + '\mpnotify'
      $PersistenceObject = New-PersistenceObject -Technique 'Winlogon MPNotify Executable' -Classification 'Uncatalogued Technique N.5' -Path $propPath -Value $mpnotify.mpnotify -AccessGained 'System' -Note 'The executable specified in the "mpnotify" property of the HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon key is run by Winlogon when a user logs on. After the timeout (30s) the process and its child processes are terminated.' -Reference 'https://persistence-info.github.io/Data/mpnotify.html'
      $null = $persistenceObjectArray.Add($PersistenceObject)
      $PersistenceObject
    }
    Write-Verbose -Message ''
  }
  
  Write-Verbose -Message 'Starting execution...'

  Get-UsersRunAndRunOnce
  Get-SystemRunAndRunOnce
  Get-ImageFileExecutionOptions
  Get-NLDPDllOverridePath
  Get-AeDebug
  Get-WerFaultHangs
  Get-UsersCmdAutoRun
  Get-SystemCmdAutoRun
  Get-ExplorerLoad
  Get-SystemWinlogonUserinit
  Get-SystemWinlogonShell
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

function Get-ServiceDllsFalsePositive
{
  Write-Verbose -Message "Outputting current Services' ServiceDll configuration to use as false positives..."
  $serviceDllsTable = @{}
  $services = Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\'
  foreach($service in $services)
  {
    $serviceKey = Get-Item -Path Registry::$service\Parameters -ErrorAction SilentlyContinue
    if($serviceKey)
    {
      $serviceDll = $serviceKey.GetValue('ServiceDll', $null, 'DoNotExpandEnvironmentNames') # .NET wizardry to prevent Powershell from expanding REG_EXPAND_SZ properties
    }
    else
    {
      $serviceDll = $null
    }   
    $serviceDllsTable.Add($service, $serviceDll)
  }
  $serviceDllsTable.GetEnumerator()
}

# SIG # Begin signature block
  # MIID7QYJKoZIhvcNAQcCoIID3jCCA9oCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
  # gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
  # AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUBgMqUaYoQ8et64iH+l4WvNpT
  # 7nugggIHMIICAzCCAWygAwIBAgIQF+BNQBpcW6RBBEo1bSFRGzANBgkqhkiG9w0B
  # AQUFADAcMRowGAYDVQQDDBFGZWRlcmljbyBMYWdyYXN0YTAeFw0yMjA3MTkxNDEz
  # MDJaFw0yNjA3MTkwMDAwMDBaMBwxGjAYBgNVBAMMEUZlZGVyaWNvIExhZ3Jhc3Rh
  # MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDjMbaODrvLdzZbpl4zEtqUXMXl
  # taFuA8vnquV5373I4Tc8Obx7U18WvEfknFLQoGGzKV8M9d9kDX9NfTRydJmEksLB
  # eFuMasI+U1N71Tn4dpN0LW6PKbE35XVZtZ10LggrozqSbk9giv1bJwTTz4ZeNpJ/
  # ytHlV6zIwcmap1Dt4QIDAQABo0YwRDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNV
  # HQ4EFgQUEvzrfw+6jTXcizBEwSWbnNZCGu4wDgYDVR0PAQH/BAQDAgeAMA0GCSqG
  # SIb3DQEBBQUAA4GBAJNKf/cEn54Sh9H3iAy0+X3hlfLtRu0UamTNtgmi1Ul7qEth
  # EfOGjDtjdYj8GD97blI3z3aGWeLQkoGzELJPG2gTfsORgIN4382YwzM7AhgN++Uv
  # 2Bmwqlzi4CtqAIg+Owi15RlOVnNSj0hw9KqEVxw4M2D9sTiKpfYCIrhhPQ8cMYIB
  # UDCCAUwCAQEwMDAcMRowGAYDVQQDDBFGZWRlcmljbyBMYWdyYXN0YQIQF+BNQBpc
  # W6RBBEo1bSFRGzAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKA
  # ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYK
  # KwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUxWu9438wV4RNpC4M/S4clEMwyfkw
  # DQYJKoZIhvcNAQEBBQAEgYBl0UMI4TF6i4BKvRYXjV1+7sKBsS4K8Wg9N27wnK92
  # S5x3jM2xxAl/PI3Stdw+hEKFIqP7KgKHYTidC9EuU9RUI38rxSjkJd6hPWwZB+dm
  # yNfLzxgGdg03dnpwcFDTdLPoNNIRbRI7zreeEdhmYZ2m3ro2MXDENqVgz24MdfR9
  # ww==
# SIG # End signature block
