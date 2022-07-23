#Requires -RunAsAdministrator
function Find-AllPersistence
{ 
  <#
      .SYNOPSIS

      This script tries to enumerate all the persistence methods implanted on a compromised machine.

      Function: Find-AllPersistence
      Authors: Federico `last` Lagrasta, Twitter: @last0x00; Riccardo Ancarani, Twitter: @dottor_morte
      License: https://creativecommons.org/licenses/by/3.0/deed.en
      Required Dependencies: None
      Optional Dependencies: None

      .DESCRIPTION

      Enumerate all the persistence methods found on a machine and print them for the user to see.

      .PARAMETER OutputCSV

      String: Output to a CSV file for later consumption.

      .PARAMETER DiffCSV

      String: Take a CSV as input and exclude from the output all the local persistences which match the ones in the input CSV. 
	    
      .EXAMPLE

      Enumerate all persistence techniques implanted on the local machine.
      Find-AllPersistence

      .EXAMPLE

      Enumerate all persistence techniques implanted on the local machine and output to a CSV.
      Find-AllPersistence -OutputCSV .\persistences.csv

      .EXAMPLE

      Enumerate all persistence techniques implanted on the local machine but show us only the persistences which are not in an input CSV.
      Find-AllPersistence -DiffCSV .\persistences.csv

      .NOTES

      This script tries to enumerate all persistence techniques that may have been deployed on a compromised machine. New techniques may take some time before they are implemented in this script, so don't assume that because the script didn't find anything the machine is clean.
     
      .LINK

      https://github.com/last-byte/PersistenceSniper
  #>
  
  
  Param(
    [Parameter(Mandatory = $false, Position = 0)]
    [System.String]
    $OutputCSV = $null,
    
    [Parameter(Mandatory = $false, Position = 0)]
    [System.String]
    $DiffCSV = $null 
  )  
  function New-PersistenceObject
  {
    param(
      $Technique, 
      $Classification, 
      $Path, 
      $Value, 
      $AccessGained,
      $Note,
      $Reference
    )
    $PersistenceObject = [PSCustomObject]@{
      "Technique" = $Technique
      "Classification" = $Classification
      "Path" = $Path
      "Value" = $Value
      "Access Gained" = $AccessGained
      "Note" = $Note
      "Reference" = $Reference
    } 
    return $PersistenceObject
  }
  
  $persistenceObjectArray = New-Object -TypeName System.Collections.ArrayList
  $psProperties = @("PSChildName","PSDrive","PSParentPath","PSPath","PSProvider")
  
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
        Write-Verbose "[!] Found properties under $sidHive user's Run key which deserve investigation!"
        foreach ($prop in (Get-Member -Type NoteProperty -InputObject $runProps))
        {
          if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
          $propPath = Convert-Path $runProps.PSPath
          $propPath += '\' + $prop.Name
          $persistenceObject = New-PersistenceObject "Registry Run Key" "MITRE ATT&CK T1547.001" $propPath $runProps.($prop.Name) "User" "Executables in properties of the key HKEY_USERS\<User_SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Run are run when the user logs in." "https://attack.mitre.org/techniques/T1547/001/"
          $null = $persistenceObjectArray.Add($persistenceObject)
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
        Write-Verbose "[!] Found properties under $sidHive user's RunOnce key which deserve investigation!"
        foreach ($prop in (Get-Member -Type NoteProperty -InputObject $runOnceProps))
        {
          if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
          $propPath = Convert-Path $runOnceProps.PSPath
          $propPath += '\' + $prop.Name
          $persistenceObject = New-PersistenceObject "Registry RunOnce Key" "MITRE ATT&CK T1547.001" $propPath $runOnceProps.($prop.Name) "User" "Executables in properties of the key HKEY_USERS\<User_SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce are run once when the user logs in and then deleted." "https://attack.mitre.org/techniques/T1547/001/"
          $null = $persistenceObjectArray.Add($persistenceObject)
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
      Write-Verbose "[!] Found properties under system's Run key which deserve investigation!"
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $runProps))
      {
        if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
        $propPath = Convert-Path $runProps.PSPath
        $propPath += '\' + $prop.Name
        $persistenceObject = New-PersistenceObject "Registry Run Key" "MITRE ATT&CK T1547.001" $propPath $runProps.($prop.Name) "System" "Executables in properties of the key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run are run when the system boots." "https://attack.mitre.org/techniques/T1547/001/"
        $null = $persistenceObjectArray.Add($persistenceObject)
      }
    }
    
    Write-Verbose -Message ''
    Write-Verbose -Message "Getting system's RunOnce properties..."
    $runOnceProps = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue
    if($runOnceProps)
    {
      Write-Verbose "[!] Found properties under system's RunOnce key which deserve investigation!"
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $runOnceProps))
      {
        if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
        $propPath = Convert-Path $runOnceProps.PSPath
        $propPath += '\' + $prop.Name
        $persistenceObject = New-PersistenceObject "Registry RunOnce Key" "MITRE ATT&CK T1547.001" $propPath $runOnceProps.($prop.Name) "System" "Executables in properties of the key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce are run once when the system boots and then deleted." "https://attack.mitre.org/techniques/T1547/001/"
        $null = $persistenceObjectArray.Add($persistenceObject)
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
        Write-Verbose '[!] Found subkeys under the Image File Execution Options key which deserve investigation!'
        foreach($key in $IFEOptsDebuggers)
        {
          $ifeProps =  Get-ItemProperty -Path Registry::$key -Name Debugger
          foreach ($prop in (Get-Member -Type NoteProperty -InputObject $ifeProps))
          {
            if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
            $propPath = Convert-Path $ifeProps.PSPath
            $propPath += '\' + $prop.Name
            $persistenceObject = New-PersistenceObject "Image File Execution Options" "MITRE ATT&CK T1546.012" $propPath $ifeProps.($prop.Name) "System/User" "Executables in the Debugger property of a subkey of HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options are run instead of the process corresponding to the subkey. Gained access depends on whose context the debugged process runs in." "https://attack.mitre.org/techniques/T1546/012/"
            $null = $persistenceObjectArray.Add($persistenceObject)
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
          $properties = Get-ItemProperty -Path Registry::$key | Select-Object *DLLPathOverride,PS*
          foreach ($prop in (Get-Member -Type NoteProperty -InputObject $properties))
          {
            if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
            $propPath = Convert-Path $properties.PSPath
            $propPath += '\' + $prop.Name
            $persistenceObject = New-PersistenceObject "Natural Language Development Platform 6 DLL Override Path" "Hexacorn Technique N.98" $propPath $properties.($prop.Name) "System" "DLLs listed in properties of subkeys of HKLM:\SYSTEM\CurrentControlSet\Control\ContentIndex\Language are loaded via LoadLibrary executed by SearchIndexer.exe" "https://www.hexacorn.com/blog/2018/12/30/beyond-good-ol-run-key-part-98/"
            Write-Verbose $persistenceObject
            $null = $persistenceObjectArray.Add($persistenceObject)
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
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $aeDebugger))
      {
        if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
        $propPath = Convert-Path $aeDebugger.PSPath
        $propPath += '\' + $prop.Name
        $persistenceObject = New-PersistenceObject "AEDebug Custom Debugger" "Hexacorn Technique N.4" $propPath $aeDebugger.($prop.Name) "System/User" "The executable in the Debugger property of HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug is run when a process crashes. Gained access depends on whose context the debugged process runs in; if the Auto property of the same registry key is set to 1, the debugger starts without user interaction." "https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/"
        $null = $persistenceObjectArray.Add($persistenceObject)
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
      Write-Verbose -Message "[!] Found a Debugger property under the WerFault Hangs key which deserve investigation!"
      $werfaultDebugger | Select-Object -Property Debugger,PS*
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $werfaultDebugger))
      {
        if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
        $propPath = Convert-Path $werfaultDebugger.PSPath
        $propPath += '\' + $prop.Name
        $persistenceObject = New-PersistenceObject "Windows Error Reporting Debugger" "Hexacorn Technique N.116" $propPath $werfaultDebugger.($prop.Name) "System" "The executable in the Debugger property of HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs is spawned by WerFault.exe when a process crashes." "https://www.hexacorn.com/blog/2019/09/20/beyond-good-ol-run-key-part-116/"
        $null = $persistenceObjectArray.Add($persistenceObject)
      }
    }
    
    Write-Verbose -Message ''
    Write-Verbose -Message 'Getting WerFault Hangs registry key ReflectDebug property...'
    $werfaultReflectDebugger = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs' -Name ReflectDebugger -ErrorAction SilentlyContinue
    if($werfaultReflectDebugger)
    {
      Write-Verbose -Message "[!] Found a ReflectDebugger property under the WerFault Hangs key which deserve investigation!"
      $werfaultReflectDebugger | Select-Object -Property ReflectDebugger,PS*
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $werfaultReflectDebugger))
      {
        if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
        $propPath = Convert-Path $werfaultReflectDebugger.PSPath
        $propPath += '\' + $prop.Name
        $persistenceObject = New-PersistenceObject "Windows Error Reporting ReflectDebugger" "Hexacorn Technique N.85" $propPath $werfaultReflectDebugger.($prop.Name) "System" "The executable in the ReflectDebugger property of HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs is spawned by WerFault.exe when called with the -pr argument." "https://www.hexacorn.com/blog/2018/08/31/beyond-good-ol-run-key-part-85/"
        $null = $persistenceObjectArray.Add($persistenceObject)
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
        foreach ($prop in (Get-Member -Type NoteProperty -InputObject $autorun))
        {
          if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
          $propPath = Convert-Path $autorun.PSPath
          $propPath += '\' + $prop.Name
          $persistenceObject = New-PersistenceObject "Users' cmd.exe AutoRun key" "Uncatalogued Technique N.1" $propPath $autorun.($prop.Name) "User" "The executable in the AutoRun property of HKEY_USERS\<User_SID>\Software\Microsoft\Command Processor\AutoRun is run when cmd.exe is spawned without the /D argument." "https://persistence-info.github.io/Data/cmdautorun.html"
          $null = $persistenceObjectArray.Add($persistenceObject)
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
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $autorun))
      {
        if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
        $propPath = Convert-Path $autorun.PSPath
        $propPath += '\' + $prop.Name
        $persistenceObject = New-PersistenceObject "System's cmd.exe AutoRun key" "Uncatalogued Technique N.1" $propPath $autorun.($prop.Name) "User" "The executable in the AutoRun property of HKEY_LOCAL_MACHINE\Software\Microsoft\Command Processor\AutoRun is run when cmd.exe is spawned without the /D argument." "https://persistence-info.github.io/Data/cmdautorun.html"
        $null = $persistenceObjectArray.Add($persistenceObject)
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
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $loadKey))
      {
        if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
        $propPath = Convert-Path $loadKey.PSPath
        $propPath += '\' + $prop.Name
        $persistenceObject = New-PersistenceObject "Explorer Load Property" "Uncatalogued Technique N.2" $propPath $loadKey.($prop.Name) "User" "The executable in the Load property of HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows is run by explorer.exe at login time." "https://persistence-info.github.io/Data/windowsload.html"
        $null = $persistenceObjectArray.Add($persistenceObject)
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
        foreach ($prop in (Get-Member -Type NoteProperty -InputObject $userinit))
        {
          if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
          $propPath = Convert-Path $userinit.PSPath
          $propPath += '\' + $prop.Name
          $persistenceObject = New-PersistenceObject "Winlogon Userinit Property" "MITRE ATT&CK T1547.004" $propPath $userinit.($prop.Name) "User" "The executables in the Userinit property of HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon are run at login time by any user. Normally this property should be set to 'C:\Windows\system32\userinit.exe,' without any further executables appended." "https://attack.mitre.org/techniques/T1547/004/"
          $null = $persistenceObjectArray.Add($persistenceObject)
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
      Write-Verbose -Message '[!] No Userinit property found, it may be an error...'
    }
    else 
    {
      if($shell.Shell -ne 'explorer.exe')
      {
        Write-Verbose -Message "[!] Winlogon's Shell property is set to a non-standard value and deserves investigation!"
        foreach ($prop in (Get-Member -Type NoteProperty -InputObject $shell))
        {
          if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
          $propPath = Convert-Path $shell.PSPath
          $propPath += '\' + $prop.Name
          $persistenceObject = New-PersistenceObject "Winlogon Shell Property" "MITRE ATT&CK T1547.004" $propPath $shell.($prop.Name) "User" "The executables in the Shell property of HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon are run as the default shells for any users. Normally this property should be set to 'explorer.exe' without any further executables appended." "https://attack.mitre.org/techniques/T1547/004/"
          $null = $persistenceObjectArray.Add($persistenceObject)
        }
        
      }
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
    
  # Use Input CSV to make a diff of the results and only show us the persistences implanted on the local machine which are not in the CSV
  if($DiffCSV)
  {
    Write-Verbose "Diffing found persistences with the ones in the input CSV..."
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
    $persistenceObjectArray | ConvertTo-Csv | Out-File -FilePath $OutputCSV -ErrorAction Stop
  }
  
  Write-Verbose -Message 'Execution finished, outputting results...'  
  return $persistenceObjectArray
}